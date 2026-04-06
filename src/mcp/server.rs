use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Instant;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{RwLock, Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::{Config, ConfigWatcher};
use crate::domain::{ExecuteCommandUseCase, OutputCache, TaskStore, TunnelManager};
use crate::error::Result;
use crate::mcp::instructions;
use crate::ports::ExecutorRouter;
use crate::ports::ToolContext;
use crate::security::{AuditLogger, AuditWriterTask, CommandValidator, RateLimiter, Sanitizer};
use crate::ssh::SessionManager;

use super::completion_provider::DefaultCompletionProvider;
use super::logger::McpLogger;
use super::pending_requests::{ClientResponse, PendingRequests};
use super::progress::ProgressReporter;
use super::protocol::{IncomingMessage, JsonRpcMessage, RootEntry, RootsListResult};

use super::history::CommandHistory;
use super::prompt_registry::{PromptRegistry, create_default_prompt_registry};
use super::protocol::{
    ClientInfo, CompletionRef, CompletionResult, CompletionsCapability, CompletionsCompleteParams,
    CompletionsCompleteResult, CreateTaskResult, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, LogLevel, LoggingCapability,
    LoggingSetLevelParams, PROTOCOL_VERSION, PromptsCapability, PromptsGetParams, PromptsGetResult,
    PromptsListResult, ResourcesCapability, ResourcesListResult, ResourcesReadParams,
    ResourcesReadResult, SERVER_NAME, SERVER_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    ServerCapabilities, ServerInfo, TaskCancelParams, TaskGetParams, TaskListParams,
    TaskListResult, TaskRequestsCapability, TaskResultParams, TaskToolsCapability, TasksCapability,
    ToolCallParams, ToolCallResult, ToolContent, ToolsCapability, ToolsListResult, WriterMessage,
};
use super::registry::{ToolRegistry, create_filtered_registry};
use super::resource_registry::{ResourceRegistry, create_default_resource_registry};

/// MCP Server that communicates over stdio
pub struct McpServer {
    config: Arc<RwLock<Config>>,
    validator: Arc<CommandValidator>,
    sanitizer: Arc<Sanitizer>,
    audit_logger: Arc<AuditLogger>,
    history: Arc<CommandHistory>,
    connection_pool: Arc<ExecutorRouter>,
    execute_use_case: Arc<ExecuteCommandUseCase>,
    rate_limiter: Arc<RateLimiter>,
    registry: ToolRegistry,
    prompt_registry: PromptRegistry,
    resource_registry: ResourceRegistry,
    session_manager: Arc<SessionManager>,
    tunnel_manager: Arc<TunnelManager>,
    output_cache: Arc<OutputCache>,
    task_store: Arc<TaskStore>,
    initialized: AtomicBool,
    concurrent_limit: Arc<Semaphore>,
    client_info: RwLock<Option<ClientInfo>>,
    runtime_max_output_chars: Arc<RwLock<Option<usize>>>,
    /// Writer channel for sending task status notifications from background workers.
    /// Initialized in `run()` before the main loop starts.
    notification_tx: Arc<RwLock<Option<mpsc::Sender<WriterMessage>>>>,
    /// Current minimum log level for MCP logging notifications.
    log_level: Arc<AtomicU8>,
    /// MCP logger for sending `notifications/message` to the client.
    /// Initialized in `run()` once the writer channel is ready.
    mcp_logger: Arc<RwLock<Option<Arc<McpLogger>>>>,
    /// Completion provider for argument auto-completion.
    completion_provider: DefaultCompletionProvider,
    /// Pending server-to-client requests (elicitation, sampling).
    pending_requests: Arc<PendingRequests>,
    /// Active resource subscriptions (uri -> list of subscription IDs).
    resource_subscriptions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Client-declared roots (MCP Roots capability).
    roots: Arc<RwLock<Vec<RootEntry>>>,
    /// Whether the client supports `roots/list`.
    client_supports_roots: AtomicBool,
    /// Application metrics for token consumption analytics.
    metrics: Arc<crate::metrics::Metrics>,
}

impl McpServer {
    /// Create a new MCP server with the given configuration
    ///
    /// Returns the server and an optional audit writer task that must be spawned.
    pub fn new(config: Config) -> (Self, Option<AuditWriterTask>) {
        // Create command validator with pre-compiled regex patterns
        let validator = Arc::new(CommandValidator::new(&config.security));

        // Create sanitizer with advanced config (supports categories and custom replacements)
        // Also includes legacy sanitize_patterns for backward compatibility
        let sanitizer = Arc::new(Sanitizer::from_config_with_legacy(
            &config.security.sanitize,
            &config.security.sanitize_patterns,
        ));

        // Create audit logger (async with background writer task)
        let (audit_logger, audit_task) = match AuditLogger::new(&config.audit) {
            Ok((logger, task)) => (logger, task),
            Err(e) => {
                warn!(error = %e, "Failed to create audit logger, using disabled logger");
                (AuditLogger::disabled(), None)
            }
        };
        let audit_logger = Arc::new(audit_logger);

        // Create command history
        let history = Arc::new(CommandHistory::with_defaults());

        // Create executor router (protocol-aware connection dispatcher)
        let connection_pool = Arc::new(ExecutorRouter::with_defaults());

        // Create execute command use case
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        // Create tool registry filtered by tool group configuration
        let registry = create_filtered_registry(&config.tool_groups);

        // Create prompt registry with default prompts
        let prompt_registry = create_default_prompt_registry();

        // Create resource registry with default handlers
        let resource_registry = create_default_resource_registry();

        // Create concurrency limiter using config value
        let max_concurrent = config.limits.max_concurrent_commands;
        let concurrent_limit = Arc::new(Semaphore::new(max_concurrent));

        // Create rate limiter (0 = disabled by default)
        let rate_limiter = Arc::new(RateLimiter::new(config.limits.rate_limit_per_second));

        // Create session manager for persistent shells
        let session_manager = Arc::new(SessionManager::new(config.sessions.clone()));

        // Create tunnel manager
        let tunnel_manager = Arc::new(TunnelManager::new(20));

        // Create output cache for paginated retrieval of truncated outputs
        let output_cache = Arc::new(OutputCache::new(
            config.limits.output_cache_ttl_seconds,
            config.limits.output_cache_max_entries,
        ));

        // Create task store for async task management (MCP 2025-11-25+)
        let task_store = Arc::new(TaskStore::new(
            config.limits.max_tasks,
            config.limits.max_task_ttl_ms,
            config.limits.task_poll_interval_ms,
        ));

        let server = Self {
            config: Arc::new(RwLock::new(config)),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool,
            execute_use_case,
            rate_limiter,
            registry,
            prompt_registry,
            resource_registry,
            session_manager,
            tunnel_manager,
            output_cache,
            task_store,
            initialized: AtomicBool::new(false),
            concurrent_limit,
            client_info: RwLock::new(None),
            runtime_max_output_chars: Arc::new(RwLock::new(None)),
            notification_tx: Arc::new(RwLock::new(None)),
            log_level: Arc::new(AtomicU8::new(LogLevel::Warning.severity())),
            mcp_logger: Arc::new(RwLock::new(None)),
            completion_provider: DefaultCompletionProvider,
            pending_requests: Arc::new(PendingRequests::new()),
            resource_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            roots: Arc::new(RwLock::new(Vec::new())),
            client_supports_roots: AtomicBool::new(false),
            metrics: Arc::new(crate::metrics::Metrics::new()),
        };

        (server, audit_task)
    }

    /// Create a `ToolContext` for tool execution
    ///
    /// This reads a snapshot of the current configuration, ensuring
    /// consistent config values during a single tool execution.
    async fn create_tool_context(&self) -> ToolContext {
        // Read config snapshot
        let mut config_snapshot = {
            let guard = self.config.read().await;
            guard.clone()
        };

        // Apply runtime override to the snapshot so handlers see the effective value
        if let Some(runtime_val) = *self.runtime_max_output_chars.read().await {
            config_snapshot.limits.max_output_chars = runtime_val;
        }

        let mut ctx = ToolContext::new(
            Arc::new(config_snapshot),
            Arc::clone(&self.validator),
            Arc::clone(&self.sanitizer),
            Arc::clone(&self.audit_logger),
            Arc::clone(&self.history),
            Arc::clone(&self.connection_pool),
            Arc::clone(&self.execute_use_case),
            Arc::clone(&self.rate_limiter),
            Arc::clone(&self.session_manager),
        );
        ctx.tunnel_manager = Arc::clone(&self.tunnel_manager);
        ctx.output_cache = Some(Arc::clone(&self.output_cache));
        ctx.runtime_max_output_chars = Some(Arc::clone(&self.runtime_max_output_chars));
        ctx.roots = self.roots.read().await.to_vec();
        ctx.metrics = Some(Arc::clone(&self.metrics));
        ctx
    }

    /// Run the server, reading from stdin and writing to stdout
    ///
    /// This method processes requests concurrently using a worker pool limited
    /// by `max_concurrent_commands` from the configuration.
    ///
    /// # Arguments
    ///
    /// * `audit_task` - Optional background task for async audit logging
    /// * `config_path` - Optional path to config file for hot-reload support
    ///
    /// # Errors
    ///
    /// Returns an error if reading from stdin or writing to stdout fails.
    #[allow(clippy::too_many_lines)]
    pub async fn run(
        self: Arc<Self>,
        audit_task: Option<AuditWriterTask>,
        config_path: Option<&Path>,
    ) -> Result<()> {
        // Spawn audit writer task if enabled
        if let Some(task) = audit_task {
            tokio::spawn(task.run());
        }

        let (tx, mut rx) = mpsc::channel::<WriterMessage>(100);

        // Store the writer channel so background task workers can send notifications
        *self.notification_tx.write().await = Some(tx.clone());

        // Create MCP logger for sending structured log notifications to the client
        let mcp_logger = Arc::new(McpLogger::new(Arc::clone(&self.log_level), tx.clone()));
        *self.mcp_logger.write().await = Some(Arc::clone(&mcp_logger));

        // Start config watcher for hot-reload if path is provided.
        // The on_reload callback sends list_changed notifications through the
        // writer channel so Claude Code can re-fetch tools/prompts/resources.
        let _config_watcher = config_path.and_then(|path| {
            let notification_tx = tx.clone();
            let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                // Use try_send (non-blocking) since we're called from a sync context.
                // If the channel is full, the notification is dropped — acceptable.
                let _ = notification_tx.try_send(WriterMessage::Notification(
                    JsonRpcNotification::tools_list_changed(),
                ));
                let _ = notification_tx.try_send(WriterMessage::Notification(
                    JsonRpcNotification::resources_list_changed(),
                ));
            });

            ConfigWatcher::with_notifications(
                path,
                Arc::clone(&self.config),
                Some(Arc::clone(&self.validator)),
                on_reload,
            )
            .map_err(|e| {
                warn!(error = %e, "Failed to start config watcher, hot-reload disabled");
                e
            })
            .ok()
        });

        // Spawn session cleanup task (runs every 60 seconds)
        let cleanup_sm = Arc::clone(&self.session_manager);
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_sm.cleanup().await;
            }
        });

        // Spawn task store cleanup task (runs every 60 seconds)
        let cleanup_ts = Arc::clone(&self.task_store);
        let task_cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_ts.cleanup().await;
            }
        });

        // Spawn output cache cleanup task (runs every 60 seconds)
        let cleanup_oc = Arc::clone(&self.output_cache);
        let output_cache_cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_oc.cleanup().await;
            }
        });

        // Spawn writer task (single writer to stdout).
        // Handles both JSON-RPC responses and unsolicited notifications.
        let writer_handle = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(msg) = rx.recv().await {
                let json_str = match &msg {
                    WriterMessage::Response(r) => serde_json::to_string(r),
                    WriterMessage::Notification(n) => serde_json::to_string(n),
                    WriterMessage::Request(r) => serde_json::to_string(&r),
                    WriterMessage::BatchResponse(responses) => serde_json::to_string(responses),
                };
                let Ok(json_str) = json_str else {
                    error!("Failed to serialize message");
                    continue;
                };
                debug!(message = %json_str, "Sending message");

                if let Err(e) = stdout.write_all(json_str.as_bytes()).await {
                    error!(error = %e, "Failed to write message");
                    break;
                }
                if let Err(e) = stdout.write_all(b"\n").await {
                    error!(error = %e, "Failed to write newline");
                    break;
                }
                if let Err(e) = stdout.flush().await {
                    error!(error = %e, "Failed to flush stdout");
                    break;
                }
            }
        });

        // Reader loop
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        info!("MCP SSH Bridge server starting...");

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                // EOF - client disconnected
                info!("Client disconnected, shutting down");
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!(request = %trimmed, "Received message");

            // Parse as single message or batch (JSON-RPC 2.0)
            let incoming = Self::parse_incoming(trimmed);
            let incoming = match incoming {
                Ok(msg) => msg,
                Err(e) => {
                    error!(error = %e, "Failed to parse message");
                    let response = JsonRpcResponse::error(
                        None,
                        JsonRpcError::parse_error(format!("Invalid JSON: {e}")),
                    );
                    let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                    continue;
                }
            };

            match incoming {
                IncomingMessage::Single(message) => {
                    let Some(request) = self.route_incoming_message(message, &tx).await else {
                        continue;
                    };

                    // Acquire permit (blocks if at concurrency limit)
                    let Ok(permit) = self.concurrent_limit.clone().acquire_owned().await else {
                        error!("Semaphore closed unexpectedly");
                        break;
                    };

                    let server = Arc::clone(&self);
                    let tx = tx.clone();

                    // Spawn worker task for this request
                    tokio::spawn(async move {
                        let response = server.handle_request(request).await;
                        let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                        drop(permit);
                    });
                }
                IncomingMessage::Batch(messages) => {
                    if messages.is_empty() {
                        let response = JsonRpcResponse::error(
                            None,
                            JsonRpcError::invalid_request("Empty batch"),
                        );
                        let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                        continue;
                    }

                    // Reject batches containing `initialize` (MCP spec)
                    let has_initialize = messages
                        .iter()
                        .any(|m| m.method.as_deref() == Some("initialize"));
                    if has_initialize {
                        let response = JsonRpcResponse::error(
                            None,
                            JsonRpcError::invalid_request(
                                "initialize must not be part of a batch request",
                            ),
                        );
                        let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                        continue;
                    }

                    // Execute batch requests in parallel
                    let server = Arc::clone(&self);
                    let tx_batch = tx.clone();
                    tokio::spawn(async move {
                        let mut handles = Vec::with_capacity(messages.len());
                        for message in messages {
                            let server = Arc::clone(&server);
                            handles.push(tokio::spawn(async move {
                                // Notifications (no method) don't produce responses
                                let method = message.method?;
                                let request = JsonRpcRequest {
                                    jsonrpc: message.jsonrpc,
                                    id: message.id,
                                    method,
                                    params: message.params,
                                };
                                // Notifications (no id) don't produce responses per JSON-RPC 2.0
                                let is_notification = request.id.is_none();
                                let response = server.handle_request(request).await;
                                if is_notification {
                                    None
                                } else {
                                    Some(response)
                                }
                            }));
                        }
                        let mut responses = Vec::new();
                        for handle in handles {
                            if let Ok(Some(response)) = handle.await {
                                responses.push(response);
                            }
                        }
                        if !responses.is_empty() {
                            let _ = tx_batch.send(WriterMessage::BatchResponse(responses)).await;
                        }
                    });
                }
            }
        }

        // Shutdown: stop cleanup tasks, close all tunnels and sessions
        cleanup_handle.abort();
        task_cleanup_handle.abort();
        output_cache_cleanup_handle.abort();
        self.tunnel_manager.close_all().await;
        self.session_manager.close_all().await;

        // Signal writer to stop and wait for it
        drop(tx);
        let _ = writer_handle.await;

        Ok(())
    }

    /// Parse an incoming line as a single JSON-RPC message or a batch.
    pub fn parse_incoming(
        trimmed: &str,
    ) -> std::result::Result<IncomingMessage, serde_json::Error> {
        let trimmed = trimmed.trim_start();
        if trimmed.starts_with('[') {
            let batch: Vec<JsonRpcMessage> = serde_json::from_str(trimmed)?;
            Ok(IncomingMessage::Batch(batch))
        } else {
            let msg: JsonRpcMessage = serde_json::from_str(trimmed)?;
            Ok(IncomingMessage::Single(msg))
        }
    }

    /// Route a single incoming message: client response or client request.
    ///
    /// Returns `Some(JsonRpcRequest)` if it's a request to be dispatched,
    /// or `None` if it was handled inline (e.g., a client response or notification).
    async fn route_incoming_message(
        &self,
        message: JsonRpcMessage,
        tx: &mpsc::Sender<WriterMessage>,
    ) -> Option<JsonRpcRequest> {
        // If no method, it's a response to a server-initiated request (elicitation/sampling)
        if message.method.is_none() {
            if let Some(id) = &message.id {
                let id_str = match id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let response = if let Some(error) = message.error {
                    ClientResponse::Error {
                        code: error.code,
                        message: error.message,
                        data: error.data,
                    }
                } else {
                    ClientResponse::Success(message.result.unwrap_or(Value::Null))
                };
                if !self.pending_requests.resolve(&id_str, response) {
                    debug!(id = %id_str, "Received response for unknown request ID");
                }
            }
            return None;
        }

        // Handle client notifications (no response needed per JSON-RPC 2.0)
        if message.method.as_deref() == Some("notifications/roots/list_changed") {
            self.handle_roots_changed(tx).await;
            return None;
        }
        if message.method.as_deref() == Some("notifications/cancelled") {
            Self::handle_cancellation_notification(message.params.as_ref());
            return None;
        }

        // It's a client request — convert to JsonRpcRequest
        Some(JsonRpcRequest {
            jsonrpc: message.jsonrpc,
            id: message.id,
            method: message.method.unwrap_or_default(),
            params: message.params,
        })
    }

    /// Fetch roots from the client after initialization.
    async fn fetch_roots(&self, tx: &mpsc::Sender<WriterMessage>) {
        if !self.client_supports_roots.load(Ordering::Relaxed) {
            return;
        }

        let requester = super::client_requester::ClientRequester::new(
            tx.clone(),
            Arc::clone(&self.pending_requests),
            std::time::Duration::from_secs(10),
        );

        match requester.send_request("roots/list", json!({})).await {
            Ok(value) => {
                if let Ok(result) = serde_json::from_value::<RootsListResult>(value) {
                    info!(count = result.roots.len(), "Received client roots");
                    *self.roots.write().await = result.roots;
                }
            }
            Err(e) => {
                debug!(error = %e, "Failed to fetch roots from client");
            }
        }
    }

    /// Handle `notifications/roots/list_changed` — re-fetch roots.
    async fn handle_roots_changed(&self, tx: &mpsc::Sender<WriterMessage>) {
        info!("Client roots changed, re-fetching");
        self.fetch_roots(tx).await;
    }

    /// Get the current client roots (for path validation).
    pub async fn get_roots(&self) -> Vec<RootEntry> {
        self.roots.read().await.clone()
    }

    /// Handle a single JSON-RPC request and return the response.
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();

        match request.method.as_str() {
            "initialize" => self.handle_initialize(id, request.params).await,
            "initialized" => {
                // After handshake, fetch roots if client supports them.
                // Spawn as background task since we can't block the response.
                if self.client_supports_roots.load(Ordering::Relaxed) {
                    let notification_tx = self.notification_tx.read().await.clone();
                    if let Some(tx) = notification_tx {
                        let roots = Arc::clone(&self.roots);
                        let pending = Arc::clone(&self.pending_requests);
                        tokio::spawn(async move {
                            let requester = super::client_requester::ClientRequester::new(
                                tx,
                                pending,
                                std::time::Duration::from_secs(10),
                            );
                            match requester.send_request("roots/list", json!({})).await {
                                Ok(value) => {
                                    if let Ok(result) =
                                        serde_json::from_value::<RootsListResult>(value)
                                    {
                                        info!(count = result.roots.len(), "Fetched client roots");
                                        *roots.write().await = result.roots;
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, "Failed to fetch roots");
                                }
                            }
                        });
                    }
                }
                JsonRpcResponse::success(id, json!({}))
            }
            "tools/list" => self.handle_tools_list(id, request.params.as_ref()),
            "tools/call" => self.handle_tools_call(id, request.params).await,
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params).await,
            "resources/list" => self.handle_resources_list(id).await,
            "resources/read" => self.handle_resources_read(id, request.params).await,
            "tasks/get" => self.handle_tasks_get(id, request.params).await,
            "tasks/result" => self.handle_tasks_result(id, request.params).await,
            "tasks/list" => self.handle_tasks_list(id, request.params).await,
            "tasks/cancel" => self.handle_tasks_cancel(id, request.params).await,
            "completions/complete" => self.handle_completions_complete(id, request.params),
            "logging/setLevel" => self.handle_logging_set_level(id, request.params),
            "resources/templates/list" => self.handle_resource_templates_list(id),
            "resources/subscribe" => self.handle_resource_subscribe(id, request.params).await,
            "resources/unsubscribe" => self.handle_resource_unsubscribe(id, request.params).await,
            "ping" => JsonRpcResponse::success(id, json!({})),
            _ => {
                error!(method = %request.method, "Unknown method");
                JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method))
            }
        }
    }

    /// Build the server extensions map based on current configuration.
    ///
    /// Auto-detects: tasks (always), output-pagination (always, since
    /// `OutputCache` is always created), multi-host (if >1 host configured).
    async fn build_server_extensions(&self) -> Option<HashMap<String, Value>> {
        use super::protocol::extensions;

        let mut exts = HashMap::new();
        exts.insert(extensions::TASKS.to_string(), json!({}));
        exts.insert(extensions::OUTPUT_PAGINATION.to_string(), json!({}));

        let host_count = self.config.read().await.hosts.len();
        if host_count > 1 {
            exts.insert(
                extensions::MULTI_HOST.to_string(),
                json!({ "hosts": host_count }),
            );
        }

        Some(exts)
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_initialize(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        // Parse initialize params, negotiate version, and store client info
        let mut negotiated_version = PROTOCOL_VERSION.to_string();

        if let Some(p) = params {
            match serde_json::from_value::<InitializeParams>(p) {
                Ok(init_params) => {
                    info!(
                        client = %init_params.client_info.name,
                        version = %init_params.client_info.version,
                        protocol = %init_params.protocol_version,
                        "Client connected"
                    );

                    // MCP version negotiation: echo client version if we support it,
                    // otherwise respond with our latest version
                    if SUPPORTED_PROTOCOL_VERSIONS.contains(&init_params.protocol_version.as_str())
                    {
                        negotiated_version = init_params.protocol_version.clone();
                    }

                    // Resolve per-client max_output_chars override
                    let (effective, yaml_default) = {
                        let config = self.config.read().await;
                        (
                            config
                                .limits
                                .effective_max_output_chars(Some(&init_params.client_info.name)),
                            config.limits.max_output_chars,
                        )
                    };
                    if effective != yaml_default {
                        info!(
                            client = %init_params.client_info.name,
                            max_output_chars = effective,
                            "Applied client-specific max_output_chars override"
                        );
                        *self.runtime_max_output_chars.write().await = Some(effective);
                    }

                    // Check if client supports roots capability
                    if init_params.capabilities.roots.is_some() {
                        self.client_supports_roots.store(true, Ordering::Relaxed);
                        info!("Client supports roots capability");
                    }

                    *self.client_info.write().await = Some(init_params.client_info);
                }
                Err(e) => {
                    debug!(error = %e, "Could not parse initialize params (continuing anyway)");
                }
            }
        }

        self.initialized.store(true, Ordering::SeqCst);

        let instructions = {
            let config = self.config.read().await;
            instructions::build_instructions(&config, self.registry.len())
        };

        let result = InitializeResult {
            protocol_version: negotiated_version,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability { list_changed: true }),
                resources: Some(ResourcesCapability {
                    subscribe: true,
                    list_changed: true,
                }),
                tasks: Some(TasksCapability {
                    list: json!({}),
                    cancel: json!({}),
                    requests: TaskRequestsCapability {
                        tools: Some(TaskToolsCapability { call: json!({}) }),
                    },
                }),
                completions: Some(CompletionsCapability {}),
                logging: Some(LoggingCapability {}),
                extensions: self.build_server_extensions().await,
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
                description: Some(
                    "Secure SSH bridge for remote server management via MCP".to_string(),
                ),
                website_url: Some("https://github.com/petermachini/mcp-ssh-bridge".to_string()),
            },
            instructions: Some(instructions),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    fn handle_tools_list(&self, id: Option<Value>, params: Option<&Value>) -> JsonRpcResponse {
        use super::registry::tool_group;

        let page_size = 50;

        // Filtering by annotation hints and tool group
        let filter_read_only = params
            .and_then(|p| p.get("readOnlyHint"))
            .and_then(Value::as_bool);
        let filter_destructive = params
            .and_then(|p| p.get("destructiveHint"))
            .and_then(Value::as_bool);
        let filter_group = params.and_then(|p| p.get("group")).and_then(|v| v.as_str());

        let mut all_tools = self.registry.list_tools();

        if let Some(group_name) = filter_group {
            all_tools.retain(|t| tool_group(&t.name) == group_name);
        }
        if let Some(read_only) = filter_read_only {
            all_tools.retain(|t| {
                t.annotations
                    .as_ref()
                    .and_then(|a| a.read_only_hint)
                    .unwrap_or(false)
                    == read_only
            });
        }
        if let Some(destructive) = filter_destructive {
            all_tools.retain(|t| {
                t.annotations
                    .as_ref()
                    .and_then(|a| a.destructive_hint)
                    .unwrap_or(false)
                    == destructive
            });
        }

        // Cursor-based pagination (only when cursor is provided)
        let cursor = params
            .and_then(|p| p.get("cursor"))
            .and_then(|c| c.as_str());

        let (page, next_cursor) = if let Some(cursor_val) = cursor {
            let start = cursor_val.parse::<usize>().unwrap_or(0);
            let end = (start + page_size).min(all_tools.len());
            let page = if start < all_tools.len() {
                all_tools[start..end].to_vec()
            } else {
                Vec::new()
            };
            let next = if end < all_tools.len() {
                Some(end.to_string())
            } else {
                None
            };
            (page, next)
        } else {
            // No cursor: return all tools (no pagination)
            (all_tools, None)
        };

        let result = ToolsListResult {
            tools: page,
            next_cursor,
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_tools_call(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let call_params: ToolCallParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(tool = %call_params.name, "Tool call");

        // Create progress reporter if the client sent a progressToken
        let progress_reporter = call_params
            .meta
            .as_ref()
            .and_then(|m| m.progress_token.clone())
            .and_then(|token| {
                let tx_guard = self.notification_tx.try_read().ok()?;
                let tx = tx_guard.as_ref()?.clone();
                Some(ProgressReporter::new(token, tx, Some(3)))
            });

        // Task-augmented request: spawn background worker and return immediately
        if let Some(task_request) = call_params.task {
            return self
                .handle_tools_call_async(call_params.name, call_params.arguments, task_request, id)
                .await;
        }

        // Synchronous path
        if let Some(ref reporter) = progress_reporter {
            reporter.report(1, Some("Preparing execution..."));
        }

        let ctx = self.create_tool_context().await;

        if let Some(ref reporter) = progress_reporter {
            reporter.report(2, Some(&format!("Executing {}...", call_params.name)));
        }

        let start = Instant::now();
        let tool_name = call_params.name.clone();
        let host_for_metrics = call_params
            .arguments
            .as_ref()
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("local")
            .to_string();

        match self
            .registry
            .execute(&call_params.name, call_params.arguments, &ctx)
            .await
        {
            Ok(result) => {
                let elapsed_ms = start.elapsed().as_millis();

                if let Some(ref reporter) = progress_reporter {
                    reporter.report(3, Some("Done"));
                }

                // Compute output size for logging and metrics
                let output_chars: usize = result
                    .content
                    .iter()
                    .map(|c| match c {
                        ToolContent::Text { text } => text.len(),
                        _ => 0,
                    })
                    .sum();
                let is_truncated = result.content.iter().any(|c| {
                    matches!(c,
                    ToolContent::Text { text } if text.contains("output_id:"))
                });

                // Record metrics
                self.metrics.record_tool_call(&tool_name, &host_for_metrics);
                self.metrics
                    .record_tool_output(&tool_name, output_chars as u64);

                // Contextual log: give Claude structured info about the execution
                if let Some(logger) = self.mcp_logger.read().await.as_ref() {
                    logger.log(
                        super::protocol::LogLevel::Debug,
                        "mcp-ssh-bridge",
                        json!({
                            "event": "tool_complete",
                            "tool": tool_name,
                            "duration_ms": elapsed_ms,
                            "output_chars": output_chars,
                            "truncated": is_truncated,
                        }),
                    );
                }

                // Strip non-standard App content items — clients that don't
                // advertise MCP Apps support reject unknown content types.
                let result = result.without_apps();

                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                let elapsed_ms = start.elapsed().as_millis();
                error!(error = %e, "Tool call failed");
                self.metrics.record_tool_call(&tool_name, "unknown");
                self.metrics.record_tool_error();

                if let Some(logger) = self.mcp_logger.read().await.as_ref() {
                    logger.log(
                        super::protocol::LogLevel::Error,
                        "mcp-ssh-bridge",
                        json!({
                            "event": "tool_failed",
                            "tool": tool_name,
                            "duration_ms": elapsed_ms,
                            "error": e.to_string(),
                        }),
                    );
                }
                if let Some(ref reporter) = progress_reporter {
                    reporter.report(3, Some(&format!("Failed: {e}")));
                }
                let error_result = ToolCallResult::error(e.to_string());
                JsonRpcResponse::success_or_serialize_error(id, &error_result)
            }
        }
    }

    /// Handle a task-augmented `tools/call`: create a task, spawn a background
    /// worker, and return `CreateTaskResult` immediately.
    async fn handle_tools_call_async(
        &self,
        tool_name: String,
        arguments: Option<Value>,
        task_request: super::protocol::TaskRequest,
        id: Option<Value>,
    ) -> JsonRpcResponse {
        // Get the handler first to validate the tool exists
        let Some(handler) = self.registry.get(&tool_name) else {
            let error_result = ToolCallResult::error(format!("Unknown tool: {tool_name}"));
            return JsonRpcResponse::success_or_serialize_error(id, &error_result);
        };
        let handler = Arc::clone(handler);

        // Create the task
        let Some((task_id, cancel_token)) = self.task_store.create_task(task_request.ttl).await
        else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::internal_error("Task limit reached, try again later"),
            );
        };

        // Get the initial task info for the response
        let Some(task_info) = self.task_store.get_task(&task_id).await else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::internal_error("Task created but expired immediately (TTL too low)"),
            );
        };

        // Clone dependencies for the background worker
        let task_store = Arc::clone(&self.task_store);
        let notification_tx = Arc::clone(&self.notification_tx);
        let ctx = self.create_tool_context().await;

        // Spawn the background worker
        tokio::spawn(async move {
            let result = tokio::select! {
                res = handler.execute(arguments, &ctx) => res,
                () = cancel_token.cancelled() => {
                    // Task was cancelled, no need to store result
                    return;
                }
            };

            // Store the result and send notification
            let info = match result {
                Ok(tool_result) => {
                    let tool_result = tool_result.without_apps();
                    let result_value =
                        serde_json::to_value(&tool_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    task_store.complete_task(&task_id, result_value).await
                }
                Err(e) => {
                    let error_result = ToolCallResult::error(e.to_string());
                    let result_value =
                        serde_json::to_value(&error_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    task_store
                        .fail_task(&task_id, &e.to_string(), result_value)
                        .await
                }
            };

            // Send status notification (best-effort)
            if let Some(info) = info {
                let tx_guard = notification_tx.read().await;
                if let Some(tx) = tx_guard.as_ref() {
                    let _ = tx.try_send(WriterMessage::Notification(
                        JsonRpcNotification::task_status(&info),
                    ));
                }
            }
        });

        // Return CreateTaskResult immediately
        let create_result = CreateTaskResult {
            task: task_info,
            meta: None,
        };
        JsonRpcResponse::success_or_serialize_error(id, &create_result)
    }

    fn handle_prompts_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let result = PromptsListResult {
            prompts: self.prompt_registry.list(),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    async fn handle_prompts_get(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let get_params: PromptsGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(prompt = %get_params.name, "Prompt get");

        let ctx = self.create_tool_context().await;

        match self
            .prompt_registry
            .get_messages(&get_params.name, get_params.arguments, &ctx)
            .await
        {
            Ok(messages) => {
                let result = PromptsGetResult { messages };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Prompt get failed");
                JsonRpcResponse::error(id, JsonRpcError::invalid_params(e.to_string()))
            }
        }
    }

    async fn handle_resources_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let ctx = self.create_tool_context().await;

        match self.resource_registry.list(&ctx).await {
            Ok(resources) => {
                let result = ResourcesListResult { resources };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Resources list failed");
                JsonRpcResponse::error(id, JsonRpcError::internal_error(e.to_string()))
            }
        }
    }

    async fn handle_resources_read(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let read_params: ResourcesReadParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(uri = %read_params.uri, "Resource read");

        let ctx = self.create_tool_context().await;

        match self.resource_registry.read(&read_params.uri, &ctx).await {
            Ok(contents) => {
                let result = ResourcesReadResult { contents };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Resource read failed");
                JsonRpcResponse::error(id, JsonRpcError::internal_error(e.to_string()))
            }
        }
    }

    // =========================================================================
    // Resource template & subscription handlers
    // =========================================================================

    fn handle_resource_templates_list(&self, id: Option<Value>) -> JsonRpcResponse {
        use super::protocol::ResourceTemplate;

        let Ok(config) = self.config.try_read() else {
            return JsonRpcResponse::success(id, json!({ "resourceTemplates": [] }));
        };
        let templates: Vec<ResourceTemplate> = config
            .hosts
            .keys()
            .map(|host| ResourceTemplate {
                uri_template: format!("ssh://{host}/{{path}}"),
                name: format!("{host} file access"),
                description: Some(format!("Access files on {host} via SSH")),
                mime_type: None,
            })
            .collect();

        JsonRpcResponse::success_or_serialize_error(id, &json!({ "resourceTemplates": templates }))
    }

    async fn handle_resource_subscribe(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if uri.is_empty() {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("uri is required"));
        }
        let sub_id = uuid::Uuid::new_v4().to_string();
        {
            let mut subs = self.resource_subscriptions.write().await;
            subs.entry(uri.to_string())
                .or_default()
                .push(sub_id.clone());
        }
        JsonRpcResponse::success(id, json!({"subscriptionId": sub_id}))
    }

    async fn handle_resource_unsubscribe(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !uri.is_empty() {
            let mut subs = self.resource_subscriptions.write().await;
            subs.remove(uri);
        }
        JsonRpcResponse::success(id, json!({}))
    }

    // =========================================================================
    // Cancellation notification handler
    // =========================================================================

    fn handle_cancellation_notification(params: Option<&Value>) {
        if let Some(request_id) = params.and_then(|p| p.get("requestId")) {
            info!(request_id = %request_id, "Received cancellation notification");
            // Future: cancel running task by request_id
        }
    }

    // =========================================================================
    // Task handlers (MCP 2025-11-25+)
    // =========================================================================

    async fn handle_tasks_get(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let get_params: TaskGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        match self.task_store.get_task(&get_params.task_id).await {
            Some(info) => JsonRpcResponse::success_or_serialize_error(id, &info),
            None => JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", get_params.task_id)),
            ),
        }
    }

    async fn handle_tasks_result(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let result_params: TaskResultParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // Block until the task reaches a terminal state
        match self
            .task_store
            .wait_for_result(&result_params.task_id)
            .await
        {
            Some(result) => {
                // Inject task correlation metadata
                let mut response = result;
                if let Some(obj) = response.as_object_mut() {
                    obj.insert(
                        "_meta".to_string(),
                        json!({
                            "io.modelcontextprotocol/related-task": {
                                "taskId": result_params.task_id
                            }
                        }),
                    );
                }
                JsonRpcResponse::success(id, response)
            }
            None => JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", result_params.task_id)),
            ),
        }
    }

    async fn handle_tasks_list(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let list_params: TaskListParams = params
            .and_then(|p| serde_json::from_value(p).ok())
            .unwrap_or(TaskListParams { cursor: None });

        let (tasks, next_cursor) = self
            .task_store
            .list_tasks(list_params.cursor.as_deref(), 20)
            .await;

        let result = TaskListResult { tasks, next_cursor };
        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    async fn handle_tasks_cancel(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let cancel_params: TaskCancelParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        match self.task_store.cancel_task(&cancel_params.task_id).await {
            Ok(info) => JsonRpcResponse::success_or_serialize_error(id, &info),
            Err(e) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(e)),
        }
    }

    // ========================================================================
    // Completions
    // ========================================================================

    fn handle_completions_complete(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        use crate::ports::CompletionProvider;

        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let complete_params: CompletionsCompleteParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // We need a sync config snapshot for completion. Use try_read to avoid
        // blocking; if the config lock is held, return empty completions.
        let Ok(config) = self.config.try_read() else {
            return JsonRpcResponse::success_or_serialize_error(
                id,
                &CompletionsCompleteResult {
                    completion: CompletionResult {
                        values: Vec::new(),
                        total: None,
                        has_more: None,
                    },
                },
            );
        };

        // Build a minimal ToolContext with just the config for completion lookups.
        // CompletionProvider only uses ctx.config.
        let ctx = ToolContext::new(
            Arc::new(config.clone()),
            Arc::clone(&self.validator),
            Arc::clone(&self.sanitizer),
            Arc::clone(&self.audit_logger),
            Arc::clone(&self.history),
            Arc::clone(&self.connection_pool),
            Arc::clone(&self.execute_use_case),
            Arc::clone(&self.rate_limiter),
            Arc::clone(&self.session_manager),
        );

        let values = match &complete_params.reference {
            CompletionRef::Prompt { name } => self
                .completion_provider
                .complete_prompt_argument(
                    name,
                    &complete_params.argument.name,
                    &complete_params.argument.value,
                    &ctx,
                )
                .unwrap_or_default(),
            CompletionRef::Resource { uri } => self
                .completion_provider
                .complete_resource_argument(
                    uri,
                    &complete_params.argument.name,
                    &complete_params.argument.value,
                    &ctx,
                )
                .unwrap_or_default(),
        };

        let total = values.len();
        let has_more = total > 100;
        let values: Vec<String> = values.into_iter().take(100).collect();

        JsonRpcResponse::success_or_serialize_error(
            id,
            &CompletionsCompleteResult {
                completion: CompletionResult {
                    values,
                    total: Some(total),
                    has_more: if has_more { Some(true) } else { None },
                },
            },
        )
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn handle_logging_set_level(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let level_params: LoggingSetLevelParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        self.log_level
            .store(level_params.level.severity(), Ordering::Relaxed);
        info!(level = ?level_params.level, "MCP log level updated");

        JsonRpcResponse::success(id, json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
        SshConfigDiscovery, ToolGroupsConfig,
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_server() -> McpServer {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };
        let (server, _audit_task) = McpServer::new(config);
        server
    }

    #[tokio::test]
    async fn test_handle_initialize_negotiates_matching_version() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Server echoes back the client's version when supported
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["serverInfo"]["version"], SERVER_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn test_handle_initialize_negotiates_older_version() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Server echoes back an older supported version
        assert_eq!(result["protocolVersion"], "2025-06-18");
    }

    #[tokio::test]
    async fn test_handle_initialize_unsupported_version_returns_latest() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "1999-01-01",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Unsupported version: server responds with its latest
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_handle_initialize_no_params_uses_default_version() {
        let server = create_test_server();

        let response = server.handle_initialize(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_handle_initialize_includes_server_metadata() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;
        let result = response.result.unwrap();

        assert!(result["serverInfo"]["description"].is_string());
        assert!(result["serverInfo"]["websiteUrl"].is_string());
        assert!(result["instructions"].is_string());
    }

    #[tokio::test]
    async fn test_handle_initialize_sets_initialized_flag() {
        let server = create_test_server();
        assert!(!server.initialized.load(Ordering::SeqCst));

        server.handle_initialize(Some(json!(1)), None).await;

        assert!(server.initialized.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_handle_initialize_includes_extensions() {
        let server = create_test_server();
        let response = server.handle_initialize(Some(json!(1)), None).await;
        let result = response.result.unwrap();
        let caps = &result["capabilities"];

        // Completions and logging capabilities are present
        assert!(caps["completions"].is_object());
        assert!(caps["logging"].is_object());

        // Extensions should contain tasks + output-pagination at minimum
        let exts = &caps["extensions"];
        assert!(exts.is_object(), "extensions should be an object");
        assert!(
            exts["io.modelcontextprotocol/tasks"].is_object(),
            "tasks extension should be present"
        );
        assert!(
            exts["com.mcp-ssh-bridge/output-pagination"].is_object(),
            "output-pagination extension should be present"
        );
    }

    #[test]
    fn test_handle_tools_list_returns_all_registered_tools() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // Verify default tools are present
        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        assert!(tool_names.contains(&"ssh_exec"));
        assert!(tool_names.contains(&"ssh_status"));
        assert!(tool_names.contains(&"ssh_history"));
        assert!(tool_names.contains(&"ssh_upload"));
        assert!(tool_names.contains(&"ssh_download"));
    }

    #[test]
    fn test_handle_tools_list_tools_have_required_fields() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        for tool in tools {
            assert!(tool["name"].is_string(), "Tool missing name");
            assert!(tool["description"].is_string(), "Tool missing description");
            assert!(tool["inputSchema"].is_object(), "Tool missing inputSchema");
        }
    }

    #[tokio::test]
    async fn test_handle_tools_call_missing_params() {
        let server = create_test_server();

        let response = server.handle_tools_call(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
        assert!(error.message.contains("Missing"));
    }

    #[tokio::test]
    async fn test_handle_tools_call_invalid_params() {
        let server = create_test_server();
        let params = json!({
            "invalid": "structure"
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
    }

    #[tokio::test]
    async fn test_handle_tools_call_unknown_tool() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent_tool",
            "arguments": {}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        // Unknown tool returns success with error content (MCP spec)
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
    }

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "unknown/method".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601); // Method not found
        assert!(error.message.contains("unknown/method"));
    }

    #[tokio::test]
    async fn test_handle_request_ping() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(42)),
            method: "ping".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!(42)));
    }

    #[tokio::test]
    async fn test_handle_request_initialized_notification() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialized".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_tools_call_ssh_status_returns_content() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["content"].is_array());
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());
        assert_eq!(content[0]["type"], "text");
    }

    #[test]
    fn test_handle_prompts_list_returns_all_prompts() {
        let server = create_test_server();
        let response = server.handle_prompts_list(Some(json!(1)));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();

        assert_eq!(prompts.len(), 7);

        let names: Vec<&str> = prompts
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"system-health"));
        assert!(names.contains(&"deploy"));
        assert!(names.contains(&"security-audit"));
        assert!(names.contains(&"troubleshoot"));
        assert!(names.contains(&"docker-health"));
        assert!(names.contains(&"k8s-overview"));
        assert!(names.contains(&"backup-verify"));
    }

    #[test]
    fn test_handle_prompts_list_prompts_have_required_fields() {
        let server = create_test_server();
        let response = server.handle_prompts_list(Some(json!(1)));

        let result = response.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();

        for prompt in prompts {
            assert!(prompt["name"].is_string(), "Prompt missing name");
            assert!(
                prompt["description"].is_string(),
                "Prompt missing description"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_prompts_get_system_health() {
        let server = create_test_server();
        let params = json!({
            "name": "system-health",
            "arguments": {
                "host": "test-server"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let messages = result["messages"].as_array().unwrap();

        assert!(!messages.is_empty());
        assert_eq!(messages[0]["role"], "user");
        assert!(
            messages[0]["content"]["text"]
                .as_str()
                .unwrap()
                .contains("test-server")
        );
    }

    #[tokio::test]
    async fn test_handle_prompts_get_unknown_prompt() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent-prompt",
            "arguments": {}
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
        assert!(error.message.contains("nonexistent-prompt"));
    }

    #[tokio::test]
    async fn test_handle_prompts_get_missing_params() {
        let server = create_test_server();
        let response = server.handle_prompts_get(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_initialize_includes_prompts_capability() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["capabilities"]["prompts"].is_object());
    }

    // ============== Additional Initialize Tests ==============

    #[tokio::test]
    async fn test_initialize_with_null_id() {
        let server = create_test_server();
        let response = server.handle_initialize(None, None).await;

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[tokio::test]
    async fn test_initialize_with_string_id() {
        let server = create_test_server();
        let response = server
            .handle_initialize(Some(json!("request-1")), None)
            .await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!("request-1")));
    }

    #[tokio::test]
    async fn test_initialize_includes_resources_capability() {
        let server = create_test_server();
        let response = server.handle_initialize(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["capabilities"]["resources"].is_object());
    }

    #[tokio::test]
    async fn test_initialize_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_initialize(Some(json!(1)), None).await;
        let response2 = server.handle_initialize(Some(json!(2)), None).await;

        // Both should succeed (no state prevents re-initialization)
        assert!(response1.error.is_none());
        assert!(response2.error.is_none());
    }

    #[tokio::test]
    async fn test_initialize_invalid_params_still_succeeds() {
        let server = create_test_server();
        let params = json!({
            "invalid": "params",
            "completely": "wrong"
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        // Should still succeed (params are optional/best-effort)
        assert!(response.error.is_none());
    }

    // ============== Additional Tools Tests ==============

    #[test]
    fn test_tools_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_tools_list(None, None);

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[test]
    fn test_tools_list_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_tools_list(Some(json!(1)), None);
        let response2 = server.handle_tools_list(Some(json!(2)), None);

        assert!(response1.error.is_none());
        assert!(response2.error.is_none());

        // Results should be identical
        assert_eq!(response1.result, response2.result);
    }

    #[tokio::test]
    async fn test_tools_call_with_null_arguments() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": null
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        // Should succeed (null arguments treated as empty)
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_tools_call_empty_name() {
        let server = create_test_server();
        let params = json!({
            "name": "",
            "arguments": {}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        // Empty name should result in tool not found
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
    }

    // ============== Additional Prompts Tests ==============

    #[tokio::test]
    async fn test_prompts_get_deploy() {
        let server = create_test_server();
        let params = json!({
            "name": "deploy",
            "arguments": {
                "host": "prod-server",
                "service": "my-app"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert!(!messages.is_empty());
    }

    #[tokio::test]
    async fn test_prompts_get_security_audit() {
        let server = create_test_server();
        let params = json!({
            "name": "security-audit",
            "arguments": {
                "host": "server1"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_prompts_get_invalid_params_structure() {
        let server = create_test_server();
        let params = json!([1, 2, 3]); // Array instead of object

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    // ============== Resources Tests ==============

    #[tokio::test]
    async fn test_resources_list_returns_array() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["resources"].is_array());
    }

    #[tokio::test]
    async fn test_resources_read_missing_params() {
        let server = create_test_server();
        let response = server.handle_resources_read(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_resources_read_invalid_uri() {
        let server = create_test_server();
        let params = json!({
            "uri": "invalid://not-a-resource"
        });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        // Should return error for unknown resource type
        assert!(response.error.is_some());
    }

    // ============== Request Handling Tests ==============

    #[tokio::test]
    async fn test_handle_request_with_null_id() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "ping".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_tools_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(99)),
            method: "tools/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!(99)));
    }

    #[tokio::test]
    async fn test_handle_request_prompts_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(100)),
            method: "prompts/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(101)),
            method: "resources/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    // ============== Server Creation Tests ==============

    #[test]
    fn test_server_creation_with_default_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let (server, audit_task) = McpServer::new(config);

        // Server should be created
        assert!(!server.initialized.load(std::sync::atomic::Ordering::SeqCst));

        // Audit task might be None if audit is disabled by default
        drop(audit_task);
    }

    #[tokio::test]
    async fn test_server_initialized_flag() {
        let server = create_test_server();

        // Initially not initialized
        assert!(!server.initialized.load(std::sync::atomic::Ordering::SeqCst));

        // After initialize call
        server.handle_initialize(Some(json!(1)), None).await;

        // Should be initialized
        assert!(server.initialized.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ============== Edge Cases ==============

    #[tokio::test]
    async fn test_handle_request_empty_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: String::new(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601); // Method not found
    }

    #[tokio::test]
    async fn test_handle_request_unicode_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "方法/调用".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
    }

    // ============== Task Tests (MCP 2025-11-25+) ==============

    #[tokio::test]
    async fn test_initialize_includes_tasks_capability() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server.handle_initialize(Some(json!(1)), Some(params)).await;

        let result = response.result.unwrap();
        assert!(result["capabilities"]["tasks"].is_object());
        assert!(result["capabilities"]["tasks"]["list"].is_object());
        assert!(result["capabilities"]["tasks"]["cancel"].is_object());
        assert!(result["capabilities"]["tasks"]["requests"]["tools"]["call"].is_object());
    }

    #[test]
    fn test_tools_list_includes_execution_field() {
        let server = create_test_server();
        let response = server.handle_tools_list(Some(json!(1)), None);

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        for tool in tools {
            assert_eq!(
                tool["execution"]["taskSupport"], "optional",
                "Tool {} missing execution.taskSupport",
                tool["name"]
            );
        }
    }

    #[tokio::test]
    async fn test_tools_call_without_task_field_is_synchronous() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        // Synchronous: should return content directly (not CreateTaskResult)
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tools_call_with_task_field_returns_create_task_result() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 30000}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Should have task field with taskId and status
        assert!(result["task"]["taskId"].is_string());
        assert_eq!(result["task"]["status"], "working");
        assert!(result["task"]["createdAt"].is_string());
        assert!(result["task"]["pollInterval"].is_number());
    }

    #[tokio::test]
    async fn test_tools_call_async_unknown_tool() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent_tool",
            "arguments": {},
            "task": {}
        });

        let response = server.handle_tools_call(Some(json!(1)), Some(params)).await;

        // Unknown tool should return error content, not CreateTaskResult
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
    }

    #[tokio::test]
    async fn test_tasks_get_returns_status() {
        let server = create_test_server();
        // Create a task via tools/call
        let call_params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 60000}
        });
        let call_response = server
            .handle_tools_call(Some(json!(1)), Some(call_params))
            .await;
        let task_id = call_response.result.unwrap()["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // Poll the task
        let get_params = json!({"taskId": task_id});
        // Small delay to let the worker potentially finish
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let response = server
            .handle_tasks_get(Some(json!(2)), Some(get_params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["taskId"], task_id);
        // Status could be working or completed at this point
        assert!(result["status"].is_string());
    }

    #[tokio::test]
    async fn test_tasks_get_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "nonexistent-id"});

        let response = server.handle_tasks_get(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel() {
        let server = create_test_server();
        // Create a task
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["status"], "cancelled");
    }

    #[tokio::test]
    async fn test_tasks_cancel_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "no-such-task"});

        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_list_empty() {
        let server = create_test_server();

        let response = server.handle_tasks_list(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["tasks"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_tasks_list_with_tasks() {
        let server = create_test_server();
        server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.create_task(Some(60_000)).await.unwrap();

        let response = server.handle_tasks_list(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["tasks"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_tasks_result_waits_for_completion() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 60000}
        });

        let call_response = server.handle_tools_call(Some(json!(1)), Some(params)).await;
        let task_id = call_response.result.unwrap()["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // tasks/result blocks until terminal
        let result_params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(2)), Some(result_params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Should have _meta with related-task
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
        // Should have content from the tool execution
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tasks_result_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "no-such-task"});

        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_cancel_already_completed_returns_error() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "done"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let err = response.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel_already_cancelled_returns_error() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_get_on_completed_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "ok"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server.handle_tasks_get(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["status"], "completed");
        assert_eq!(result["taskId"], task_id);
    }

    #[tokio::test]
    async fn test_tasks_result_on_cancelled_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        // Cancelled tasks have no stored result — handler returns error
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_result_on_already_completed() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "result data"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tasks_get_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_get(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_cancel(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_result_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_result(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_handle_request_tasks_result_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/result".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_ne!(response.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_handle_request_tasks_get_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/get".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602); // Invalid params (task not found)
    }

    #[tokio::test]
    async fn test_handle_request_tasks_list_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        // Should succeed with empty tasks list
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["tasks"].is_array());
    }

    #[tokio::test]
    async fn test_handle_request_tasks_cancel_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/cancel".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_ne!(response.error.unwrap().code, -32601);
    }

    // ============== Resources List/Read Tests ==============

    #[tokio::test]
    async fn test_resources_list_contains_expected_resources() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        // With no hosts configured, history://recent and health://server are present
        let uris: Vec<&str> = resources
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert!(uris.contains(&"history://recent"));
        assert!(uris.contains(&"health://server"));
    }

    #[tokio::test]
    async fn test_resources_list_resources_have_required_fields() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        let result = response.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        for resource in resources {
            assert!(resource["uri"].is_string(), "Resource missing uri");
            assert!(resource["name"].is_string(), "Resource missing name");
        }
    }

    #[tokio::test]
    async fn test_resources_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_resources_list(None).await;

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[tokio::test]
    async fn test_resources_read_valid_history_uri() {
        let server = create_test_server();
        let params = json!({ "uri": "history://recent" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["contents"].is_array());
    }

    #[tokio::test]
    async fn test_resources_read_valid_health_uri() {
        let server = create_test_server();
        let params = json!({ "uri": "health://server" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["contents"].is_array());
        let contents = result["contents"].as_array().unwrap();
        assert!(!contents.is_empty());
    }

    #[tokio::test]
    async fn test_resources_read_unsupported_scheme() {
        let server = create_test_server();
        let params = json!({ "uri": "ftp://server/file" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert!(error.message.contains("ftp"));
    }

    #[tokio::test]
    async fn test_resources_read_invalid_params_structure() {
        let server = create_test_server();
        let params = json!([1, 2, 3]); // Array instead of object

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    // ============== Resource Templates Tests ==============

    #[test]
    fn test_resource_templates_list_empty_hosts() {
        let server = create_test_server();
        let response = server.handle_resource_templates_list(Some(json!(1)));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let templates = result["resourceTemplates"].as_array().unwrap();
        // No hosts configured, so no templates
        assert!(templates.is_empty());
    }

    #[test]
    fn test_resource_templates_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_resource_templates_list(None);

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    // ============== Resource Subscribe/Unsubscribe Tests ==============

    #[tokio::test]
    async fn test_resource_subscribe_valid() {
        let server = create_test_server();
        let params = json!({ "uri": "health://server" });

        let response = server
            .handle_resource_subscribe(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["subscriptionId"].is_string());
    }

    #[tokio::test]
    async fn test_resource_subscribe_missing_uri() {
        let server = create_test_server();
        let params = json!({});

        let response = server
            .handle_resource_subscribe(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_resource_unsubscribe() {
        let server = create_test_server();
        // First subscribe
        let sub_params = json!({ "uri": "health://server" });
        server
            .handle_resource_subscribe(Some(json!(1)), Some(sub_params))
            .await;

        // Then unsubscribe
        let unsub_params = json!({ "uri": "health://server" });
        let response = server
            .handle_resource_unsubscribe(Some(json!(2)), Some(unsub_params))
            .await;

        assert!(response.error.is_none());
    }

    // ============== Completions Tests ==============

    #[test]
    fn test_completions_complete_missing_params() {
        let server = create_test_server();
        let response = server.handle_completions_complete(Some(json!(1)), None);

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_completions_complete_invalid_params() {
        let server = create_test_server();
        let params = json!({ "invalid": "structure" });
        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_completions_complete_prompt_ref() {
        let server = create_test_server();
        let params = json!({
            "ref": {
                "type": "ref/prompt",
                "name": "system-health"
            },
            "argument": {
                "name": "host",
                "value": ""
            }
        });

        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["completion"].is_object());
        assert!(result["completion"]["values"].is_array());
        assert!(result["completion"]["total"].is_number());
    }

    #[test]
    fn test_completions_complete_resource_ref() {
        let server = create_test_server();
        let params = json!({
            "ref": {
                "type": "ref/resource",
                "uri": "ssh://server/{path}"
            },
            "argument": {
                "name": "path",
                "value": "/etc"
            }
        });

        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["completion"]["values"].is_array());
    }

    // ============== Logging Tests ==============

    #[test]
    fn test_logging_set_level_missing_params() {
        let server = create_test_server();
        let response = server.handle_logging_set_level(Some(json!(1)), None);

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[test]
    fn test_logging_set_level_invalid_params() {
        let server = create_test_server();
        let params = json!({ "level": "nonexistent" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params));

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[test]
    fn test_logging_set_level_debug() {
        let server = create_test_server();
        let params = json!({ "level": "debug" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        assert_eq!(server.log_level.load(Ordering::Relaxed), 0); // debug = 0
    }

    #[test]
    fn test_logging_set_level_error() {
        let server = create_test_server();
        let params = json!({ "level": "error" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        assert_eq!(server.log_level.load(Ordering::Relaxed), 4); // error = 4
    }

    // ============== Tools List Pagination Tests ==============

    #[test]
    fn test_tools_list_with_cursor_paginates() {
        let server = create_test_server();

        // First page with cursor "0"
        let params = json!({ "cursor": "0" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 50); // page_size = 50
        assert!(result["nextCursor"].is_string()); // more pages available
    }

    #[test]
    fn test_tools_list_cursor_past_end_returns_empty() {
        let server = create_test_server();

        // Cursor way past the end
        let params = json!({ "cursor": "999999" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_tools_list_no_cursor_returns_all() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // Without cursor, all tools are returned (>50)
        assert!(tools.len() > 50);
        // And no nextCursor
        assert!(result.get("nextCursor").is_none() || result["nextCursor"].is_null());
    }

    #[test]
    fn test_tools_list_filter_by_group() {
        let server = create_test_server();

        let params = json!({ "group": "docker" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(
                name.starts_with("ssh_docker"),
                "Expected docker tool, got {name}"
            );
        }
    }

    #[test]
    fn test_tools_list_filter_read_only() {
        let server = create_test_server();

        let params = json!({ "readOnlyHint": true });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for tool in tools {
            let read_only = tool["annotations"]["readOnlyHint"]
                .as_bool()
                .unwrap_or(false);
            assert!(read_only, "Tool {} not read-only", tool["name"]);
        }
    }

    #[test]
    fn test_tools_list_filter_destructive() {
        let server = create_test_server();

        let params = json!({ "destructiveHint": true });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        for tool in tools {
            let destructive = tool["annotations"]["destructiveHint"]
                .as_bool()
                .unwrap_or(false);
            assert!(destructive, "Tool {} not destructive", tool["name"]);
        }
    }

    // ============== Request Routing Coverage ==============

    #[tokio::test]
    async fn test_handle_request_completions_complete_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "completions/complete".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        // Missing params -> invalid_params, not method_not_found
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_handle_request_logging_set_level_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "logging/setLevel".to_string(),
            params: Some(json!({ "level": "info" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_templates_list_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/templates/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["resourceTemplates"].is_array());
    }

    #[tokio::test]
    async fn test_handle_request_resources_subscribe_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/subscribe".to_string(),
            params: Some(json!({ "uri": "health://server" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_unsubscribe_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/unsubscribe".to_string(),
            params: Some(json!({ "uri": "health://server" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_read_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/read".to_string(),
            params: Some(json!({ "uri": "history://recent" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    // ============== Build Server Extensions Tests ==============

    #[tokio::test]
    async fn test_build_server_extensions_includes_tasks() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        assert!(exts.contains_key("io.modelcontextprotocol/tasks"));
    }

    #[tokio::test]
    async fn test_build_server_extensions_includes_output_pagination() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        assert!(exts.contains_key("com.mcp-ssh-bridge/output-pagination"));
    }

    #[tokio::test]
    async fn test_build_server_extensions_no_multi_host_with_zero_hosts() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        // Zero hosts -> no multi-host extension
        assert!(!exts.contains_key("com.mcp-ssh-bridge/multi-host"));
    }
}
