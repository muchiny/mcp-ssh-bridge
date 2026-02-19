use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{RwLock, Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::{Config, ConfigWatcher};
use crate::domain::{ExecuteCommandUseCase, OutputCache, TaskStore, TunnelManager};
use crate::error::Result;
use crate::ports::ToolContext;
use crate::security::{AuditLogger, AuditWriterTask, CommandValidator, RateLimiter, Sanitizer};
use crate::ssh::{ConnectionPool, SessionManager};

use super::history::CommandHistory;
use super::prompt_registry::{PromptRegistry, create_default_prompt_registry};
use super::protocol::{
    ClientInfo, CreateTaskResult, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, PromptsCapability,
    PromptsGetParams, PromptsGetResult, PromptsListResult, ResourcesCapability,
    ResourcesListResult, ResourcesReadParams, ResourcesReadResult, SERVER_NAME, SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS, ServerCapabilities, ServerInfo, TaskCancelParams, TaskGetParams,
    TaskListParams, TaskListResult, TaskRequestsCapability, TaskResultParams, TaskToolsCapability,
    TasksCapability, ToolCallParams, ToolCallResult, ToolsCapability, ToolsListResult,
    WriterMessage,
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
    connection_pool: Arc<ConnectionPool>,
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

        // Create connection pool
        let connection_pool = Arc::new(ConnectionPool::with_defaults());

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

        // Spawn writer task (single writer to stdout).
        // Handles both JSON-RPC responses and unsolicited notifications.
        let writer_handle = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(msg) = rx.recv().await {
                let json_str = match &msg {
                    WriterMessage::Response(r) => serde_json::to_string(r),
                    WriterMessage::Notification(n) => serde_json::to_string(n),
                };
                let json_str = match json_str {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize message");
                        continue;
                    }
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

            debug!(request = %trimmed, "Received request");

            // Parse the JSON-RPC request
            let request = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                Ok(req) => req,
                Err(e) => {
                    error!(error = %e, "Failed to parse request");
                    let response = JsonRpcResponse::error(
                        None,
                        JsonRpcError::parse_error(format!("Invalid JSON: {e}")),
                    );
                    let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                    continue;
                }
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
                drop(permit); // Release the permit
            });
        }

        // Shutdown: stop cleanup tasks, close all tunnels and sessions
        cleanup_handle.abort();
        task_cleanup_handle.abort();
        self.tunnel_manager.close_all().await;
        self.session_manager.close_all().await;

        // Signal writer to stop and wait for it
        drop(tx);
        let _ = writer_handle.await;

        Ok(())
    }

    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();

        match request.method.as_str() {
            "initialize" => self.handle_initialize(id, request.params).await,
            "initialized" => {
                // Notification, no response needed but we return empty success
                JsonRpcResponse::success(id, json!({}))
            }
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, request.params).await,
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params).await,
            "resources/list" => self.handle_resources_list(id).await,
            "resources/read" => self.handle_resources_read(id, request.params).await,
            "tasks/get" => self.handle_tasks_get(id, request.params).await,
            "tasks/result" => self.handle_tasks_result(id, request.params).await,
            "tasks/list" => self.handle_tasks_list(id, request.params).await,
            "tasks/cancel" => self.handle_tasks_cancel(id, request.params).await,
            "ping" => JsonRpcResponse::success(id, json!({})),
            _ => {
                error!(method = %request.method, "Unknown method");
                JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method))
            }
        }
    }

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

                    *self.client_info.write().await = Some(init_params.client_info);
                }
                Err(e) => {
                    debug!(error = %e, "Could not parse initialize params (continuing anyway)");
                }
            }
        }

        self.initialized.store(true, Ordering::SeqCst);

        let result = InitializeResult {
            protocol_version: negotiated_version,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability { list_changed: true }),
                resources: Some(ResourcesCapability { list_changed: true }),
                tasks: Some(TasksCapability {
                    list: json!({}),
                    cancel: json!({}),
                    requests: TaskRequestsCapability {
                        tools: Some(TaskToolsCapability { call: json!({}) }),
                    },
                }),
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
                description: Some(
                    "Secure SSH bridge for remote server management via MCP".to_string(),
                ),
                website_url: Some("https://github.com/petermachini/mcp-ssh-bridge".to_string()),
            },
            instructions: Some(
                "MCP SSH Bridge provides tools for remote server management via SSH. \
                 Always call ssh_status first to discover available host aliases. \
                 Use specialized tools (ssh_docker_*, ssh_k8s_*, ssh_service_*, \
                 ssh_net_*, ssh_git_*, etc.) over ssh_exec when available — they \
                 provide input validation, structured output, auto-detection of \
                 binaries, and safety checks. Use ssh_exec only for ad-hoc commands \
                 not covered by a specialized tool. If output is truncated, use \
                 ssh_output_fetch with the provided output_id to retrieve the rest. \
                 For multi-step workflows sharing state (cd, env vars), use \
                 ssh_session_create + ssh_session_exec instead of ssh_exec."
                    .to_string(),
            ),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    fn handle_tools_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let result = ToolsListResult {
            tools: self.registry.list_tools(),
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

        // Task-augmented request: spawn background worker and return immediately
        if let Some(task_request) = call_params.task {
            return self
                .handle_tools_call_async(call_params.name, call_params.arguments, task_request, id)
                .await;
        }

        // Synchronous path (unchanged)
        let ctx = self.create_tool_context().await;

        match self
            .registry
            .execute(&call_params.name, call_params.arguments, &ctx)
            .await
        {
            Ok(result) => JsonRpcResponse::success_or_serialize_error(id, &result),
            Err(e) => {
                error!(error = %e, "Tool call failed");
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
        let task_info = self.task_store.get_task(&task_id).await.unwrap();

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, LimitsConfig, SecurityConfig, SessionConfig, SshConfigDiscovery,
        ToolGroupsConfig,
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

    #[test]
    fn test_handle_tools_list_returns_all_registered_tools() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)));

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

        let response = server.handle_tools_list(Some(json!(1)));

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
        let response = server.handle_tools_list(None);

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[test]
    fn test_tools_list_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_tools_list(Some(json!(1)));
        let response2 = server.handle_tools_list(Some(json!(2)));

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
        let response = server.handle_tools_list(Some(json!(1)));

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
}
