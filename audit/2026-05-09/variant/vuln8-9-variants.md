# Vuln 8 / Vuln 9 Variant Analysis — 2026-05-09

**Skill:** `variant-analysis:variant-analysis` (trailofbits, v1.0.0)
**Method:** 5-step process — root-cause modelling → exact-match search → abstraction → iterative generalization → triage
**Seed bugs (already fixed):** Vuln 8 (PendingRequests cross-session, commits c60d863+6c047f3); Vuln 9 (SessionCapabilities cross-session, commit da0bbad)

---

## Step 1 — Root cause

> A mutable collection (HashMap / Vec / atomic flag) lives at `McpServer` (process-singleton) scope. It is mutated by per-session message handlers but keyed only on a non-session-scoped identifier (URI, request-id, no key, or last-writer-wins single slot). A second concurrent MCP session can read or evict the first session's entries, OR mutate state observed by all sessions.

## Step 2 — Search scope

`src/mcp/server.rs` (every field of `McpServer` struct L46-L92), plus `src/mcp/`, `src/security/`, all `*/pool.rs` checked for the same structural pattern.

## Step 3 — Iterative classification of every `McpServer` field

### Acceptable (server-scoped by design — not a finding)

| Field | Type | Why acceptable |
|---|---|---|
| `config` | `Arc<RwLock<Config>>` | Config IS server-scoped; per-session config doesn't make sense |
| `validator`, `sanitizer`, `audit_logger`, `history`, `connection_pool`, `execute_use_case`, `rate_limiter`, `registry`, `prompt_registry`, `resource_registry`, `session_manager`, `tunnel_manager`, `output_cache`, `task_store`, `metrics`, `completion_provider` | Various `Arc<...>` immutable services | Stateless / read-only / cross-session-safe by design |
| `initialized: AtomicBool` | atomic | Single-shot init flag, not session state |
| `concurrent_limit: Arc<Semaphore>` | global semaphore | Intentional global concurrency cap |
| `mcp_logger` | `Arc<RwLock<Option<...>>>` | Wraps `notification_tx`; analyzed there |

### Variants confirmed (NEW FINDINGS)

| FIND | Field | Pattern | Cross-session impact | Severity |
|---|---|---|---|---|
| **FIND-038** | `active_requests: Arc<Mutex<HashMap<String, CancellationToken>>>` (L91) | HashMap keyed on **JSON-RPC request id** (caller-chosen, NOT session-scoped). Insert at L720 (`register_request(id.clone())` — `id` is taken straight from the incoming message). Lookup-and-remove at L274 inside `cancel_request`, called by `notifications/cancelled` handler at L1826. | **Direct attack:** client A sends `tools/call { id: 42 }` → server stores `active_requests["42"] = token_A`. Concurrent client B sends `notifications/cancelled { params: { requestId: "42" } }` → `cancel_request("42")` removes A's entry, cancels A's token. Client A's tool call is aborted mid-execution. | **P0** |
| **FIND-033** | `runtime_max_output_chars: Arc<RwLock<Option<usize>>>` (L65) | Single `Option<usize>` slot. Written at L1125 inside `handle_initialize` based on `init_params.client_info.name` (per-client override profile from `LimitsConfig.client_overrides`). Read at L405 (`get_max_output_chars`) and L422 (passed to every `ToolContext`). | **Last-writer-wins.** Two concurrent HTTP clients with different `client_overrides` profiles: client A connects (slot = A's override = 200K chars), client B connects (slot = B's override = 80K chars), client A's tool calls now get truncated at B's limit. Operational quality-of-service leak. | **P1** |
| **FIND-034** | `notification_tx: Arc<RwLock<Option<mpsc::Sender<WriterMessage>>>>` (L68) | Single `Option<Sender>` slot. Overwritten on every `serve_session` entry at L653 (`*self.notification_tx.write().await = Some(tx.clone())`). Cleanup at L827-830 has a `same_channel` defensive check. Reader (writer-task at L598-603) captures the Arc at session start but uses `blocking_read()` to fetch current `tx` per notification. | Notifications fired by background workers (e.g. progress events from `task_store`) route through `notification_tx_slot.blocking_read()` → if the slot's tx points to the most-recently-connected session, A's notification reaches B's writer. **Confirms OQ-008 partially.** | **P1** |
| **FIND-036** | `resource_subscriptions: Arc<RwLock<HashMap<String, Vec<String>>>>` (L77) | HashMap keyed on **URI** (resource path), value is `Vec<subscription_id>`. Subscribe at L1763 appends to the Vec; unsubscribe at L1782 removes from it. NO session-scope on the key OR on the subscription IDs. | Two clients subscribing to the same URI share the same `Vec<String>`. When client A unsubscribes id "1", the Vec is mutated; client B's subscription "2" is unaffected — but notifications fan out to **all** sub-IDs in the Vec, meaning A and B both receive each other's notifications. Data leakage if any client's subscription contains identifying info. | **P1** |
| **FIND-037** | `roots: Arc<RwLock<Vec<RootEntry>>>` (L79) | Single `Vec<RootEntry>`. Written at L942 by `fetch_roots` with the result of `roots/list` from the *requesting* client. | **Last-writer-wins.** Client A declares roots `["~/projA"]`, client B declares roots `["/srv"]`. Tool handlers reading `ctx.roots` see whichever client called `fetch_roots` last. Confirms OQ-006 sibling case. | **P1** |
| **FIND-035** | `log_level: Arc<AtomicU8>` (L70) | Global atomic. Set by `notifications/setLevel` from any client. | Client A at debug level, client B sends `setLevel: error` → A's log notifications go silent. Cross-session denial-of-observability. Low operational impact. | **P3** |

### Variants verified secure (no finding)

| Field | Type | Why secure |
|---|---|---|
| `client_info: RwLock<Option<ClientInfo>>` (L64) | last-writer-wins on `initialize` | Read sites are limited to logging inside `handle_initialize` (L1097) — same scope as the write. Not propagated to per-session state. **OK.** |
| `ssh::ConnectionPool.connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>` (`src/ssh/pool.rs:66`) | host-alias-keyed | Pool is *meant* to be cross-session (that's the whole point of pooling). Sharing connections across MCP sessions is intentional. Not a Vuln 8/9 variant. |
| `winrm::WinRmPool.inner: Arc<RwLock<HashMap<String, PooledClient>>>` (`src/winrm/pool.rs:51`) | host-alias-keyed | Same rationale as ssh pool. Not a finding. |
| `psrp::PsrpPool.inner: Arc<RwLock<HashMap<String, PooledClient>>>` (`src/psrp/pool.rs:53`) | host-alias-keyed | Same rationale. |
| `static ANSI_ESCAPE_REGEX: LazyLock<Regex>` (`src/security/sanitizer.rs:9`) | immutable | Read-only after init. |
| `static MAP: OnceLock<HashMap<&'static str, _>>` (`src/mcp/registry.rs:78,91`) | immutable | Build-time data (tool annotations, group mapping). Read-only. |

## Step 4 — Generalization stop point

After `McpServer` field-by-field enumeration, the abstraction "process-singleton mutable collection mutated by per-session handler, no session-scope on key" yielded 6 hits. Generalizing further (e.g. to "any `Arc<RwLock<...>>` on `McpServer`") raised FP rate above 50% (the immutable-service Arcs). Stopped at field-by-field.

## Step 5 — Triage and severity

The **FIND-038 active_requests** finding is the only one in this set that enables a direct attack (cross-session denial-of-service: cancel another client's in-flight request). The pattern matches Vuln 8 exactly — same defect class, same root cause, same shape of fix needed (per-session `Arc<...>`, not server field). FIND-033/034/036/037 are quality-of-service / cross-session contamination rather than auth bypass. FIND-035 is observability disruption.

## Recommended fix shape (applies to FIND-033..038)

Same pattern as the Vuln 8/9 fixes already in this branch:

1. Move the field OUT of `McpServer` struct.
2. Allocate a fresh `Arc<...>` inside `serve_session` (mirror of `session_pending = Arc::new(PendingRequests::new())` at L641 and `session_caps = Arc::new(SessionCapabilities::new())` at L646).
3. Clone the `Arc` into spawned request-handler tasks (mirror of L734 `Arc::clone(&session_pending)` and `Arc::clone(&session_caps)`).
4. Audit every read/write site to consult the per-session handle, not `self.<field>`.

For **FIND-038 specifically**: also include the session id (or a session-scoped opaque id derived from the caller) in the `register_request` key so that even within-session id collisions can't cause cross-handler cancel.

## Findings appended to `docs/audit-2026-05-09-findings.md`

FIND-033 (P1), FIND-034 (P1), FIND-035 (P3), FIND-036 (P1), FIND-037 (P1), **FIND-038 (P0)**.
