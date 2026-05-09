# tokio — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/websites/rs_tokio`
- Topic: `task_local spawn_blocking Mutex RwLock poison cancellation safety current_thread vs multi_thread runtime isolation`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`tokio::sync::RwLock::blocking_write()` / `blocking_read()` PANIC if called inside an async context.** Must always be wrapped in `spawn_blocking`. Greppable footgun: any direct `blocking_write()` / `blocking_read()` call NOT inside a `spawn_blocking` closure is a latent panic.
2. **`spawn_blocking` is the only safe way to call sync code from async contexts** (e.g. shelling out, FS I/O on slow paths, CPU-bound loops). Without it, the runtime worker thread stalls and other tasks starve — relevant to MCP server responsiveness under load.
3. **Cancellation safety** — `tokio::select!` will drop a future at any await point. State held across `.await` in a branch is lost on cancellation. For session-scoped state in `McpServer`, ensure mutation operations are atomic before any `.await`.
4. **`tokio::sync::Mutex` is NOT poison-aware** (unlike `std::sync::Mutex`). A panic while holding a tokio Mutex does NOT poison it — the next acquirer simply gets the lock. This is by design but means we cannot rely on poisoning to detect torn invariants.
5. **`task_local!`** for per-task data is preferable to channel-passing or mutex-wrapped HashMaps when isolation is per-handler. Relevant to per-session capabilities/pending-requests after Vuln 8/9 fixes.
6. **Runtime flavor** — `current_thread` runtime is single-threaded (no `Send` requirements) but stalls on any blocking call; `multi_thread` is the default for `#[tokio::main]` without args.

## Audit checklist for `mcp-ssh-bridge`

- [ ] grep for `blocking_write\(\)` / `blocking_read\(\)` — every call site must be inside a `spawn_blocking` closure or be in unambiguously-sync code (e.g. `Drop` impls, tests).
- [ ] grep for any synchronous file I/O, CLI subprocess wait, or DB call inside an async fn that is NOT wrapped in `spawn_blocking`.
- [ ] After the Vuln 8/9 per-session fixes, confirm the new state-mutating paths in `McpServer` perform atomic updates BEFORE any `.await` to keep cancellation-safe.
- [ ] Audit any `tokio::sync::Mutex` use in security-critical paths (validator, session store, audit) — torn invariants on panic will not be visible via poisoning. Consider explicit invariant checks.
- [ ] Search for opportunities to convert globally-shared `Arc<Mutex<HashMap<SessionId, _>>>` into `task_local!` per-session storage.

## Raw response excerpt

```
This method is intended for use cases where you need to use this rwlock in
asynchronous code as well as in synchronous code.
This function panics if called within an asynchronous execution context.
```

```rust
let blocking_task = tokio::task::spawn_blocking({
    let rwlock = Arc::clone(&rwlock);
    move || {
        // This shall block until the `read_lock` is released.
        let mut write_lock = rwlock.blocking_write();
        *write_lock = 2;
    }
});
```
