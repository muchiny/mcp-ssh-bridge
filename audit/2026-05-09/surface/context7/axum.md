# axum — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/tokio-rs/axum`
- Topic: `DefaultBodyLimit RequestBodyLimit timeout TimeoutLayer SetSensitiveHeaders security middleware tower-http defaults`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **Body extractors ship with a 2 MiB default limit.** From upstream docs verbatim: *"For security reasons, `Bytes` will, by default, not accept bodies larger than 2MB. This limit also applies to extractors that use `Bytes` internally, such as `String`, `Json`, and `Form`."* Disabling or raising this is a security decision — `DefaultBodyLimit::disable()` is greppable and should be flagged.
2. **Timeouts come from `tower_http::timeout::TimeoutLayer`** and `tower::ServiceBuilder::timeout`. Without an explicit layer, requests inherit only the underlying TCP/Hyper read timeouts. **Pair `TimeoutLayer` with `HandleErrorLayer`** — without the error handler, Hyper closes the connection without sending a response (request appears to hang to the client).
3. **Recommended security middleware stack** (from upstream README):
   - `TraceLayer` — structured tracing/logging
   - `CorsLayer` — explicit origin allowlist
   - `RequestIdLayer` + `PropagateRequestIdLayer` — correlation, audit
   - `TimeoutLayer` (with `HandleErrorLayer`)
   - `CompressionLayer` — be cautious about CRIME/BREACH-style oracle if combined with sensitive responses
4. **Sensitive headers** — `tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer` / `SetSensitiveResponseHeadersLayer` mark headers (e.g. `Authorization`, `Cookie`) so tracing layers redact them. Required for any deployment that logs request/response.
5. **Per-route vs global layers** — `Router::layer(...)` applies to ALL routes including the fallback. Use `route_layer` to scope a middleware to specific routes.

## Audit checklist for `mcp-ssh-bridge`

- [ ] `src/mcp/transport/http*.rs` (HTTP transport, feature-gated): is `TimeoutLayer` present with `HandleErrorLayer`?
- [ ] grep for `DefaultBodyLimit::disable()` or `DefaultBodyLimit::max(...)` — flag any non-default limit.
- [ ] Confirm `SetSensitiveRequestHeadersLayer` / `SetSensitiveResponseHeadersLayer` is applied so `Authorization`, `Cookie`, `X-Api-Key` are redacted in tracing.
- [ ] Confirm `CorsLayer` uses an explicit allowlist (not `Any`) for any production-exposed endpoint.
- [ ] Confirm `RequestIdLayer` is wired so audit logs can correlate per-request.

## Raw response excerpt

```rust
let app = Router::new()
    .route("/", get(handler))
    .layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async {
                StatusCode::REQUEST_TIMEOUT
            }))
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
    );
```

> "For security reasons, `Bytes` will, by default, not accept bodies larger than 2MB. This limit also applies to extractors that use `Bytes` internally, such as `String`, `Json`, and `Form`."
