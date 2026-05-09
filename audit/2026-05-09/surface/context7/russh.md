# russh — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/eugeny/russh`
- Topic: `client host key verification check_server_key kex algorithms cipher allowlist preferred algorithms recent CVE security defaults`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`Handler::check_server_key` is the only host-key verification hook.** The default impl in the upstream example returns `Ok(true)` (accept any) — a comment in the doc explicitly says "In production, verify the server's host key". A custom implementation must compare the presented `ssh_key::PublicKey` against a pinned/known-hosts store; otherwise the client is vulnerable to MITM.
2. **Algorithm allowlists are configured via `client::Config::preferred: Preferred { kex, key, cipher, mac, compression }`** as `Cow<'static, [...]>` slices. The recommended-default snippet in the upstream docs uses:
   - kex: `CURVE25519`, `ECDH_SHA2_NISTP256`
   - key: `ED25519`, `ECDSA_SHA2_NISTP256`, `RSA_SHA2_256`
   - cipher: `CHACHA20_POLY1305`, `AES_256_GCM`
   - mac: `HMAC_SHA2_256_ETM`, `HMAC_SHA2_256`
3. **Re-key limits matter** — the example sets `Limits::new(1<<30, 1<<30, Duration::from_secs(3600))` for write/read/time. Without explicit re-keying limits, long-lived sessions accumulate per-key data beyond safe cryptographic bounds.
4. **Inactivity / keepalive** — the Config exposes `inactivity_timeout`, `keepalive_interval`, `keepalive_max`. Defaults in `client::Config::default()` are NOT necessarily safe for an idle pool — verify in our `src/ssh/pool.rs`.
5. **`SshId`** can be customized; revealing the bridge's exact identification string is mostly informational but leaks fingerprint to remote hosts.

## Audit checklist for `mcp-ssh-bridge`

- [ ] `src/ssh/client.rs` (and any custom `Handler` impl): does `check_server_key` actually verify against a stored fingerprint? Look for any path that returns `Ok(true)` unconditionally.
- [ ] `src/ssh/client.rs` / `src/config/types.rs`: are `Preferred` algorithms explicitly set, or do we accept the upstream `Default` (which may include weaker algos for compatibility)?
- [ ] `src/ssh/client.rs`: are re-key `Limits` set?
- [ ] `src/ssh/pool.rs`: are inactivity/keepalive timeouts explicitly configured (not relying on `Default`)?

## Raw response excerpt

```
### Connect and Authenticate with Russh Client
...
async fn check_server_key(
    &mut self,
    _server_public_key: &ssh_key::PublicKey,
) -> Result<bool, Self::Error> {
    // In production, verify the server's host key
    Ok(true)
}
```

```rust
preferred: Preferred {
    kex: Cow::Borrowed(&[kex::CURVE25519, kex::ECDH_SHA2_NISTP256]),
    key: Cow::Borrowed(&[key::ED25519, key::ECDSA_SHA2_NISTP256, key::RSA_SHA2_256]),
    cipher: Cow::Borrowed(&[cipher::CHACHA20_POLY1305, cipher::AES_256_GCM]),
    mac: Cow::Borrowed(&[mac::HMAC_SHA2_256_ETM, mac::HMAC_SHA2_256]),
    compression: Cow::Borrowed(&[compression::ZLIB, compression::NONE]),
},
limits: Limits::new(1 << 30, 1 << 30, Duration::from_secs(3600)),
```
