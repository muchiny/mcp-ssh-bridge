# rustls — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/websites/rs_rustls_rustls`
- Topic: `ClientConfig builder root store webpki CRL revocation cipher suite defaults dangerous certificate verifier`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`ClientConfig::builder()` uses safe defaults** for ciphersuites and protocol versions out of the box (TLS 1.2 + 1.3, modern AEAD ciphers). Do not override unless required.
2. **CRL handling lives on `WebPkiServerVerifier::builder_with_provider(...).with_crls(...)`**. The plain `.with_root_certificates(root_store)` path does **NOT** check revocation. To enable CRL checks for SERVER certs (our likely use case for HTTP-out / AWS / OAuth), the build chain must be:
   ```rust
   .with_webpki_verifier(
     WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
       .with_crls(crls)
       .build()?
   )
   ```
3. **CRL builder methods carry security implications:**
   - `only_check_end_entity_revocation()` — RELAXES default (default checks every cert in chain except trust anchor). Only use if intermediate CRLs are unavailable.
   - `allow_unknown_revocation_status()` — RELAXES default (default treats unknown status as error). Avoid in security-critical paths.
   - `enforce_revocation_expiration()` — STRENGTHENS default (default does NOT treat expired CRLs as error). Recommend enabling when feasible.
4. **Dangerous APIs** (`dangerous().set_certificate_verifier(...)`) bypass all built-in verification. Should never be used in production code; greppable as a smell.
5. **Recent CRL-handling advisories** apply to `rustls-webpki` and are already in our `deny.toml` ignore list (RUSTSEC-2026-0098/0099/0104) per the project's branch state — these are transitive via aws-sdk and the project tracks them.

## Audit checklist for `mcp-ssh-bridge`

- [ ] grep for `ClientConfig::builder` / `with_webpki_verifier` / `with_root_certificates` in `src/` to inventory TLS config sites (HTTP transport, AWS adapter, OAuth, kube).
- [ ] grep for `dangerous(` and `set_certificate_verifier` — must be zero matches (or feature-gated test-only).
- [ ] If any TLS chain calls `with_crls`, also confirm `enforce_revocation_expiration()` is on.
- [ ] Check our HTTP / OAuth / AWS init code: are we explicitly providing a `CryptoProvider`, or relying on the implicit default (which can panic if multiple providers are linked)?

## Raw response excerpt

```rust
let client_verifier = WebPkiClientVerifier::builder(roots.into())
    .with_crls(crls)
    .build()
    .unwrap();
```

```diff
- .with_root_certificates(root_store)
+ .with_webpki_verifier(
+   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
+   .with_crls(...)
+   .build()?
+ )
```
