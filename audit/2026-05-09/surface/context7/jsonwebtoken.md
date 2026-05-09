# jsonwebtoken — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/keats/jsonwebtoken`
- Topic: `Validation set_required_spec_claims algorithms decode header confusion expiration leeway aud iss verification pitfalls`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`Validation::new(algorithm)` PINS the expected algorithm.** Do not pass a `Vec<Algorithm>` of mixed kinds (HS / RS / EdDSA) — that re-opens the alg-confusion class. The `decode` function will reject any token whose header `alg` differs from what `Validation` was constructed with.
2. **Default `Validation` only validates `exp` (with 60-second leeway).** It does NOT enforce `aud`, `iss`, `sub`, `nbf`. A safe baseline must call:
   - `validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"])`
   - `validation.set_issuer(&["…"])`
   - `validation.set_audience(&["…"])`
   - `validation.validate_nbf = true`
3. **`reject_tokens_expiring_in_less_than: u64`** is a useful extra knob — rejects tokens that would expire mid-flight. Recommended for short-lived API tokens.
4. **`leeway`** defaults to 60s. Tighten to 30s or less for high-security paths if clock sync is reliable.
5. **`DecodingKey::from_secret(...)`** for HS algorithms takes raw bytes — the secret should be wrapped in `Zeroizing` until the call site.

## Audit checklist for `mcp-ssh-bridge`

- [ ] `src/mcp/transport/oauth.rs`, `src/mcp/transport/jwt*.rs` (if exist), or any `decode::<...>` call: confirm `Validation` is constructed with a single explicit `Algorithm` and that `set_required_spec_claims`, `set_issuer`, `set_audience` are all called on the validator.
- [ ] Confirm `validate_nbf = true` is set if the upstream issuer ever ships nbf claims.
- [ ] Confirm the secret (HS) or private key (RS/ES/EdDSA) loaded for signing/verifying is held in `Zeroizing` / `secrecy::Secret`.
- [ ] grep for `Validation::default()` — that's the no-issuer-no-audience baseline; flag any production use.

## Raw response excerpt

```rust
let mut validation = Validation::new(Algorithm::HS256);
validation.leeway = 30;
validation.reject_tokens_expiring_in_less_than = 60;
validation.validate_nbf = true;
validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
validation.set_issuer(&["https://auth.example.com"]);
validation.set_audience(&["https://api.example.com"]);
validation.sub = Some("alice@example.com".to_string());
```
