# zeroize — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/rustcrypto/utils` (the `zeroize` crate lives in this monorepo)
- Topic: `derive zeroize on drop wrapper Zeroizing best practice Drop guarantees compiler optimization safety serde feature`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **Three idiomatic usage patterns:**
   - `secret.zeroize()` — manual, explicit zeroing.
   - `let secret = Zeroizing::new([0u8; 32]);` — wrapper that zeroes on drop, no derive needed.
   - `#[derive(Zeroize, ZeroizeOnDrop)]` on a struct (requires `zeroize_derive` feature, enabled in the project's `Cargo.toml` as `zeroize = { version = "1", features = ["serde"] }` — note: project includes `serde` feature but verify whether `zeroize_derive` is active).
2. **`#[zeroize(skip)]`** on individual fields lets you opt out per-field (e.g. a public id you don't want to wipe).
3. **`zeroize` uses Rust intrinsics that the compiler is contractually forbidden from optimizing away.** `#[derive(Zeroize)]` walks all owned fields. Borrowed references (`&[u8]`) cannot be zeroized — caller must own the data.
4. **`ZeroizeOnDrop` requires `Zeroize`** to also be derived/implemented. Both deriving `Drop` and `ZeroizeOnDrop` is a compile-time conflict.
5. **`String` zeroize** zeros the underlying bytes but does NOT shrink capacity — the `len` is set to 0, the alloc'd memory stays mapped (and zeroed) until drop.

## Audit checklist for `mcp-ssh-bridge`

- [ ] Inspect `Cargo.toml` `[dependencies] zeroize = ...` — does the feature list include `derive` (or `zeroize_derive`)? Without it, `#[derive(Zeroize, ZeroizeOnDrop)]` won't compile.
- [ ] grep for `#[derive(.*Zeroize.*)]` in `src/` — every credential-bearing struct (`SshAuth`, `KubeConfig`, `VaultToken`, OAuth secrets, JWT signing keys) should be on this list.
- [ ] grep for `Zeroizing::new(` in `src/` — verify any password/key buffer that's passed by value through ≥1 function is wrapped at the entry point.
- [ ] Verify no struct uses `#[zeroize(skip)]` on a field that actually contains secret material.
- [ ] Verify zeroize-able data isn't being cloned into long-lived caches (e.g. memoized `String` of a token).

## Raw response excerpt

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
struct Credentials {
    username: String,
    password: Vec<u8>,
    api_key: [u8; 32],
}

#[derive(Zeroize)]
struct PartialSecret {
    #[zeroize(skip)]
    public_id: u64,        // Not zeroized
    secret_key: [u8; 32],  // Will be zeroized
}

let secret = Zeroizing::new([0u8; 32]);
```
