# secrecy — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/websites/rs_secrecy_secrecy`
- Topic: `SecretBox ExposeSecret expose_secret SecretString serde feature integration zeroize lifetime debug display`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`SecretBox<S>` is the modern wrapper.** Older `Secret<S>` is deprecated in 0.10. The inner type must implement `Zeroize`.
2. **Access is gated by `ExposeSecret::expose_secret(&self) -> &S`** — the only way to read the inner. Greppable: every read must go through `expose_secret()` or `expose_secret_mut()`. Avoid `.as_ref()` shortcuts.
3. **`Debug` impl never shows the secret** — it just prints the wrapper type. This means `tracing::debug!(?secret)` is safe; `tracing::debug!(secret = ?secret.expose_secret())` is NOT.
4. **`Serialize` is NOT auto-derived** — by design, to prevent accidental exfiltration via serde. Implementing the marker trait `SerializableSecret` opts in. Audit any `impl SerializableSecret for ...`.
5. **`Deserialize` IS auto-derived** behind the `serde` feature, BUT the warning in upstream docs verbatim: *"be careful to clean up any intermediate secrets when doing this, e.g. the unparsed input!"* — meaning the input string passed to the deserializer remains in memory unless the caller wipes it.
6. **Inner type must be `Zeroize + Default` to use `SecretBox::default()`.** Practical implication: wrap `Box<S>` not `S` directly when the type doesn't have a sensible default.

## Audit checklist for `mcp-ssh-bridge`

- [ ] grep `Secret(Box|String|Vec)?\s*<` to inventory every secrecy use site.
- [ ] grep `impl\s+SerializableSecret` — any match must be justified in a comment because it deliberately opens an exfiltration path.
- [ ] grep `expose_secret\b` — confirm each call is in a controlled scope (e.g. one local binding, used immediately, not propagated into logs).
- [ ] When a `SecretBox<...>` is deserialized from YAML/JSON config, verify the source buffer (the raw config bytes) is itself wrapped in `Zeroizing` — otherwise the secret remains in the unparsed source.
- [ ] Any `Debug` formatter on a struct that *contains* `SecretBox<...>` must NOT call `.expose_secret()`.

## Raw response excerpt

```
To prevent exfiltration of secret values via serde, by default
SecretBox<T> does NOT receive a corresponding Serialize impl.
If you would like types of SecretBox<T> to be serializable with serde,
you will need to impl the SerializableSecret marker trait on T.
```

```rust
impl<S: Zeroize + ?Sized> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&self) -> &S
}
impl<S: Zeroize + ?Sized> ZeroizeOnDrop for SecretBox<S>
```
