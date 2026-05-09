# russh-keys — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/eugeny/russh` (russh-keys is part of the russh monorepo)
- Topic: `private key parsing PEM OpenSSH format encrypted decode_secret_key load_secret_key security`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`load_secret_key(path, passphrase)`** is the canonical entry point. It handles OpenSSH and PKCS8 formats. For encrypted keys the second arg is `Some(passphrase)`.
2. **Passphrase parameter is `Option<&str>`** in the upstream example — meaning the secret enters the function as a borrowed string slice. Whatever owns that buffer must be wrapped in `Zeroizing` BEFORE the call (otherwise it sits in the caller's frame indefinitely).
3. **`load_openssh_certificate`** parses certs separately. Cert key id (`cert.key_id()`) is logged in the example — make sure we don't propagate cert id into audit logs without redaction context.
4. **SSH agent integration** — the `AgentClient` API supports `add_identity(&key, &[Constraint::KeyLifetime{seconds: 3600}])`. If we use the agent, we should set lifetime constraints to bound key residency.
5. **Public-key parsing from base64** uses `parse_public_key_base64`. Untrusted base64 from a remote source must be size-bounded by the caller (`russh-keys` itself does not appear to enforce a max length on this path).

## Audit checklist for `mcp-ssh-bridge`

- [ ] `src/ssh/auth.rs` / `src/ssh/client.rs`: when calling `load_secret_key(path, Some(passphrase))`, the passphrase variable must be wrapped in `Zeroizing` or `secrecy::Secret` before being passed.
- [ ] `src/ssh/auth.rs`: confirm we never log the path, fingerprint, or cert key id outside an audit-redacted context.
- [ ] If we use ssh-agent (search for `AgentClient`), confirm `KeyLifetime` is set.
- [ ] If we accept user-supplied base64 public-key strings (e.g. for fingerprint pinning), enforce a max length before parsing.

## Raw response excerpt

```rust
// Load a private key from file (supports OpenSSH, PKCS8 formats)
let key = load_secret_key("/path/to/id_ed25519", None)?;

// Load an encrypted private key
let encrypted_key = load_secret_key("/path/to/id_rsa", Some("passphrase"))?;

// Get key fingerprint
let fingerprint = pubkey.fingerprint(ssh_key::HashAlg::Sha256);
```

```rust
client.add_identity(&key, &[
    agent::Constraint::KeyLifetime { seconds: 3600 },
]).await?;
```
