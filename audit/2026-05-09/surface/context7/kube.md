# kube — upstream guidance (context7)

- Query date: 2026-05-09
- libraryId: `/kube-rs/kube`
- Topic: `Config kubeconfig auth provider token refresh exec plugin client_certificate_data bearer_token Kubernetes credential handling`
- context7 server: Upstash `@upstash/context7-mcp@latest`

## Key takeaways

1. **`Client::try_default()` auto-detects** — tries in-cluster config first, then `~/.kube/config`. **In our context (`mcp-ssh-bridge`)** this means an MCP client running on a remote host could surreptitiously inherit the bridge host's k8s context if our code calls `try_default()` without an explicit override.
2. **kubeconfig auth modes carry risk:**
   - `client-certificate-data` / `client-key-data`: PEM bytes — must be wrapped in `Zeroizing` from parse to drop.
   - `bearer_token`: long-lived static token — must be `SecretString` / `SecretBox`.
   - `auth-provider` (oidc, gcp, azure, exec): invokes external commands — `exec` plugin in particular runs an arbitrary process per request. Auditing required: do we honor `exec` blobs from untrusted kubeconfigs?
3. **Token refresh** for OIDC / OAuth providers: kube-rs caches the refreshed token internally. Confirm: when does the cached token get zeroed — on Client drop only, or also on refresh-replace?
4. **`pods.exec(...)` runs a remote command** — equivalent risk class to `ssh_exec`. Inputs (the `vec!["sh", "-c", ...]` argv) must go through the same SecurityValidator path as our other shell-execution surfaces.
5. **`AttachParams::default().stdin(true)`** opens an interactive stream. Sessions left open leak resources and can keep a remote shell active across MCP session boundaries — the per-session lifecycle pattern from Vuln 8/9 should apply here too.

## Audit checklist for `mcp-ssh-bridge`

- [ ] grep for `Client::try_default(` — every call should be either documented as "intentionally inherit host kubeconfig" OR replaced with `Config::from_*` that takes an explicit path.
- [ ] grep for `pods.exec\(` and any `AttachParams::default().stdin(true)` — these need the same validator pipeline as `ssh_exec`.
- [ ] In the kube auth path: confirm bearer_token / client_key_data / client_certificate_data are held in `SecretBox` or `Zeroizing`.
- [ ] If we accept user-supplied kubeconfigs (e.g. via tool params), reject any with an `exec` auth-provider OR add an explicit allowlist of permitted exec command basenames.
- [ ] Audit `AttachedProcess` lifecycle: is there a per-session map that closes attached processes on session shutdown?

## Raw response excerpt

```rust
let client = Client::try_default().await?;  // in-cluster first, then ~/.kube/config

let mut attached = pods.exec(
    "my-pod",
    vec!["sh", "-c", "echo hello; date"],
    &AttachParams::default().stderr(false),
).await?;
```
