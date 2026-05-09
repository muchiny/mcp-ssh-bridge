# context7 query targets (pinned 2026-05-09)

Selected because each is a direct dependency on a security-critical path
(SSH, TLS, JWT, K8s creds, secrets-in-RAM, HTTP transport). Order = priority.

| # | Crate          | Why audit-relevant                                  | Resolved libraryId                  |
|---|----------------|-----------------------------------------------------|--------------------------------------|
| 1 | russh          | SSH client core — host-key policy, KEX, ciphers    | `/eugeny/russh`                      |
| 2 | russh-keys     | PEM/key parsing — historical CVE surface           | `/eugeny/russh` (monorepo)           |
| 3 | rustls         | TLS for HTTP transport + AWS — CRL/cert handling   | `/websites/rs_rustls_rustls`         |
| 4 | jsonwebtoken   | JWT validation — algorithm-confusion class         | `/keats/jsonwebtoken`                |
| 5 | axum           | HTTP transport defaults — request limits, headers  | `/tokio-rs/axum`                     |
| 6 | tokio          | Task isolation, blocking-call detection            | `/websites/rs_tokio`                 |
| 7 | zeroize        | Drop guarantees, current derive feature set        | `/rustcrypto/utils` (monorepo home)  |
| 8 | secrecy        | Wrapper API, expose/peek lifetimes                 | `/websites/rs_secrecy_secrecy`       |
| 9 | kube           | kubeconfig parsing, token refresh, exec auth       | `/kube-rs/kube`                      |
| 10| serde-saphyr   | YAML loader actually used by `mcp-ssh-bridge` (panic-free, deny-unknown by default) — substituted for `serde_yaml` (unmaintained) per project's `src/config/`. | `/bourumir-wyngs/serde-saphyr` |
