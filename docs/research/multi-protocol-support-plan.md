# Plan: Multi-Protocol Support for MCP SSH Bridge

## Context

Le projet MCP SSH Bridge est actuellement limité à SSH comme unique protocole de communication. Pour gérer des environnements hétérogènes (Windows sans SSH, instances cloud, flottes IoT, infrastructures cloud-native), il faut supporter plusieurs protocoles. L'architecture hexagonale existante rend cette extension naturelle — le domaine est déjà protocol-agnostic.

## Recherche : Protocoles identifiés (10 protocoles, 3 tiers)

### Tier 1 — Haute priorité (très utilisés, crates Rust matures)

| Protocole | Usage | Crate Rust | Auth |
|-----------|-------|------------|------|
| **SSH** (existant) | Linux/Unix, cross-platform | `russh` | Key, Agent, Interactive |
| **WinRM** | Windows fleet automation (port 5985/5986) | `librust-winrm`, `rust-winrm-client` | NTLM, Kerberos |
| **AWS SSM** | Exécution cloud sans SSH via SendCommand API | `aws-sdk-ssm` (v1.107, GA) | IAM roles, profiles |
| **Azure Run Command** | Exécution sur VMs Azure | `azure_core` (beta) | Service Principal, Managed Identity |
| **GCP OS Command** | Exécution sur VMs GCP | `gcloud-sdk` (v1.0, GA) | Service Account |
| **gRPC** | APIs cloud-native, gNMI réseau | `tonic` + `prost` | mTLS, tokens |

### Tier 2 — Priorité moyenne (scénarios spécifiques, très utilisés dans l'industrie)

| Protocole | Usage | Crate Rust | Modèle |
|-----------|-------|------------|--------|
| **ZeroMQ** | Fleet-scale push execution (modèle SaltStack, LinkedIn 100k+ hosts) | `zeromq` | Pub/Sub, Push/Pull |
| **NATS** | Cloud-native messaging, event-driven execution | `async-nats` | Pub/Sub, Request-Reply |
| **Kubernetes Exec** | Exécution directe dans containers K8s | `kube` + `k8s-openapi` | ServiceAccount, kubeconfig |

### Tier 3 — Spécialisé

| Protocole | Usage | Crate Rust |
|-----------|-------|------------|
| **MQTT** | IoT/Edge devices (AWS IoT, Azure IoT Hub) | `rumqttc` |
| **Tailscale/WireGuard** | Overlay réseau (traverse NAT/firewall) | `tailscale-api` / REST |

## Architecture d'implémentation

### Phase 1 : Abstraction générique (non-breaking)

**1.1 — Nouveau trait `RemoteExecutor`** (`src/ports/executor.rs`)

```rust
#[async_trait]
pub trait RemoteExecutor: Send + Sync {
    async fn execute(&self, host: &str, command: &str, timeout: Duration) -> Result<CommandOutput>;
    async fn upload(&self, host: &str, local: &Path, remote: &Path) -> Result<()>;
    async fn download(&self, host: &str, remote: &Path, local: &Path) -> Result<()>;
    async fn is_reachable(&self, host: &str) -> bool;
    fn protocol_name(&self) -> &'static str;
    fn supports_file_transfer(&self) -> bool;
    fn supports_interactive(&self) -> bool { false }
}
```

**1.2 — `ExecutorRouter`** (`src/ports/executor_router.rs`) — Dispatcher par host

```rust
pub struct ExecutorRouter {
    config: Arc<Config>,
    ssh_pool: Arc<ConnectionPool>,
    #[cfg(feature = "winrm")] winrm_pool: Arc<WinRmPool>,
    #[cfg(feature = "ssm")] ssm_client: Arc<SsmExecutor>,
    #[cfg(feature = "grpc")] grpc_pool: Arc<GrpcPool>,
    // ...
}
```

Implémente `RemoteExecutor` en dispatchant selon `host.protocol` dans la config.

**1.3 — Config : Protocol enum + TransportConfig**  (`src/config/types.rs`)

```rust
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default] Ssh,
    #[cfg(feature = "winrm")] WinRm,
    #[cfg(feature = "ssm")] Ssm,
    #[cfg(feature = "grpc")] Grpc,
    #[cfg(feature = "zeromq")] ZeroMq,
    #[cfg(feature = "nats")] Nats,
    #[cfg(feature = "k8s-exec")] Kubernetes,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    Ssh(SshTransportConfig),
    WinRm(WinRmTransportConfig),
    Ssm(SsmTransportConfig),
    Grpc(GrpcTransportConfig),
}
```

**Rétrocompatibilité** : Custom deserializer qui accepte l'ancien format plat YAML (sans `protocol:` ni `transport:`) et le mappe automatiquement vers `TransportConfig::Ssh`.

**1.4 — Migration `ToolContext`** (`src/ports/tools.rs`)

Ajouter `executor: Arc<dyn RemoteExecutor>` aux côtés de `connection_pool`. Migrer progressivement les tool handlers de :
```rust
let mut conn = ctx.connection_pool.get_connection_with_jump(...).await?;
let output = conn.exec(&command, &limits).await?;
```
vers :
```rust
let output = ctx.executor.execute(&args.host, &command, timeout).await?;
```

### Phase 2 : Adapters WinRM + SSM (feature-gated)

**2.1 — WinRM Adapter** (`src/winrm/`)
- `client.rs` : HTTP/HTTPS + SOAP/WSMAN via `reqwest` + `quick-xml`
- `executor.rs` : Implémente `RemoteExecutor`
- `pool.rs` : Pool de sessions WinRM
- Auth : NTLM (`reqwest`), Kerberos
- Feature : `winrm = ["dep:reqwest", "dep:quick-xml"]`

**2.2 — SSM Adapter** (`src/ssm/`)
- `executor.rs` : `SendCommand` + polling `GetCommandInvocation` via `aws-sdk-ssm`
- `waiter.rs` : Polling async avec timeout
- Auth : AWS credential chain standard
- Feature : `ssm = ["dep:aws-sdk-ssm", "dep:aws-config"]`

**2.3 — Cloud Adapters** (`src/cloud_exec/`)
- Azure Run Command via REST API
- GCP via `gcloud-sdk`

### Phase 3 : Deprecation accès pool direct

- Marquer `connection_pool` sur `ToolContext` comme `#[deprecated]`
- Migrer tous les handlers restants
- Supprimer une fois la migration complète

### Phase 4 : Protocols Tier 2/3

- gRPC adapter (`src/grpc_exec/`) avec `tonic` — nécessite un agent distant
- ZeroMQ adapter (`src/zmq_exec/`) — modèle pub/sub pour fleet-scale
- NATS adapter (`src/nats_exec/`) — event-driven
- K8s Exec adapter (`src/k8s_exec/`) via `kube` crate — direct pod exec
- MQTT adapter (`src/mqtt_exec/`) — IoT/edge

## Feature Flags (`Cargo.toml`)

```toml
[features]
default = ["cli"]
winrm = ["dep:reqwest", "dep:quick-xml"]
ssm = ["dep:aws-sdk-ssm", "dep:aws-config"]
grpc = ["dep:tonic", "dep:prost"]
zeromq = ["dep:zeromq"]
nats = ["dep:async-nats"]
k8s-exec = ["dep:kube", "dep:k8s-openapi"]
mqtt = ["dep:rumqttc"]
cloud = ["ssm"]
all-protocols = ["winrm", "ssm", "grpc", "zeromq", "nats", "k8s-exec", "mqtt"]
```

## Exemple YAML Multi-Protocol

```yaml
hosts:
  # SSH classique (inchangé, rétrocompatible)
  linux-prod:
    hostname: 192.168.1.100
    port: 22
    user: admin
    auth: { type: key, path: ~/.ssh/id_ed25519 }

  # Windows via WinRM
  windows-dc:
    hostname: 192.168.1.200
    user: Administrator
    os_type: windows
    protocol: winrm
    transport:
      type: winrm
      port: 5986
      use_ssl: true
      auth: { type: ntlm, password_env: WIN_PASSWORD }

  # AWS EC2 via SSM (pas besoin de port/SSH)
  aws-web-prod:
    hostname: i-0abc123def456
    user: ssm-user
    protocol: ssm
    transport:
      type: ssm
      region: us-east-1
      document: AWS-RunShellScript

  # Kubernetes pod direct
  k8s-api-pod:
    hostname: api-deployment-xyz
    protocol: kubernetes
    transport:
      type: kubernetes
      namespace: production
      container: api
      kubeconfig: ~/.kube/config
```

## Fichiers critiques à modifier

| Fichier | Changement |
|---------|------------|
| `src/ports/executor.rs` | **Nouveau** — Trait `RemoteExecutor` |
| `src/ports/executor_router.rs` | **Nouveau** — `ExecutorRouter` dispatcher |
| `src/ports/mod.rs` | Exporter les nouveaux modules |
| `src/ports/tools.rs` | Ajouter `executor` à `ToolContext` |
| `src/config/types.rs` | `Protocol` enum, `TransportConfig`, rétrocompat deser |
| `src/mcp/server.rs` | Construire `ExecutorRouter` au lieu du bare `ConnectionPool` |
| `src/ssh/executor_adapter.rs` | **Nouveau** — Wrapper SSH implémentant `RemoteExecutor` |
| `src/winrm/` | **Nouveau module** — WinRM adapter |
| `src/ssm/` | **Nouveau module** — SSM adapter |
| `src/grpc_exec/` | **Nouveau module** — gRPC adapter |
| `Cargo.toml` | Features flags + dépendances conditionnelles |

## Vérification

1. `make test` — Les 5800+ tests existants passent (aucun changement de comportement SSH)
2. Charger un ancien `config.yaml` sans `protocol:` → confirmer parsing en `TransportConfig::Ssh`
3. Charger un config multi-protocol → confirmer dispatch correct
4. Pour chaque adapter : test unitaire avec mock, test d'intégration feature-gated
5. `make lint` — Clippy clean
6. `make ci` — CI complet

## Sources

- [WinRM - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
- [gRPC](https://grpc.io/)
- [aws-sdk-ssm crate](https://crates.io/crates/aws-sdk-ssm)
- [Azure SDK for Rust](https://azure.github.io/azure-sdk/releases/2025-09/rust.html)
- [gcloud-sdk crate](https://crates.io/crates/gcloud-sdk)
- [librust-winrm](https://github.com/oktay454/librust-winrm)
- [MCP Transport Future](https://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/)
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [SaltStack ZeroMQ Transport](https://docs.saltproject.io/en/latest/topics/transports/zeromq.html)
- [LinkedIn Salt Scaling](https://www.linkedin.com/blog/engineering/infrastructure/scaling-salt-for-remote-execution-to-support-linkedin-infra-grow)
- [MITRE ATT&CK T1651 - Cloud Administration Command](https://attack.mitre.org/techniques/T1651/)
- [AWS SSM Agent](https://github.com/aws/amazon-ssm-agent)
- [PowerShell PyPSRP](https://johal.in/powershell-pypsrp-remote-windows-automation-scripts-2026/)
