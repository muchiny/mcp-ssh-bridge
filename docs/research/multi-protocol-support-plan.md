# Plan: Multi-Protocol Support for MCP SSH Bridge (Mise à jour complète)

## Context

Le projet MCP SSH Bridge est actuellement limité à SSH comme unique protocole d'exécution distante. Pour gérer des environnements hétérogènes (Windows sans SSH, équipements réseau legacy, infrastructures cloud-native, matériel air-gapped), il faut supporter plusieurs protocoles. L'architecture hexagonale existante rend cette extension naturelle — le domaine est déjà protocol-agnostic via le trait `SshExecutor`.

**Mise à jour** : Après recherche approfondie, le tiering original contenait des erreurs de catégorisation. Ce plan corrigé distingue clairement les **protocoles d'exécution** des **couches réseau** et des **bus de messaging**.

## Recherche : Protocoles identifiés (14 protocoles, 4 catégories)

### Tier 1 — Haute priorité (exécution distante native, crates Rust matures, air-gapped compatible)

| Protocole | Usage | Crate Rust | Auth | Port |
|-----------|-------|------------|------|------|
| **SSH** (existant) | Linux/Unix, cross-platform | `russh` 0.57 | Key, Agent, Password | 22 |
| **WinRM** | Windows fleet automation (SOAP/WS-Man) | `librust-winrm` | NTLM, Kerberos, CredSSP | 5985/5986 |
| **Telnet** | **NOUVEAU** — Équipements réseau legacy (Cisco IOS ancien, switches, PLCs) | `mini-telnet` (async/tokio) | Login/password prompt | 23 |
| **NETCONF/YANG** | **NOUVEAU** — Config réseau moderne RFC 6241 (Juniper, Cisco IOS XE) | `netconf-rs` | Via SSH (RFC 6242) | 830 |
| **gRPC** | APIs cloud-native, gNMI réseau, microservices | `tonic` + `prost` | mTLS, tokens | custom |

### Tier 2 — Priorité moyenne (contextes spécifiques mais importants)

| Protocole | Usage | Crate Rust | Modèle | Air-gapped |
|-----------|-------|------------|--------|------------|
| **Kubernetes Exec** | Exécution directe dans containers K8s | `kube` + `k8s-openapi` | WebSocket exec | ✅ (cluster local) |
| **Serial/Console** | **NOUVEAU** — BMC, PDU, IPMI, accès out-of-band physique | `serial2-tokio` | AsyncRead/Write | ✅ (local) |
| **SNMP** | **NOUVEAU** — Monitoring réseau (GET/SET, pas d'exécution) | `csnmp`, `snmp2` | UDP req/resp | ✅ |

### Tier 3 — Cloud-only (nécessite connectivité cloud, NON air-gapped)

> **Note** : Ces protocoles sont utiles pour les déploiements cloud mais **incompatibles avec les environnements air-gapped** — le use case principal du projet.

| Protocole | Usage | Crate Rust | Limitation |
|-----------|-------|------------|------------|
| **AWS SSM** | SendCommand sur EC2 sans SSH | `aws-sdk-ssm` | Requiert accès API AWS |
| **Azure Run Command** | Exécution sur VMs Azure | `azure_core` (beta) | Requiert accès API Azure |
| **GCP OS Command** | Exécution sur VMs GCP | `gcloud-sdk` | Requiert accès API GCP |

### Tier 4 — Messaging (nécessite agent custom distant, PAS des protocoles d'exécution natifs)

> **Note** : Ces technologies sont des **bus de messaging**, pas des protocoles d'exécution de commandes. Leur utilisation pour l'exécution distante nécessite un agent custom des deux côtés (modèle SaltStack pour ZeroMQ).

| Protocole | Usage réel | Crate Rust | Pourquoi pas Tier 1/2 |
|-----------|-----------|------------|----------------------|
| **ZeroMQ** | Fleet-scale push (modèle SaltStack) | `zeromq`, `rzmq` | Requiert agent custom distant |
| **NATS** | Event-driven messaging | `async-nats` | Pub/sub, pas RPC natif |
| **MQTT** | IoT/Edge telemetry | `rumqttc` | Pub/sub, pas d'exécution |

### Retiré du plan

| Protocole | Raison du retrait |
|-----------|-------------------|
| **Tailscale/WireGuard** | **Couche réseau/tunnel VPN**, pas un protocole d'exécution. SSH ou WinRM nécessaire par-dessus. Peut être utilisé comme transport réseau transparent. |

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
    fn supports_structured_config(&self) -> bool { false } // NETCONF, SNMP
}
```

**1.2 — `ExecutorRouter`** (`src/ports/executor_router.rs`) — Dispatcher par host

```rust
pub struct ExecutorRouter {
    config: Arc<Config>,
    ssh_pool: Arc<ConnectionPool>,
    #[cfg(feature = "winrm")] winrm_pool: Arc<WinRmPool>,
    #[cfg(feature = "telnet")] telnet_pool: Arc<TelnetPool>,
    #[cfg(feature = "netconf")] netconf_pool: Arc<NetconfPool>,
    #[cfg(feature = "ssm")] ssm_client: Arc<SsmExecutor>,
    #[cfg(feature = "grpc")] grpc_pool: Arc<GrpcPool>,
    #[cfg(feature = "serial")] serial_mgr: Arc<SerialManager>,
}
```

Implémente `RemoteExecutor` en dispatchant selon `host.protocol` dans la config.

**1.3 — Config : Protocol enum + TransportConfig** (`src/config/types.rs`)

```rust
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default] Ssh,
    #[cfg(feature = "winrm")] WinRm,
    #[cfg(feature = "telnet")] Telnet,
    #[cfg(feature = "netconf")] Netconf,
    #[cfg(feature = "grpc")] Grpc,
    #[cfg(feature = "ssm")] Ssm,
    #[cfg(feature = "k8s-exec")] Kubernetes,
    #[cfg(feature = "serial")] Serial,
    #[cfg(feature = "zeromq")] ZeroMq,
    #[cfg(feature = "nats")] Nats,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    Ssh(SshTransportConfig),
    WinRm(WinRmTransportConfig),
    Telnet(TelnetTransportConfig),   // NEW
    Netconf(NetconfTransportConfig), // NEW
    Serial(SerialTransportConfig),   // NEW
    Ssm(SsmTransportConfig),
    Grpc(GrpcTransportConfig),
}
```

**Rétrocompatibilité** : Custom deserializer qui accepte l'ancien format plat YAML (sans `protocol:` ni `transport:`) et le mappe automatiquement vers `TransportConfig::Ssh`.

**1.4 — Cut-over `ToolContext`** (`src/ports/tools.rs`)

`ExecutorRouter` implémente le trait `SshExecutor` existant. On remplace `connection_pool` par `ExecutorRouter` dans `ToolContext` **en une seule fois**. Aucun tool handler ne change — ils appellent toujours la même interface `SshExecutor`, le router dispatch vers SSH, WinRM, Telnet, etc. selon le `protocol` du host configuré.

```rust
// Avant (dans ToolContext)
pub connection_pool: Arc<ConnectionPool>,

// Après (dans ToolContext) — même trait, implémentation différente
pub executor: Arc<dyn SshExecutor>,  // ExecutorRouter implémente SshExecutor
```

**Pas de migration progressive** — l'architecture hexagonale garantit que les 337 handlers existants fonctionnent sans modification car ils dépendent du port (trait), pas de l'adapter.

### Phase 2 : Adapters Tier 1 (air-gapped, feature-gated)

**2.1 — WinRM Adapter** (`src/winrm/`)
- `client.rs` : HTTP/HTTPS + SOAP/WSMAN via `reqwest` + `quick-xml`
- `executor.rs` : Implémente `RemoteExecutor`
- `pool.rs` : Pool de sessions WinRM
- Auth : NTLM, Kerberos, CredSSP
- Feature : `winrm = ["dep:reqwest", "dep:quick-xml"]`

**2.2 — Telnet Adapter** (`src/telnet/`) — **NOUVEAU**
- `client.rs` : Connexion TCP + négociation Telnet via `mini-telnet` ou raw tokio `TcpStream`
- `executor.rs` : Implémente `RemoteExecutor`
- `pool.rs` : Pool de connexions Telnet avec keep-alive
- `prompt.rs` : Détection de prompt (regex configurable pour Cisco `#`, Juniper `>`, etc.)
- Auth : Login/password via prompt interactif
- Feature : `telnet = ["dep:mini-telnet"]`
- Intégration directe avec les outils `network_equipment` existants

**2.3 — NETCONF Adapter** (`src/netconf/`) — **NOUVEAU**
- `client.rs` : NETCONF over SSH (RFC 6242) via `netconf-rs`
- `executor.rs` : Implémente `RemoteExecutor` avec `supports_structured_config() -> true`
- Opérations : `get-config`, `edit-config`, `lock`, `unlock`, `commit`
- Feature : `netconf = ["dep:netconf-rs"]`
- Nouveau groupe d'outils : `netconf` (get-config, edit-config, validate, commit)

**2.4 — gRPC Adapter** (`src/grpc_exec/`)
- `client.rs` : gRPC client via `tonic`
- `executor.rs` : Implémente `RemoteExecutor`
- Proto definition pour remote exec service
- Feature : `grpc = ["dep:tonic", "dep:prost"]`

### Phase 3 : Adapters Tier 2

**3.1 — Kubernetes Exec Adapter** (`src/k8s_exec/`)
- Via `kube` crate — WebSocket exec dans pods
- Feature : `k8s-exec = ["dep:kube", "dep:k8s-openapi"]`

**3.2 — Serial/Console Adapter** (`src/serial/`) — **NOUVEAU**
- `client.rs` : Serial port I/O via `serial2-tokio`
- `executor.rs` : Implémente `RemoteExecutor`
- `prompt.rs` : Détection de prompt (partagé avec Telnet)
- Feature : `serial = ["dep:serial2-tokio"]`
- Use cases : BMC console, PDU management, IPMI serial-over-LAN

**3.3 — SNMP Adapter** (`src/snmp/`) — **NOUVEAU**
- `client.rs` : SNMP v2c/v3 via `csnmp`
- **Ne implémente PAS `RemoteExecutor`** — pas d'exécution de commandes
- Nouveau trait : `MonitoringProvider` pour GET/SET/WALK
- Nouveau groupe d'outils : `snmp` (get, walk, set, table)
- Feature : `snmp = ["dep:csnmp"]`

### Phase 4 : Cloud Adapters (feature-gated, opt-in) ✅ DONE

**4.1 — AWS SSM Adapter** (`src/ssm/mod.rs`)
- Uses `aws-sdk-ssm` + `aws-config` crates
- `SendCommand` → poll `GetCommandInvocation` pattern
- Auto-detects document: `AWS-RunShellScript` (Linux) / `AWS-RunPowerShellScript` (Windows)
- Host mapping: `hostname` → instance ID, `user` → region, `description` → document
- Feature: `ssm = ["dep:aws-sdk-ssm", "dep:aws-config"]`

**4.2 — Azure Run Command Adapter** (`src/cloud_exec/azure.rs`)
- Uses `reqwest` for Azure Compute Management REST API
- Supports sync (200) and async (202 + Location polling) responses
- Auth via Azure CLI (`az account get-access-token`) or `AZURE_ACCESS_TOKEN` env var
- Host mapping: `hostname` → VM name, `user` → resource group, `description` → subscription ID
- Feature: `azure = ["dep:reqwest"]` (shares reqwest with WinRM)

**4.3 — GCP OS Command Adapter** (`src/cloud_exec/gcp.rs`)
- Wraps `gcloud compute ssh --command` CLI (no direct Run Command API in GCP)
- Uses IAP tunneling for secure access
- Auto-detects project/zone from `gcloud config` if not specified
- Host mapping: `hostname` → instance name, `user` → project ID, `description` → zone
- Feature: `gcp = []` (no extra deps, uses gcloud CLI)

**Bundle**: `cloud = ["ssm", "azure", "gcp"]`

### Phase 5 : Messaging-based Adapters (nécessite agent distant)

> Ces adapters nécessitent un **agent/daemon custom** installé sur les machines cibles.

- ZeroMQ adapter (`src/zmq_exec/`) — `zeromq`
- NATS adapter (`src/nats_exec/`) — `async-nats`
- MQTT adapter (`src/mqtt_exec/`) — `rumqttc` (IoT/edge uniquement)

## Feature Flags (`Cargo.toml`)

```toml
[features]
default = ["cli"]

# Tier 1 — Air-gapped execution protocols
winrm = ["dep:reqwest", "dep:quick-xml"]
telnet = ["dep:mini-telnet"]
netconf = ["dep:netconf-rs"]
grpc = ["dep:tonic", "dep:prost"]

# Tier 2 — Specialized
k8s-exec = ["dep:kube", "dep:k8s-openapi"]
serial = ["dep:serial2-tokio"]
snmp = ["dep:csnmp"]

# Tier 3 — Cloud-only (non air-gapped)
ssm = ["dep:aws-sdk-ssm", "dep:aws-config"]
azure = ["dep:reqwest"]
gcp = []
cloud = ["ssm", "azure", "gcp"]

# Tier 4 — Messaging (requires remote agent)
zeromq = ["dep:zeromq"]
nats = ["dep:async-nats"]
mqtt = ["dep:rumqttc"]

# Bundles
air-gapped = ["winrm", "telnet", "netconf", "serial", "snmp"]
all-protocols = ["winrm", "telnet", "netconf", "grpc", "k8s-exec", "serial", "snmp", "ssm", "azure", "gcp", "zeromq", "nats", "mqtt"]
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

  # Switch Cisco legacy via Telnet (NOUVEAU)
  cisco-core-sw:
    hostname: 10.0.0.1
    protocol: telnet
    transport:
      type: telnet
      port: 23
      prompt_regex: "^\\S+[#>]"
      login_prompt: "Username:"
      password_prompt: "Password:"
      auth: { type: password, password_env: SWITCH_PASSWORD }

  # Juniper via NETCONF (NOUVEAU)
  juniper-router:
    hostname: 10.0.0.2
    user: admin
    protocol: netconf
    transport:
      type: netconf
      port: 830
      auth: { type: key, path: ~/.ssh/id_ed25519 }

  # Console série BMC (NOUVEAU)
  server-bmc:
    hostname: /dev/ttyUSB0
    protocol: serial
    transport:
      type: serial
      baud_rate: 115200
      data_bits: 8
      parity: none
      stop_bits: 1

  # Kubernetes pod direct
  k8s-api-pod:
    hostname: api-deployment-xyz
    protocol: kubernetes
    transport:
      type: kubernetes
      namespace: production
      container: api
      kubeconfig: ~/.kube/config

  # AWS EC2 via SSM (cloud-only)
  aws-web-prod:
    hostname: i-0abc123def456
    user: ssm-user
    protocol: ssm
    transport:
      type: ssm
      region: us-east-1
      document: AWS-RunShellScript
```

## Nouveaux groupes d'outils

| Groupe | Outils | Protocole |
|--------|--------|-----------|
| `netconf` | `netconf_get_config`, `netconf_edit_config`, `netconf_validate`, `netconf_commit`, `netconf_lock`, `netconf_unlock` | NETCONF |
| `snmp` | `snmp_get`, `snmp_walk`, `snmp_set`, `snmp_table`, `snmp_trap_list` | SNMP |
| `serial_console` | `serial_connect`, `serial_send`, `serial_expect`, `serial_disconnect` | Serial |

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
| `src/telnet/` | **Nouveau module** — Telnet adapter |
| `src/netconf/` | **Nouveau module** — NETCONF adapter |
| `src/winrm/` | **Nouveau module** — WinRM adapter |
| `src/serial/` | **Nouveau module** — Serial adapter |
| `src/snmp/` | **Nouveau module** — SNMP adapter (trait séparé) |
| `src/ssm/` | **Nouveau module** — SSM adapter |
| `src/grpc_exec/` | **Nouveau module** — gRPC adapter |
| `src/domain/use_cases/netconf.rs` | **Nouveau** — NETCONF command builders |
| `src/domain/use_cases/snmp.rs` | **Nouveau** — SNMP command builders |
| `src/domain/use_cases/serial.rs` | **Nouveau** — Serial command builders |
| `src/mcp/tool_handlers/netconf.rs` | **Nouveau** — NETCONF tool handlers |
| `src/mcp/tool_handlers/snmp.rs` | **Nouveau** — SNMP tool handlers |
| `src/mcp/tool_handlers/serial.rs` | **Nouveau** — Serial tool handlers |
| `Cargo.toml` | Features flags + dépendances conditionnelles |
| `docs/research/multi-protocol-support-plan.md` | Mise à jour avec le plan corrigé |

## Vérification

1. `make test` — Les 5800+ tests existants passent (aucun changement de comportement SSH)
2. Charger un ancien `config.yaml` sans `protocol:` → confirmer parsing en `TransportConfig::Ssh`
3. Charger un config multi-protocol → confirmer dispatch correct
4. Pour chaque adapter : test unitaire avec mock, test d'intégration feature-gated
5. `make lint` — Clippy clean
6. `make ci` — CI complet
7. Compiler avec `--features air-gapped` → vérifie que tout compile
8. Compiler avec `--no-default-features` → vérifie que SSH seul fonctionne

## Sources

- [WinRM - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
- [gRPC](https://grpc.io/)
- [RFC 6241 - NETCONF](https://datatracker.ietf.org/doc/html/rfc6241)
- [RFC 6242 - NETCONF over SSH](https://datatracker.ietf.org/doc/html/rfc6242)
- [mini-telnet crate](https://crates.io/crates/mini-telnet)
- [netconf-rs](https://github.com/jiegec/netconf-rs)
- [serial2-tokio](https://docs.rs/serial2-tokio)
- [csnmp](https://crates.io/crates/csnmp)
- [aws-sdk-ssm crate](https://crates.io/crates/aws-sdk-ssm)
- [librust-winrm](https://github.com/oktay454/librust-winrm)
- [tonic gRPC](https://github.com/hyperium/tonic)
- [kube-rs](https://github.com/kube-rs/kube)
- [SaltStack ZeroMQ Transport](https://docs.saltproject.io/en/latest/topics/transports/zeromq.html)
