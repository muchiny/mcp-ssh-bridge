# PLAN.md — MCP SSH Bridge Feature Roadmap (v1.6.0 → v2.2.0)

> **18 features** | **56 nouveaux tools** | **7 phases** | Total final : **337 tools**, **69 groups**

---

## Conventions Architecture

Chaque feature suit le pattern hexagonal existant :

1. **Domain** (`src/domain/use_cases/`) : `*CommandBuilder` avec des méthodes `build_*_command()` pures (pas d'I/O)
2. **Tool handler** (`src/mcp/tool_handlers/`) : 1 fichier par tool, trait `StandardTool`, struct `Args` avec `impl_common_args!`
3. **Registry** (`src/mcp/registry.rs`) : Enregistrement dans `create_filtered_registry()`, `tool_group()`, `tool_annotations()`
4. **Config** (`src/config/types.rs`) : Nouvelles sections si nécessaire
5. **Tests** : Minimum par tool : `test_missing_arguments`, `test_unknown_host`, `test_schema`, `test_args_deserialization`, `test_build_command_*`

Fichiers modifiés pour CHAQUE nouveau tool :

- `src/mcp/tool_handlers/mod.rs` — `mod` + `pub use`
- `src/mcp/registry.rs` — import, `all_handlers`, `tool_group()`, `tool_annotations()`, assertion count
- `src/domain/use_cases/mod.rs` — `pub mod`

---

## Phase 1 : Observability & Analysis (v1.6.0)

**Features** : Cron Analysis, Performance Profiling, Container Log Analysis
**Pourquoi ensemble** : Tools read-only d'observation. Pas de mutation d'état. Même pattern que `ssh_diagnose`.

### 1.1 — Intelligent Cron/Job Analysis (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_cron_analyze` | Détecter overlaps, jobs qui échouent, jobs qui ne tournent jamais |
| `ssh_cron_history` | Historique d'exécution des crons (syslog/journalctl) |
| `ssh_at_jobs` | Gérer les jobs `at` (atq, at -c) |

**Nouveaux fichiers** :

- `src/domain/use_cases/cron_analysis.rs` — `CronAnalysisCommandBuilder`
- `src/mcp/tool_handlers/ssh_cron_analyze.rs`
- `src/mcp/tool_handlers/ssh_cron_history.rs`
- `src/mcp/tool_handlers/ssh_at_jobs.rs`

**Groupe** : `cron_analysis`

### 1.2 — Performance Profiling (4 tools)

| Tool | Description |
|------|-------------|
| `ssh_perf_trace` | Tracer les syscalls d'un process (perf stat/strace) |
| `ssh_io_trace` | Tracer les I/O (iostat/iotop/blktrace) |
| `ssh_latency_test` | Tester la latence réseau/disque (ping/mtr) |
| `ssh_benchmark` | Benchmarks rapides CPU/IO/réseau (sysbench/fio/dd) |

**Nouveaux fichiers** :

- `src/domain/use_cases/performance.rs` — `PerformanceCommandBuilder`
- `src/mcp/tool_handlers/ssh_perf_trace.rs`
- `src/mcp/tool_handlers/ssh_io_trace.rs`
- `src/mcp/tool_handlers/ssh_latency_test.rs`
- `src/mcp/tool_handlers/ssh_benchmark.rs`

**Groupe** : `performance`
**Note sécurité** : `perf`/`blktrace` peuvent nécessiter sudo. Durée configurable avec limites.

### 1.3 — Container Log Analysis (4 tools)

| Tool | Description |
|------|-------------|
| `ssh_container_log_search` | Chercher dans les logs Docker avec filtres (time, severity, pattern) |
| `ssh_container_log_stats` | Statistiques de logs (error rate, top errors, fréquence) |
| `ssh_container_events` | Événements Docker/K8s (restarts, OOM kills, evictions) |
| `ssh_container_health_history` | Historique des health checks |

**Nouveaux fichiers** :

- `src/domain/use_cases/container_logs.rs` — `ContainerLogCommandBuilder`
- `src/mcp/tool_handlers/ssh_container_log_search.rs`
- `src/mcp/tool_handlers/ssh_container_log_stats.rs`
- `src/mcp/tool_handlers/ssh_container_events.rs`
- `src/mcp/tool_handlers/ssh_container_health_history.rs`

**Groupe** : `container_logs`
**Pattern de référence** : `ssh_docker_logs.rs`

### Bilan Phase 1

- **+11 tools** (281 → 292)
- **+3 groupes** (`cron_analysis`, `performance`, `container_logs`)
- **~180 nouveaux tests**

---

## Phase 2 : Network Security & Compliance (v1.7.0)

**Features** : Network Security Analysis, Compliance as Code
**Pourquoi ensemble** : Outils de sécurité. Le scan réseau fournit les primitives, la compliance les exploite.

### 2.1 — Network Security Analysis (4 tools)

| Tool | Description |
|------|-------------|
| `ssh_port_scan` | Scanner les ports ouverts (nmap/ss/nc -z) |
| `ssh_ssl_audit` | Auditer la configuration TLS/SSL (openssl s_client, testssl.sh) |
| `ssh_network_capture` | Capture de paquets limitée (tcpdump -c, max 1000 paquets) |
| `ssh_fail2ban_status` | État de fail2ban/denyhosts par jail |

**Nouveaux fichiers** :

- `src/domain/use_cases/network_security.rs` — `NetworkSecurityCommandBuilder`
- `src/mcp/tool_handlers/ssh_port_scan.rs`
- `src/mcp/tool_handlers/ssh_ssl_audit.rs`
- `src/mcp/tool_handlers/ssh_network_capture.rs`
- `src/mcp/tool_handlers/ssh_fail2ban_status.rs`

**Groupe** : `network_security` — **DÉSACTIVÉ par défaut** (sensible)
**Sécurité** : Validation des IPs cibles, limite hard de paquets pour tcpdump.

### 2.2 — Compliance as Code (4 tools)

| Tool | Description |
|------|-------------|
| `ssh_cis_benchmark` | Vérifier CIS Benchmarks (file perms, SSH hardening, kernel params) |
| `ssh_stig_check` | Vérifier DISA STIG par ID |
| `ssh_compliance_score` | Score de conformité global (pass/fail/total) |
| `ssh_compliance_report` | Rapport de conformité structuré (JSON/texte) |

**Nouveaux fichiers** :

- `src/domain/use_cases/compliance.rs` — `ComplianceCommandBuilder`
- `src/mcp/tool_handlers/ssh_cis_benchmark.rs`
- `src/mcp/tool_handlers/ssh_stig_check.rs`
- `src/mcp/tool_handlers/ssh_compliance_score.rs`
- `src/mcp/tool_handlers/ssh_compliance_report.rs`
- `config/compliance/` — Profils de compliance en YAML (comme `config/runbooks/`)

**Groupe** : étend `security_scan`
**Config** : `ComplianceConfig` avec `profiles_dir`

### Bilan Phase 2

- **+8 tools** (292 → 300)
- **+1 groupe** (`network_security`), 1 étendu (`security_scan`)
- **~130 nouveaux tests**

---

## Phase 3 : Cloud & Inventory (v1.8.0)

**Features** : Cloud Provider Integration, Host Discovery & Inventory, Multi-cloud Inventory
**Pourquoi ensemble** : Concepts couplés — cloud fournit les primitives, inventory les utilise, multi-cloud agrège.

### 3.1 — Cloud Provider Integration (4 tools)

| Tool | Description |
|------|-------------|
| `ssh_aws_cli` | Exécuter des commandes AWS CLI via le host |
| `ssh_cloud_metadata` | Récupérer métadonnées instance (auto-détecte AWS/GCP/Azure) |
| `ssh_cloud_tags` | Lire/écrire les tags cloud de l'instance |
| `ssh_cloud_cost` | Coûts de l'instance (aws ce get-cost-and-usage) |

**Nouveaux fichiers** :

- `src/domain/use_cases/cloud.rs` — `CloudCommandBuilder`
- `src/mcp/tool_handlers/ssh_aws_cli.rs`
- `src/mcp/tool_handlers/ssh_cloud_metadata.rs`
- `src/mcp/tool_handlers/ssh_cloud_tags.rs`
- `src/mcp/tool_handlers/ssh_cloud_cost.rs`

**Groupe** : `cloud`

### 3.2 — Host Discovery & Inventory (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_discover_hosts` | Scanner un subnet pour trouver les hosts SSH (nmap -sn/arp-scan) |
| `ssh_inventory_sync` | Collecter hostname, OS, IP, uptime de tous les hosts configurés |
| `ssh_host_tags` | Gérer les tags sur les hosts pour filtrage |

**Nouveaux fichiers** :

- `src/domain/use_cases/inventory.rs` — `InventoryCommandBuilder`
- `src/mcp/tool_handlers/ssh_discover_hosts.rs`
- `src/mcp/tool_handlers/ssh_inventory_sync.rs` — multi-host (pattern `ssh_exec_multi.rs`)
- `src/mcp/tool_handlers/ssh_host_tags.rs`

**Groupe** : `inventory`

### 3.3 — Multi-cloud Inventory (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_multicloud_list` | Lister les instances par provider |
| `ssh_multicloud_sync` | Agréger les inventaires cross-provider |
| `ssh_multicloud_compare` | Comparer les inventaires entre providers |

**Nouveaux fichiers** :

- `src/domain/use_cases/multicloud.rs` — `MulticloudCommandBuilder`
- `src/mcp/tool_handlers/ssh_multicloud_list.rs`
- `src/mcp/tool_handlers/ssh_multicloud_sync.rs`
- `src/mcp/tool_handlers/ssh_multicloud_compare.rs`

**Groupe** : `multicloud`

### Bilan Phase 3

- **+10 tools** (300 → 310)
- **+3 groupes** (`cloud`, `inventory`, `multicloud`)
- **~170 nouveaux tests**

---

## Phase 4 : Alerting, Capacity & Incident Intelligence (v1.9.0)

**Features** : Alerting & Thresholds, Capacity Planning, Incident Timeline
**Pourquoi ensemble** : Ops proactives. Alerting définit les seuils, capacity prédit quand ils seront atteints, incident timeline analyse après coup.

### 4.1 — Alerting & Thresholds (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_alert_set` | Définir un seuil (CPU > 90%, disk > 85%) — local, pas de SSH |
| `ssh_alert_list` | Lister les alertes actives — local |
| `ssh_alert_check` | Vérifier tous les seuils maintenant — via SSH |

**Nouveaux fichiers** :

- `src/domain/use_cases/alerting.rs` — `AlertingCommandBuilder`
- `src/domain/alerting.rs` — `AlertDefinition`, `AlertStore` (stockage local `~/.config/mcp-ssh-bridge/alerts.json`)
- `src/mcp/tool_handlers/ssh_alert_set.rs` — handler custom (pas StandardTool)
- `src/mcp/tool_handlers/ssh_alert_list.rs` — handler custom
- `src/mcp/tool_handlers/ssh_alert_check.rs` — StandardTool

**Groupe** : `alerting`
**Config** : `AlertingConfig` avec `alerts_file`, `default_check_interval`

### 4.2 — Capacity Planning (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_capacity_collect` | Collecter métriques CPU/RAM/disk/inodes actuelles |
| `ssh_capacity_trend` | Tendances via `sar` (sysstat) |
| `ssh_capacity_predict` | Données brutes pour que le LLM extrapole les tendances |

**Nouveaux fichiers** :

- `src/domain/use_cases/capacity.rs` — `CapacityCommandBuilder`
- `src/mcp/tool_handlers/ssh_capacity_collect.rs`
- `src/mcp/tool_handlers/ssh_capacity_trend.rs`
- `src/mcp/tool_handlers/ssh_capacity_predict.rs`

**Groupe** : `capacity`

### 4.3 — Incident Timeline (2 tools)

| Tool | Description |
|------|-------------|
| `ssh_incident_timeline` | Reconstruire la timeline chronologique (syslog, services, deploys, logins, OOM) |
| `ssh_incident_correlate` | Corréler par services spécifiques |

**Nouveaux fichiers** :

- `src/domain/use_cases/incident.rs` — `IncidentCommandBuilder`
- `src/mcp/tool_handlers/ssh_incident_timeline.rs`
- `src/mcp/tool_handlers/ssh_incident_correlate.rs`

**Groupe** : étend `diagnostics`

### Bilan Phase 4

- **+8 tools** (310 → 318)
- **+2 groupes** (`alerting`, `capacity`), 1 étendu (`diagnostics`)
- **~140 nouveaux tests**

---

## Phase 5 : Multi-host Operations & ChatOps (v2.0.0)

**Features** : Log Aggregation Multi-host, SSH Key Rotation, Backup Enhanced, ChatOps Hooks
**Pourquoi ensemble** : Coordination cross-host et effets de bord. Construit sur le pattern multi-host de `ssh_exec_multi`/`ssh_rolling_exec`.

### 5.1 — Log Aggregation Multi-host (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_log_search_multi` | Chercher un pattern dans les logs de N serveurs en parallèle |
| `ssh_log_aggregate` | Stats de logs agrégées cross-hosts (error counts, warning counts) |
| `ssh_log_tail_multi` | Tail des logs récents de N hosts simultanément |

**Nouveaux fichiers** :

- `src/domain/use_cases/log_aggregation.rs` — `LogAggregationCommandBuilder`
- `src/mcp/tool_handlers/ssh_log_search_multi.rs` — pattern `ssh_exec_multi.rs`
- `src/mcp/tool_handlers/ssh_log_aggregate.rs`
- `src/mcp/tool_handlers/ssh_log_tail_multi.rs`

**Groupe** : `log_aggregation`

### 5.2 — SSH Key Rotation (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_key_generate` | Générer une paire de clés — local, pas de SSH |
| `ssh_key_distribute` | Distribuer la clé publique sur N hosts |
| `ssh_key_audit` | Auditer les clés autorisées (âge, type, longueur) |

**Nouveaux fichiers** :

- `src/domain/use_cases/key_management.rs` — `KeyManagementCommandBuilder`
- `src/mcp/tool_handlers/ssh_key_generate.rs`
- `src/mcp/tool_handlers/ssh_key_distribute.rs`
- `src/mcp/tool_handlers/ssh_key_audit.rs`

**Groupe** : `key_management` — **DÉSACTIVÉ par défaut** (sensible)

### 5.3 — Backup Enhanced (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_backup_snapshot` | Snapshot avec timestamp et métadonnées |
| `ssh_backup_verify` | Vérifier l'intégrité d'une archive (tar -t, checksums) |
| `ssh_backup_schedule` | Créer un cron job de backup périodique |

**Nouveaux fichiers** :

- `src/domain/use_cases/backup_advanced.rs` — `BackupAdvancedCommandBuilder`
- `src/mcp/tool_handlers/ssh_backup_snapshot.rs`
- `src/mcp/tool_handlers/ssh_backup_verify.rs`
- `src/mcp/tool_handlers/ssh_backup_schedule.rs`

**Groupe** : étend `backup`

### 5.4 — ChatOps Hooks (2 tools)

| Tool | Description |
|------|-------------|
| `ssh_webhook_send` | Envoyer un webhook depuis un host distant (curl POST) |
| `ssh_notify` | Notification formatée Slack/Teams avec contexte |

**Nouveaux fichiers** :

- `src/domain/use_cases/chatops.rs` — `ChatOpsCommandBuilder`
- `src/mcp/tool_handlers/ssh_webhook_send.rs`
- `src/mcp/tool_handlers/ssh_notify.rs`

**Groupe** : `chatops`
**Config** : `ChatOpsConfig` avec `webhooks: HashMap<String, WebhookConfig>` (url, type, headers)
**Sécurité** : HTTPS only pour les webhooks, sanitization du payload.

### Bilan Phase 5

- **+11 tools** (318 → 329)
- **+3 groupes** (`log_aggregation`, `key_management`, `chatops`), 1 étendu (`backup`)
- **~190 nouveaux tests**

---

## Phase 6 : Configuration Templates & MCP Roots (v2.1.0)

**Features** : Configuration Templates Library, MCP Roots Support
**Pourquoi ensemble** : Templates = système de registry comme les runbooks. MCP Roots = sécurité protocol-level. Les deux sont de l'infrastructure.

### 6.1 — Configuration Templates Library (5 tools)

| Tool | Description |
|------|-------------|
| `ssh_template_list` | Lister les templates disponibles — local |
| `ssh_template_show` | Afficher le contenu d'un template — local |
| `ssh_template_apply` | Rendre et écrire un template sur le host |
| `ssh_template_validate` | Valider une config (nginx -t, pg_isready, etc.) |
| `ssh_template_diff` | Comparer template rendu vs config actuelle |

**Nouveaux fichiers** :

- `src/domain/template.rs` — `ConfigTemplate`, `TemplateLibrary` (substitution `{{variable}}`, pas de dépendance externe)
- `src/domain/use_cases/templates.rs` — `TemplateCommandBuilder`
- `src/mcp/tool_handlers/ssh_template_list.rs`
- `src/mcp/tool_handlers/ssh_template_show.rs`
- `src/mcp/tool_handlers/ssh_template_apply.rs`
- `src/mcp/tool_handlers/ssh_template_validate.rs`
- `src/mcp/tool_handlers/ssh_template_diff.rs`
- `config/templates/nginx/` — Templates Nginx (reverse proxy, static, SSL)
- `config/templates/apache/` — Templates Apache
- `config/templates/postgresql/` — Templates PostgreSQL
- `config/templates/mysql/` — Templates MySQL
- `config/templates/redis/` — Templates Redis

**Groupe** : `templates`
**Pattern de référence** : `src/domain/runbook.rs` pour le chargement YAML depuis un répertoire.

### 6.2 — MCP Roots Support (0 tools, infrastructure)

Pas de nouveaux tools — c'est un renforcement sécurité au niveau protocole.

**Fichiers modifiés** :

- `src/security/validator.rs` — `validate_path_in_roots(path, roots)`
- `src/mcp/standard_tool.rs` — Nouveau const `ENFORCE_ROOTS: bool = false;`, les tools fichier le mettent à `true`
- `src/mcp/server.rs` — Handler `roots/list_changed` pour mise à jour dynamique
- `src/mcp/tool_handlers/utils.rs` — `validate_path` étendu avec roots optionnel

### Bilan Phase 6

- **+5 tools** (329 → 334)
- **+1 groupe** (`templates`)
- **~120 nouveaux tests**

---

## Phase 7 : Interactive Terminal (v2.2.0)

**Feature** : Interactive Terminal (Pseudo-PTY)
**Pourquoi seul** : Le plus complexe architecturalement. Touche le SSH adapter (russh PTY), nouveau mode d'exécution, gestion de session.

### 7.1 — Interactive Terminal (3 tools)

| Tool | Description |
|------|-------------|
| `ssh_pty_exec` | Exécuter une commande avec allocation PTY |
| `ssh_pty_interact` | Envoyer de l'input à une session PTY active |
| `ssh_pty_resize` | Redimensionner le terminal (SIGWINCH) |

**Nouveaux fichiers** :

- `src/ports/ssh.rs` — Étend `SshExecutor` avec `async fn execute_pty()`
- `src/ssh/client.rs` — Implémente `execute_pty` via `channel.request_pty()` de russh
- `src/domain/use_cases/pty.rs` — `PtyCommandBuilder`
- `src/mcp/tool_handlers/ssh_pty_exec.rs`
- `src/mcp/tool_handlers/ssh_pty_interact.rs`
- `src/mcp/tool_handlers/ssh_pty_resize.rs`
- `src/security/sanitizer.rs` — `SanitizeMode::PreserveAnsi`

**Groupe** : `pty` — **DÉSACTIVÉ par défaut**
**Points critiques** :

- Timeout hard obligatoire (les sessions PTY peuvent bloquer)
- Bypass la validation de commandes → opt-in explicite requis
- L'entropie de détection de secrets doit gérer les séquences ANSI
- Sessions trackées dans `SessionManager` avec auto-close

### Bilan Phase 7

- **+3 tools** (334 → 337)
- **+1 groupe** (`pty`)
- **~80 nouveaux tests**

---

## Résumé Global

| Phase | Version | Features | +Tools | Total | +Groupes |
|-------|---------|----------|--------|-------|----------|
| 1 | v1.6.0 | Cron, Perf, Container Logs | +11 | 292 | +3 |
| 2 | v1.7.0 | Network Security, Compliance | +8 | 300 | +1, 1 étendu |
| 3 | v1.8.0 | Cloud, Inventory, Multi-cloud | +10 | 310 | +3 |
| 4 | v1.9.0 | Alerting, Capacity, Incident | +8 | 318 | +2, 1 étendu |
| 5 | v2.0.0 | Logs Multi, Keys, Backup+, ChatOps | +11 | 329 | +3, 1 étendu |
| 6 | v2.1.0 | Templates, MCP Roots | +5 | 334 | +1 |
| 7 | v2.2.0 | Interactive Terminal (PTY) | +3 | 337 | +1 |
| **TOTAL** | | **18 features** | **+56** | **337** | **+14 new, +3 extended** |

## Groupes désactivés par défaut (sécurité)

- `network_security` — port scanning, packet capture
- `key_management` — rotation de clés SSH
- `pty` — terminal interactif

## Estimation tests

- Tests actuels : ~4782
- Nouveaux tests estimés : ~1010
- **Total estimé : ~5792 tests**
