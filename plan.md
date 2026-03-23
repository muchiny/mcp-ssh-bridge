# Plan d'Implémentation — Features Manquantes MCP SSH Bridge

> 10 features, ~55 nouveaux fichiers, ~7 nouveaux tool groups, passage de 262 à ~290 tools

---

## ÉTAT ACTUEL VÉRIFIÉ (ce qui EXISTE déjà)

| Feature | Status | Détail |
|---------|--------|--------|
| Secrets detection (56 patterns, Aho-Corasick, 17 catégories) | ✅ | `src/security/sanitizer.rs` |
| Audit logging (JSON Lines, async mpsc, rotation) | ✅ | `src/security/audit.rs` |
| File ops (read/write/chmod/chown/stat) | ✅ | `src/mcp/tool_handlers/ssh_file_*.rs` |
| Git diff | ✅ | `ssh_git_diff` |
| Multi-host exec basique (parallèle, fail-fast) | ✅ | `ssh_exec_multi` |
| Health check basique (pool, sessions, history) | ✅ | `ssh_health` |
| Release: 5 targets, Docker, cargo install, SBOM, attestations | ✅ | `release.yml`, `Makefile` |
| MCP complet (Tools, Resources, Prompts, Sampling, Tasks, OAuth, HTTP) | ✅ | Tout implémenté |

**Ce qui est ABSENT** (confirmé par recherche) :

- Entropy-based secrets detection
- Session recording / hash-chain audit
- Intelligent diagnostics (ssh_diagnose)
- Runbook engine
- Advanced multi-host (canary, rolling, fleet diff)
- Environment drift detection
- File diff/patch/template (hors git)
- SBOM/vuln scan remote
- MCP Server Card
- DXT packaging

---

## PHASE 1 — Sécurité & Compliance (semaine 1)

### 1.1 Secrets Detection par Entropie

**Fichiers à modifier :**

- `src/security/sanitizer.rs` — ajouter module entropie dans le pipeline existant
- `src/security/entropy.rs` — **NOUVEAU** : calcul Shannon entropy par token
- `src/config/types.rs` — ajouter `entropy_threshold: f64` dans `SanitizeConfig`
- `config/config.example.yaml` — documenter le nouveau champ

**Logique :**

```
Pour chaque token (mot séparé par espace/newline) dans l'output :
  1. Si longueur >= 16 caractères
  2. Calculer Shannon entropy = -Σ p(x) * log2(p(x))
  3. Si entropy >= seuil (défaut: 4.5 pour hex, 5.0 pour base64)
  4. Et pas dans whitelist → remplacer par ***HIGH_ENTROPY_REDACTED***
```

**Intégration :** S'insère dans `Sanitizer::sanitize()` APRÈS les patterns regex (tier 1-5) et AVANT le retour. Zéro impact sur le pipeline existant si désactivé.

**Config YAML :**

```yaml
security:
  sanitize:
    entropy_detection: true          # NEW
    entropy_threshold: 4.5           # NEW (Shannon bits)
    entropy_min_length: 16           # NEW
    entropy_whitelist: []            # NEW (known safe strings)
```

**Tests :** 8 tests unitaires (vraie clé AWS, faux positif UUID, seuil configurable, whitelist, perf)

---

### 1.2 Session Recording & Hash-Chain Audit

**Fichiers NOUVEAUX :**

- `src/security/recording.rs` — SessionRecorder (format asciinema v2 + hash chain)
- `src/mcp/tool_handlers/ssh_recording_start.rs`
- `src/mcp/tool_handlers/ssh_recording_stop.rs`
- `src/mcp/tool_handlers/ssh_recording_list.rs`
- `src/mcp/tool_handlers/ssh_recording_replay.rs`
- `src/mcp/tool_handlers/ssh_recording_verify.rs`

**Fichiers à modifier :**

- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `recording` + annotations
- `src/config/types.rs` — `RecordingConfig` struct
- `config/config.example.yaml` — section recording

**Format asciinema v2 :**

```json
{"version": 2, "width": 80, "height": 24, "timestamp": 1234567890}
[0.5, "o", "$ whoami\r\n"]
[0.8, "o", "root\r\n"]
```

**Hash chain :** Chaque événement inclut `hash = HMAC-SHA256(previous_hash + event_data, secret_key)`. Vérifiable via `ssh_recording_verify`.

**Groupe : `recording`** (5 tools, read-only sauf start/stop)

**Config YAML :**

```yaml
recording:
  enabled: false
  path: ~/.local/share/mcp-ssh-bridge/recordings/
  format: asciinema_v2
  hash_chain: true
  hash_key_env: MCP_RECORDING_KEY   # env var for HMAC key
  max_duration_seconds: 3600
  auto_mask_secrets: true            # uses sanitizer on recordings
```

**Tests :** 10 tests (record/replay cycle, hash chain verification, tamper detection, secret masking)

---

## PHASE 2 — SRE Platform (semaine 2)

### 2.1 Intelligent Diagnostics

**Fichiers NOUVEAUX :**

- `src/domain/use_cases/diagnostics.rs` — DiagnosticsCommandBuilder
- `src/mcp/tool_handlers/ssh_diagnose.rs`
- `src/mcp/tool_handlers/ssh_incident_triage.rs`
- `src/mcp/tool_handlers/ssh_compare_state.rs`

**Fichiers à modifier :**

- `src/domain/use_cases/mod.rs` — export
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `diagnostics` + annotations
- `config/config.example.yaml` — section diagnostics

**`ssh_diagnose` — Un seul appel collecte :**

```bash
# Exécuté comme UN script compound via ssh_exec
uptime && free -m && df -h && top -bn1 | head -20 && \
systemctl --failed --no-pager && \
journalctl -p err --since '1 hour ago' --no-pager -n 50 && \
dmesg | grep -i 'oom\|kill\|error' | tail -20 && \
ss -tunapl | head -30
```

Retourne un JSON structuré (utilise `outputSchema` existant) avec sections : cpu, memory, disk, processes, failed_services, recent_errors, oom_kills, network.

**`ssh_incident_triage` args :** `host`, `symptom` (slow|crash|oom|disk|network), `since` (timerange)
→ Adapte les commandes selon le symptôme. Ex: symptom=oom → focus dmesg OOM, /proc/meminfo, top RSS.

**`ssh_compare_state` args :** `host`, `baseline_snapshot_id`
→ Compare état actuel vs snapshot enregistré (lien avec Phase 4 drift detection).

**Groupe : `diagnostics`** (3 tools, tous read-only)

**Tests :** 6 tests par handler (18 total)

---

### 2.2 Runbook Engine

**Fichiers NOUVEAUX :**

- `src/domain/runbook.rs` — Runbook model (Step, Condition, Rollback)
- `src/domain/use_cases/runbook_engine.rs` — RunbookExecutor
- `src/mcp/tool_handlers/ssh_runbook_list.rs`
- `src/mcp/tool_handlers/ssh_runbook_execute.rs`
- `src/mcp/tool_handlers/ssh_runbook_status.rs`
- `src/mcp/tool_handlers/ssh_runbook_validate.rs`
- `config/runbooks/` — **NOUVEAU répertoire** avec runbooks built-in :
  - `config/runbooks/disk_full.yaml`
  - `config/runbooks/service_restart.yaml`
  - `config/runbooks/cert_renewal.yaml`
  - `config/runbooks/oom_recovery.yaml`
  - `config/runbooks/log_rotation.yaml`

**Fichiers à modifier :**

- `src/domain/mod.rs` — export runbook module
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `runbooks` + annotations
- `src/config/types.rs` — `RunbookConfig` struct
- `config/config.example.yaml` — section runbooks
- `Cargo.toml` — **aucune nouvelle dep** (serde_yaml déjà via serde-saphir)

**Format Runbook YAML :**

```yaml
name: disk_full_recovery
description: "Recover from disk full condition"
version: "1.0"
params:
  threshold_percent: { type: integer, default: 90 }
  target_dir: { type: string, default: "/var/log" }

steps:
  - name: check_disk
    command: "df -h {{ target_dir }} | awk 'NR==2{print $5}' | tr -d '%'"
    save_as: current_usage

  - name: evaluate
    condition: "{{ current_usage }} >= {{ threshold_percent }}"
    on_false: skip_to_end

  - name: find_large_files
    command: "find {{ target_dir }} -type f -size +100M -exec ls -lh {} + 2>/dev/null | sort -k5 -rh | head -20"

  - name: clean_old_logs
    command: "find {{ target_dir }} -name '*.gz' -mtime +7 -delete"
    confirm: true    # Requires MCP Elicitation confirmation
    rollback: "echo 'No rollback possible for deleted files'"

  - name: verify
    command: "df -h {{ target_dir }}"
```

**Exécution :** Utilise MCP Tasks existant pour le suivi async. Chaque step → `ssh_exec` interne. Progress notifications via MCP Progress existant.

**Groupe : `runbooks`** (4 tools : list=read-only, execute=destructive, status=read-only, validate=read-only)

**Tests :** 8 tests par handler + 10 tests pour le RunbookExecutor (parsing, conditions, rollback, template vars)

---

## PHASE 3 — Orchestration Avancée (semaine 3)

### 3.1 Advanced Multi-Host

**Fichiers NOUVEAUX :**

- `src/domain/use_cases/orchestration.rs` — OrchestrationEngine
- `src/mcp/tool_handlers/ssh_canary_exec.rs`
- `src/mcp/tool_handlers/ssh_rolling_exec.rs`
- `src/mcp/tool_handlers/ssh_fleet_diff.rs`

**Fichiers à modifier :**

- `src/domain/use_cases/mod.rs` — export
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `orchestration` + annotations
- `config/config.example.yaml` — section orchestration

**`ssh_canary_exec` :**

```json
{
  "hosts": ["web1", "web2", "web3", "web4", "web5"],
  "command": "sudo systemctl restart nginx",
  "canary_count": 1,
  "health_check": "curl -sf http://localhost/health",
  "health_timeout": 30,
  "proceed_on_success": true
}
```

Logique : exécute sur canary_count hosts → health_check → si OK, exécute sur le reste → health_check global.

**`ssh_rolling_exec` :**

```json
{
  "hosts": ["web1", "web2", "web3", "web4"],
  "command": "sudo apt upgrade -y nginx",
  "batch_size": 2,
  "health_check": "curl -sf http://localhost/health",
  "delay_between_batches": 10,
  "rollback_command": "sudo apt install nginx=1.24.0-1",
  "abort_on_failure": true
}
```

**`ssh_fleet_diff` :**

```json
{
  "hosts": ["web1", "web2", "web3", "web4"],
  "command": "nginx -V 2>&1 | head -1",
  "reference_host": "web1"
}
```

Retourne : quels hosts ont un output identique à la référence, lesquels divergent, avec le diff.

**Groupe : `orchestration`** (3 tools : canary=destructive, rolling=destructive, fleet_diff=read-only)

**Tests :** 6 tests par handler (18 total)

---

## PHASE 4 — DevOps Quality (semaine 4)

### 4.1 Environment Drift Detection

**Fichiers NOUVEAUX :**

- `src/domain/use_cases/drift.rs` — SnapshotBuilder, DriftDetector
- `src/mcp/tool_handlers/ssh_env_snapshot.rs`
- `src/mcp/tool_handlers/ssh_env_diff.rs`
- `src/mcp/tool_handlers/ssh_env_drift.rs`

**Fichiers à modifier :**

- `src/domain/use_cases/mod.rs` — export
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `drift` + annotations
- `src/config/types.rs` — `DriftConfig` + snapshot storage path
- `config/config.example.yaml` — section drift

**`ssh_env_snapshot` collecte :**

- Packages installés + versions (`dpkg -l` ou `rpm -qa`)
- Services actifs (`systemctl list-units --state=active`)
- Ports ouverts (`ss -tunapl`)
- Users/groups (`getent passwd`, `getent group`)
- Kernel version, hostname, OS release
- Config files checksums (configurable list)

Stocke en JSON local avec timestamp + SHA256 du snapshot.

**`ssh_env_diff` :** Compare 2 snapshots (même host à des dates différentes, ou 2 hosts différents).

**`ssh_env_drift` :** Compare un snapshot vs un "desired state" YAML (déclaratif).

**Groupe : `drift`** (3 tools, tous read-only)

---

### 4.2 File Diff / Patch / Template

**Fichiers NOUVEAUX :**

- `src/domain/use_cases/file_advanced.rs` — FileAdvancedCommandBuilder
- `src/mcp/tool_handlers/ssh_file_diff.rs`
- `src/mcp/tool_handlers/ssh_file_patch.rs`
- `src/mcp/tool_handlers/ssh_file_template.rs`

**Fichiers à modifier :**

- `src/domain/use_cases/mod.rs` — export
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — ajouter au groupe existant `file_ops`

**`ssh_file_diff` :** `diff -u file1 file2` (même host) ou cross-host (lit les 2 via ssh_exec puis diff local).

**`ssh_file_patch` :** Upload du patch + `patch -p0 < patch_file` avec `--dry-run` d'abord.

**`ssh_file_template` :** Simple `sed` substitution ou envsubst pour des templates basiques. Pas de Jinja2 (éviter la dépendance Python sur le remote).

**Ajout au groupe existant `file_ops`** (passe de 5 à 8 tools)

---

### 4.3 SBOM & Vulnerability Scanning (Remote)

**Fichiers NOUVEAUX :**

- `src/domain/use_cases/sbom.rs` — SbomCommandBuilder
- `src/mcp/tool_handlers/ssh_sbom_generate.rs`
- `src/mcp/tool_handlers/ssh_vuln_scan.rs`
- `src/mcp/tool_handlers/ssh_compliance_check.rs`

**Fichiers à modifier :**

- `src/domain/use_cases/mod.rs` — export
- `src/mcp/tool_handlers/mod.rs` — exports
- `src/mcp/registry.rs` — nouveau groupe `security_scan` + annotations
- `config/config.example.yaml` — section security_scan

**`ssh_sbom_generate` :**

```bash
# Détecte le package manager et génère l'inventaire
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null || \
rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null || \
apk list -I 2>/dev/null
```

Retourne JSON structuré (outputSchema).

**`ssh_vuln_scan` :** Croise l'inventaire packages avec une commande locale (`apt list --upgradable` / `yum updateinfo list sec` / `apk audit`). Pas de base CVE embarquée — utilise les outils natifs du système.

**`ssh_compliance_check` args :** `host`, `profile` (cis-level1 | cis-level2 | custom)
→ Vérifie des points CIS basiques : permissions /etc/shadow, SSH config, firewall status, etc. Script shell compound.

**Groupe : `security_scan`** (3 tools, tous read-only)

---

## PHASE 5 — Écosystème & Distribution (semaine 5)

### 5.1 MCP Server Card

**Fichier NOUVEAU :**

- `.well-known/mcp/server-card.json` — statique, commité dans le repo

**Contenu :**

```json
{
  "name": "mcp-ssh-bridge",
  "version": "0.x.y",
  "description": "Secure SSH bridge for AI-powered remote server management",
  "capabilities": {
    "tools": true,
    "resources": true,
    "prompts": true,
    "sampling": true,
    "elicitation": true,
    "tasks": true,
    "structured_output": true,
    "completions": true
  },
  "transports": ["stdio", "streamable-http"],
  "authentication": ["oauth2", "jwt"],
  "tool_count": 290,
  "tool_groups": 54,
  "homepage": "https://github.com/muchiny/mcp-ssh-bridge",
  "license": "MIT"
}
```

**Impact minimal :** Un seul fichier statique. Mis à jour manuellement ou via script dans `make release`.

---

### 5.2 DXT Packaging (Claude Desktop Extension)

**Fichiers NOUVEAUX :**

- `dxt/manifest.json` — DXT manifest
- `dxt/icon.png` — icône 512x512
- `dxt/README.md` — description pour le marketplace
- `Makefile` — nouvelle target `make dxt`

**`dxt/manifest.json` :**

```json
{
  "dxt_version": "0.1",
  "name": "mcp-ssh-bridge",
  "display_name": "MCP SSH Bridge",
  "version": "0.x.y",
  "description": "Execute commands on remote servers via SSH",
  "author": { "name": "muchiny" },
  "mcp": {
    "command": { "type": "binary", "path": "mcp-ssh-bridge" },
    "transport": "stdio"
  },
  "platforms": ["linux", "macos", "windows"],
  "icon": "icon.png"
}
```

**Intégration release :** Ajouter dans `release.yml` un step qui :

1. Copie le binaire + manifest.json + icon dans un dossier
2. Zip le tout en `.dxt`
3. Upload comme artifact de release

**Makefile target :**

```makefile
dxt: release
    @mkdir -p dist/dxt
    cp target/release/mcp-ssh-bridge dist/dxt/
    cp dxt/manifest.json dxt/icon.png dist/dxt/
    cd dist && zip -r mcp-ssh-bridge.dxt dxt/
    @echo "DXT package: dist/mcp-ssh-bridge.dxt"
```

---

### 5.3 Mise à jour Release Pipeline

**Fichiers à modifier :**

- `.github/workflows/release.yml` — ajouter :
  - Step DXT packaging (par plateforme)
  - Step server-card.json dans les assets
  - Upload .dxt comme artifact
- `Makefile` — ajouter targets `dxt`, `server-card`
- `config/config.example.yaml` — ajouter toutes les nouvelles sections (recording, runbooks, diagnostics, orchestration, drift, security_scan)

**Les archives release existantes (.tar.gz, .zip) incluront automatiquement** le binaire mis à jour avec les nouveaux tools. Aucun changement au format des archives existantes.

---

## RÉSUMÉ DES MODIFICATIONS

### Nouveaux fichiers (~40)

| Phase | Fichiers | Tools ajoutés |
|-------|----------|--------------|
| 1.1 Entropy | 1 (entropy.rs) | 0 (interne) |
| 1.2 Recording | 6 (recording.rs + 5 handlers) | 5 |
| 2.1 Diagnostics | 4 (diagnostics.rs + 3 handlers) | 3 |
| 2.2 Runbooks | 6 (runbook.rs + engine + 4 handlers) + 5 YAML | 4 |
| 3.1 Orchestration | 4 (orchestration.rs + 3 handlers) | 3 |
| 4.1 Drift | 4 (drift.rs + 3 handlers) | 3 |
| 4.2 File advanced | 4 (file_advanced.rs + 3 handlers) | 3 |
| 4.3 SBOM | 4 (sbom.rs + 3 handlers) | 3 |
| 5.1 Server Card | 1 (.well-known/mcp/server-card.json) | 0 |
| 5.2 DXT | 3 (manifest.json, icon, README) | 0 |
| **TOTAL** | **~42 fichiers** | **24 tools** |

### Fichiers existants modifiés (~8, toujours les mêmes)

| Fichier | Type de modification |
|---------|---------------------|
| `src/mcp/tool_handlers/mod.rs` | +24 mod + pub use |
| `src/mcp/registry.rs` | +7 groupes dans tool_group(), +24 handlers dans create_filtered_registry(), +24 annotations |
| `src/domain/use_cases/mod.rs` | +5 mod exports |
| `src/config/types.rs` | +4 config structs |
| `src/security/sanitizer.rs` | +appel entropy dans pipeline |
| `config/config.example.yaml` | +5 sections config |
| `.github/workflows/release.yml` | +DXT step |
| `Makefile` | +2 targets (dxt, server-card) |

### Nouveaux groupes de tools

| Groupe | Tools | Annotations |
|--------|-------|-------------|
| `recording` | 5 | start/stop=mutating, list/replay/verify=read-only |
| `diagnostics` | 3 | tous read-only |
| `runbooks` | 4 | execute=destructive, reste=read-only |
| `orchestration` | 3 | canary/rolling=destructive, fleet_diff=read-only |
| `drift` | 3 | tous read-only |
| `security_scan` | 3 | tous read-only |
| `file_ops` (existant) | +3 | diff=read-only, patch=destructive, template=mutating |

### Passage de 262 → 286 tools, de 47 → 53 groupes

### Aucune nouvelle dépendance Cargo requise

Tout est implémenté avec les crates existantes (serde, sha2/hmac pour hash-chain, regex pour entropy).

---

## ORDRE D'IMPLÉMENTATION RECOMMANDÉ

```
Phase 1.1 (Entropy)          ──┐
Phase 1.2 (Recording)        ──┤── Semaine 1 : Sécurité
                                │
Phase 2.1 (Diagnostics)      ──┤── Semaine 2 : SRE
Phase 2.2 (Runbooks)         ──┘

Phase 3.1 (Orchestration)    ──── Semaine 3 : Orchestration

Phase 4.1 (Drift)            ──┐
Phase 4.2 (File advanced)    ──┤── Semaine 4 : DevOps
Phase 4.3 (SBOM)             ──┘

Phase 5.1 (Server Card)      ──┐
Phase 5.2 (DXT)              ──┤── Semaine 5 : Distribution
Phase 5.3 (Release pipeline) ──┘
```

Chaque phase est **indépendante** et peut être livrée séparément. L'ordre est par ROI décroissant.
