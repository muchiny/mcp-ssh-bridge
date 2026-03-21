# Recherche Approfondie : Features Manquantes pour MCP SSH Bridge

> Date: 2026-03-21 | Analyse comparative avec l'écosystème MCP, les concurrents, et l'état de l'art

---

## INVENTAIRE ACTUEL

Votre projet est **déjà très avancé** :

| Catégorie | Status |
|---|---|
| **262 tools** across 47 groups (34 Linux, 13 Windows) | ✅ |
| MCP Resources (6 : health, history, log, metrics, services, file) | ✅ |
| MCP Prompts (7 : deploy, docker_health, k8s_overview, security_audit, system_health, troubleshoot, backup_verify) | ✅ |
| MCP Sampling (server-initiated LLM calls) | ✅ |
| MCP Elicitation (user input requests) | ✅ |
| MCP Progress (notifications/progress) | ✅ |
| MCP Logging (notifications/message) | ✅ |
| MCP Completions (argument auto-completion) | ✅ |
| MCP Tasks (background tasks with get/list/cancel/result) | ✅ |
| OAuth 2.0 / JWT auth on HTTP transport | ✅ |
| Transports: stdio + HTTP/SSE | ✅ |
| Config hot-reload (watcher + list_changed notifications) | ✅ |
| Apps (Dashboard, Table, Form, Chart builders) | ✅ |
| SSH: connection pool, sessions, tunnels, retry, ProxyJump, SOCKS proxy | ✅ |
| Security: blacklist, sanitization, rate limiting, audit, RBAC | ✅ |
| Docker, K8s, Helm, Ansible, Terraform, Vault, ESXi, Podman | ✅ |
| Windows: AD, IIS, Hyper-V, Registry, Events, Services | ✅ |
| Network Equipment (Cisco-style show commands) | ✅ |
| LDAP, Let's Encrypt, MongoDB, Redis, PostgreSQL, MySQL | ✅ |

---

## FEATURES MANQUANTES IDENTIFIÉES

### 🔴 PRIORITÉ HAUTE — Différenciateurs concurrentiels

#### 1. **MCP Structured Output (JSON Schema responses)**
- **Quoi** : La spec MCP 2025-03-26 ajoute `structuredContent` aux résultats d'outils — le serveur retourne des données structurées (JSON Schema validé) en plus du `content` texte.
- **Pourquoi** : Permet à Claude de parser les résultats de façon fiable (pas de regex sur du texte). Critique pour l'intégration dans des pipelines automatisés.
- **Impact** : Les tools comme `ssh_k8s_get`, `ssh_docker_ps`, `ssh_metrics` pourraient retourner du JSON structuré + texte lisible.

#### 2. **Multi-Host Orchestration Intelligente (Fan-out/Fan-in)**
- **Quoi** : Exécuter une commande/workflow sur N hosts en parallèle avec agrégation des résultats, diff entre hosts, et détection d'anomalies.
- **Pourquoi** : Ansible fait ça. `ssh_exec_multi` existe mais c'est basique. Il manque : rolling updates, canary execution (1 host d'abord, puis les autres si OK), result diffing, conditional execution.
- **Concurrents** : Ansible, Fabric, pdsh, pssh, Rundeck — tous offrent du fan-out avancé.
- **Features à ajouter** :
  - `ssh_orchestrate` — workflow multi-step multi-host avec stratégie (serial, parallel, canary)
  - `ssh_fleet_diff` — exécuter et comparer les résultats entre hosts (détecter la config drift)
  - `ssh_rolling_exec` — rolling execution avec rollback automatique si erreur

#### 3. **Runbook Engine / Workflow Automation**
- **Quoi** : Définir et exécuter des runbooks YAML (séquences d'opérations avec conditions, boucles, rollback).
- **Pourquoi** : C'est le coeur de Rundeck, StackStorm, PagerDuty Runbook Automation. Un MCP SSH Bridge sans runbooks est un "couteau sans manche" pour le SRE.
- **Features** :
  - `ssh_runbook_list` — lister les runbooks disponibles
  - `ssh_runbook_execute` — exécuter un runbook avec paramètres
  - `ssh_runbook_status` — suivre l'exécution en cours
  - Template de runbooks pour incidents communs (disk full, OOM, service crash, cert expiry)
  - Intégration avec MCP Tasks pour le suivi async

#### 4. **Intelligent Diagnostics / Root Cause Analysis**
- **Quoi** : Toolchain automatisée de diagnostic qui combine multiple checks en un seul appel intelligent.
- **Pourquoi** : Au lieu que Claude fasse 15 appels séquentiels (check CPU → check mem → check disk → check logs → check services...), un outil intelligent le fait en un shot.
- **Features** :
  - `ssh_diagnose` — diagnostic complet d'un host (CPU, RAM, disk, load, top processes, failed services, recent errors, OOM kills, disk SMART)
  - `ssh_incident_triage` — triage automatique d'un incident (corrèle logs, metrics, et état services)
  - `ssh_compare_state` — comparer l'état actuel vs un baseline connu

#### 5. ~~SSH Jump Host / Bastion / ProxyJump~~ ✅ DÉJÀ IMPLÉMENTÉ
- ProxyJump + SOCKS4/SOCKS5 proxy déjà supportés dans `src/ssh/` et `src/config/types.rs`.
- **Amélioration possible** : Support des chaînes multi-hop (bastion1 → bastion2 → target) si pas déjà fait.

#### 6. **Streamable HTTP Transport (MCP 2025-03-26)**
- **Quoi** : Nouveau transport MCP qui remplace SSE. Un seul endpoint HTTP, bidirectionnel, supporte resumability.
- **Pourquoi** : C'est le futur du MCP. SSE est "legacy". Les clients modernes vont migrer vers Streamable HTTP.
- **Features** : Session management, resumability (Mcp-Session-Id), request batching.

---

### 🟠 PRIORITÉ MOYENNE — Features attendues par le marché

#### 7. **File Diff & Patch**
- **Quoi** : Outils pour comparer des fichiers, générer des diffs, et appliquer des patches à distance.
- **Features** :
  - `ssh_file_diff` — diff entre 2 fichiers (même host ou cross-host)
  - `ssh_file_patch` — appliquer un patch/diff
  - `ssh_file_template` — rendre un template Jinja2/Handlebars avec des variables
  - `ssh_file_search` — grep/ripgrep à distance avec contexte

#### 8. **Session Recording & Replay**
- **Quoi** : Enregistrer toutes les commandes et outputs dans un format rejouable (asciinema-like).
- **Pourquoi** : Compliance (SOC2, HIPAA, PCI-DSS), audit post-incident, training.
- **Features** :
  - `ssh_recording_start` / `ssh_recording_stop` — enregistrer une session
  - `ssh_recording_list` / `ssh_recording_replay` — lister et rejouer
  - Export en format asciinema v2 ou JSON structuré
  - Masquage automatique des secrets dans les recordings

#### 9. **Secrets Detection & Masking**
- **Quoi** : Détecter automatiquement les secrets dans les outputs (tokens, passwords, API keys, private keys) et les masquer.
- **Pourquoi** : Le sanitizer actuel est basique. Des outils comme gitleaks, truffleHog, detect-secrets font ça beaucoup mieux.
- **Features** :
  - Détection par regex patterns (AWS keys, JWT, private keys, connection strings)
  - Détection par entropie (strings à haute entropie = probable secret)
  - Masquage configurable (remplacer par `***REDACTED***`)
  - Whitelist pour les faux positifs

#### 10. **Container Log Analysis**
- **Quoi** : Outils spécialisés pour analyser les logs de containers Docker/K8s (pas juste `docker logs`).
- **Features** :
  - `ssh_container_log_search` — chercher dans les logs avec filtres avancés (time range, severity, pattern)
  - `ssh_container_log_stats` — statistiques sur les logs (error rate, top errors, frequency)
  - `ssh_container_events` — événements Docker/K8s (restarts, OOM kills, evictions)
  - `ssh_container_health_history` — historique des health checks

#### 11. **SBOM & Vulnerability Scanning**
- **Quoi** : Inventaire logiciel et scan de vulnérabilités sur les hosts distants.
- **Features** :
  - `ssh_sbom_generate` — générer un SBOM (packages installés, versions)
  - `ssh_vuln_scan` — scanner les vulnérabilités connues (CVE) contre les packages installés
  - `ssh_compliance_check` — vérifier la conformité (CIS benchmarks, STIG)

#### 12. **Cloud Provider Integration**
- **Quoi** : Outils pour interagir avec les APIs cloud (AWS, GCP, Azure) via le SSH host.
- **Features** :
  - `ssh_aws_cli` — exécuter des commandes AWS CLI
  - `ssh_cloud_metadata` — récupérer les métadonnées de l'instance
  - `ssh_cloud_tags` — lire/écrire les tags cloud
  - `ssh_cloud_cost` — coûts de l'instance

#### 13. **Intelligent Cron/Job Analysis**
- **Quoi** : Au-delà de `ssh_cron_list`, analyser les jobs planifiés pour détecter les problèmes.
- **Features** :
  - `ssh_cron_analyze` — détecter overlaps, jobs qui échouent silencieusement, jobs qui ne s'exécutent jamais
  - `ssh_cron_history` — historique d'exécution des crons (via syslog/journal)
  - `ssh_at_jobs` — gérer les jobs `at` en plus de cron

#### 14. **Network Security Analysis**
- **Quoi** : Outils de sécurité réseau avancés.
- **Features** :
  - `ssh_port_scan` — scanner les ports ouverts sur le host (nmap-like)
  - `ssh_ssl_audit` — auditer la configuration TLS/SSL d'un service
  - `ssh_network_capture` — capture de paquets limitée (tcpdump avec timeout et filtres)
  - `ssh_fail2ban_status` — état de fail2ban/denyhosts

#### 15. **Performance Profiling**
- **Quoi** : Outils de profiling système avancés.
- **Features** :
  - `ssh_perf_trace` — tracer les syscalls d'un process (strace-like, limité en durée)
  - `ssh_io_trace` — tracer les I/O (iotop/blktrace)
  - `ssh_latency_test` — tester la latence réseau/disque
  - `ssh_benchmark` — benchmarks rapides (CPU, I/O, réseau)

---

### 🟡 PRIORITÉ BASSE — Nice-to-have / Innovation

#### 16. **MCP Roots Support**
- **Quoi** : Implémenter le support des MCP Roots pour restreindre les opérations fichiers aux répertoires déclarés par le client.
- **Status** : Partiellement implémenté (instructions mentionnent ROOTS) mais pas clair si c'est vraiment enforced.

#### 17. **Interactive Terminal (Pseudo-PTY)**
- **Quoi** : Mode terminal interactif via SSH (PTY allocation) pour les commandes qui nécessitent un terminal.
- **Pourquoi** : Certaines commandes (vim, top interactif, passwd) nécessitent un PTY. Rare mais parfois nécessaire.
- **Limitation** : Difficile avec le modèle MCP request/response. Possible via Resources en streaming.

#### 18. **Configuration Templates Library**
- **Quoi** : Bibliothèque de templates de configuration pour services communs.
- **Features** :
  - Templates Nginx, Apache, PostgreSQL, MySQL, Redis
  - Génération de configs sécurisées (best practices)
  - Validation de configs avant application

#### 19. **Host Discovery & Inventory**
- **Quoi** : Découvrir automatiquement les hosts dans un réseau (scan, DNS, cloud API).
- **Features** :
  - `ssh_discover_hosts` — scanner un subnet pour les hosts SSH
  - `ssh_inventory_sync` — synchroniser l'inventaire depuis AWS/GCP/Azure
  - `ssh_host_tags` — taguer les hosts pour filtrage

#### 20. **Alerting & Thresholds**
- **Quoi** : Définir des seuils sur les métriques et envoyer des alertes.
- **Features** :
  - `ssh_alert_set` — définir un seuil (CPU > 90%, disk > 85%)
  - `ssh_alert_list` — lister les alertes actives
  - `ssh_alert_check` — vérifier tous les seuils maintenant
  - Intégration avec MCP Notifications pour les alertes

#### 21. **Environment Diff / Drift Detection**
- **Quoi** : Comparer la configuration de 2 environnements (staging vs prod, old vs new).
- **Features** :
  - `ssh_env_snapshot` — snapshot complet d'un host (packages, configs, services, users)
  - `ssh_env_diff` — comparer 2 snapshots
  - `ssh_env_drift` — détecter la dérive vs un state désiré

#### 22. **Log Forwarding & Aggregation**
- **Quoi** : Agréger les logs de multiple hosts en un seul stream.
- **Features** :
  - `ssh_log_aggregate` — collecter les logs de N hosts avec un filtre
  - `ssh_log_correlate` — corréler des événements entre hosts par timestamp

#### 23. **Database Migration Tools**
- **Quoi** : Au-delà de query/dump/restore, des outils de migration.
- **Features** :
  - `ssh_db_migrate` — exécuter des migrations (flyway, liquibase style)
  - `ssh_db_compare` — comparer les schémas entre 2 bases
  - `ssh_db_slow_queries` — analyser les slow queries

#### 24. **Webhook / Callback Support**
- **Quoi** : Permettre de déclencher des webhooks quand certains événements se produisent.
- **Pourquoi** : Intégration avec Slack, PagerDuty, Opsgenie, etc.

#### 25. **Multi-Cloud / Hybrid Support**
- **Quoi** : Outils spécialisés pour les environnements hybrides.
- **Features** :
  - Support WinRM en plus de SSH pour Windows
  - Support de SSM (AWS Systems Manager) comme transport alternatif
  - Support de Azure Bastion / GCP IAP tunnels

---

## COMPARAISON AVEC LES CONCURRENTS MCP

| Feature | Votre Projet | mcp-server-ssh (basique) | Warp AI | Fabric AI |
|---|---|---|---|---|
| Nombre de tools | **262** | ~5 | N/A | N/A |
| MCP Resources | ✅ (6) | ❌ | N/A | N/A |
| MCP Prompts | ✅ (7) | ❌ | N/A | N/A |
| MCP Sampling | ✅ | ❌ | N/A | N/A |
| MCP Elicitation | ✅ | ❌ | N/A | N/A |
| MCP Tasks | ✅ | ❌ | N/A | N/A |
| Structured Output | ❌ | ❌ | N/A | N/A |
| Runbook Engine | ❌ | ❌ | ❌ | ❌ |
| Multi-host Orchestration | Basique | ❌ | ❌ | ✅ |
| Jump Host/Bastion | ✅ | ❌ | ❌ | N/A |
| Session Recording | ❌ | ❌ | ✅ | ❌ |
| Secrets Masking | Basique | ❌ | ❌ | ❌ |
| Streamable HTTP | ❌ | ❌ | N/A | N/A |

---

## TOP 10 RECOMMANDATIONS (par ROI)

| # | Feature | Effort | Impact | ROI |
|---|---|---|---|---|
| 1 | **Intelligent Diagnostics** (`ssh_diagnose`) | Moyen | Très élevé | 🔥🔥🔥🔥🔥 |
| 2 | **Runbook Engine** | Élevé | Très élevé | 🔥🔥🔥🔥🔥 |
| 3 | **Structured Output** (MCP spec) | Faible | Élevé | 🔥🔥🔥🔥 |
| 4 | **Advanced Multi-Host** (canary, rolling, diff) | Moyen | Élevé | 🔥🔥🔥🔥 |
| 5 | **Secrets Detection avancée** | Faible | Élevé (sécurité) | 🔥🔥🔥🔥 |
| 6 | **Streamable HTTP Transport** | Moyen | Élevé (future-proof) | 🔥🔥🔥🔥 |
| 7 | **Session Recording** | Moyen | Élevé (compliance) | 🔥🔥🔥 |
| 8 | **File Diff/Patch/Template** | Faible | Moyen | 🔥🔥🔥 |
| 9 | **Environment Drift Detection** | Moyen | Élevé (DevOps) | 🔥🔥🔥 |
| 10 | **SBOM & Vulnerability Scanning** | Moyen | Élevé (sécurité) | 🔥🔥🔥 |

---

## CONCLUSION

Votre stack est **déjà dans le top 1%** des serveurs MCP en termes de complétude. Vous avez implémenté des features MCP avancées (Sampling, Elicitation, Tasks, Apps) que quasi aucun autre serveur n'a.

Les gaps principaux sont :
1. **Opérationnel** : Jump hosts, runbooks, diagnostics intelligents — ce qui transforme l'outil d'un "remote executor" en un vrai "AI SRE platform"
2. **Protocole** : Structured Output et Streamable HTTP pour rester à jour avec la spec MCP
3. **Sécurité** : Secrets detection avancée et session recording pour la compliance enterprise
4. **Orchestration** : Passer de "exécuter sur N hosts" à "orchestrer des workflows sur N hosts"
