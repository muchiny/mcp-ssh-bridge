---
name: ssh-deploy
description: Deploy to remote hosts — rolling updates, canary releases, K8s rollouts, service restarts. Manual-only for safety.
disable-model-invocation: true
argument-hint: <host> <action>
---

# Deployment Operations

Deploy changes to remote infrastructure via mcp-ssh-bridge CLI.
This skill is **manual-only** — invoke with `/ssh-deploy`.

**Host:** `$0`
**Action:** `$1` (restart, canary, rolling, k8s, helm)

## Pre-Deploy Checklist

Before ANY deployment, verify:

1. **Health check** — confirm the target is healthy BEFORE changing anything:
   ```bash
   mcp-ssh-bridge tool ssh_diagnose host=$0 --json
   ```

2. **Confirm with user** — always ask before proceeding with destructive operations.

3. **Know the rollback** — have a rollback command ready before executing.

## Deployment Patterns

### Service Restart

```bash
# Check current status
mcp-ssh-bridge tool ssh_service_status host=$0 service=SERVICE --json

# Restart
mcp-ssh-bridge tool ssh_service_restart host=$0 service=SERVICE

# Verify recovery
mcp-ssh-bridge tool ssh_service_status host=$0 service=SERVICE --json
```

### Canary Deploy

Deploy to a single canary host first, verify, then decide:

```bash
# Execute on canary
mcp-ssh-bridge tool ssh_canary_exec host=$0 command="DEPLOY_COMMAND"

# Health check canary
mcp-ssh-bridge tool ssh_diagnose host=$0 --json

# ASK the user before continuing to remaining hosts
```

### Rolling Deploy

Execute on one host at a time with health checks between:

```bash
mcp-ssh-bridge tool ssh_rolling_exec host=$0 command="DEPLOY_COMMAND"
```

### Kubernetes Rollout

```bash
# Check current state
mcp-ssh-bridge tool ssh_k8s_get host=$0 resource=deployments namespace=NAMESPACE --json

# Apply update
mcp-ssh-bridge tool ssh_k8s_apply host=$0 manifest="PATH_TO_YAML" namespace=NAMESPACE

# Watch rollout
mcp-ssh-bridge tool ssh_k8s_rollout host=$0 action=status deployment=DEPLOYMENT namespace=NAMESPACE

# Rollback if needed
mcp-ssh-bridge tool ssh_k8s_rollout host=$0 action=undo deployment=DEPLOYMENT namespace=NAMESPACE
```

### Helm Upgrade

```bash
# Check current release
mcp-ssh-bridge tool ssh_helm_status host=$0 release=RELEASE --json

# Upgrade
mcp-ssh-bridge tool ssh_helm_upgrade host=$0 release=RELEASE chart=CHART

# Verify
mcp-ssh-bridge tool ssh_helm_status host=$0 release=RELEASE --json

# Rollback if needed
mcp-ssh-bridge tool ssh_helm_rollback host=$0 release=RELEASE
```

## Post-Deploy

After every deployment:

1. **Health check** — verify the system is healthy:
   ```bash
   mcp-ssh-bridge tool ssh_diagnose host=$0 --json
   ```

2. **Verify service** — check the specific service/app is running:
   ```bash
   mcp-ssh-bridge tool ssh_service_status host=$0 service=SERVICE --json
   ```

3. **Report** — tell the user: what was deployed, current status, rollback command if needed.
