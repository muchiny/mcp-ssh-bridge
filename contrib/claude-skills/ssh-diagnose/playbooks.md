# Diagnostic Playbooks

Symptom-specific investigation workflows for ssh-diagnose.

## Playbook: Slow / High Latency

**Goal:** Identify CPU, I/O, or memory bottleneck.

| Step | Command | Look for |
|------|---------|----------|
| 1 | `ssh_diagnose host=HOST` | Load avg > CPU count, high memory usage |
| 2 | `ssh_process_top host=HOST` | Process consuming >80% CPU or memory |
| 3 | `ssh_metrics host=HOST` | iowait > 20% indicates disk bottleneck |
| 4 | `ssh_exec host=HOST command="iostat -x 1 3"` | Disk utilization > 90% |
| 5 | `ssh_exec host=HOST command="vmstat 1 5"` | High si/so = swapping |

**Common causes:** Runaway process, memory leak (swap thrashing), full disk causing I/O stalls, too many connections.

## Playbook: Crash / Restart

**Goal:** Find what crashed and why.

| Step | Command | Look for |
|------|---------|----------|
| 1 | `ssh_exec host=HOST command="last reboot \| head -5"` | Unexpected reboots |
| 2 | `ssh_exec host=HOST command="journalctl -p crit --since '24 hours ago' --no-pager"` | Critical errors |
| 3 | `ssh_service_list host=HOST` | Failed services |
| 4 | `ssh_exec host=HOST command="coredumpctl list 2>/dev/null \| tail -10"` | Core dumps |
| 5 | `ssh_exec host=HOST command="dmesg \| grep -i -E 'panic\|oom\|kill\|error' \| tail -20"` | Kernel issues |

**Common causes:** OOM killer, kernel panic, watchdog timeout, power loss, segfault.

## Playbook: OOM / Memory

**Goal:** Identify memory hog and prevent recurrence.

| Step | Command | Look for |
|------|---------|----------|
| 1 | `ssh_exec host=HOST command="free -h"` | Used vs available, swap usage |
| 2 | `ssh_exec host=HOST command="dmesg \| grep -i oom \| tail -10"` | OOM killer events |
| 3 | `ssh_process_top host=HOST` | Top memory consumers |
| 4 | `ssh_exec host=HOST command="cat /proc/meminfo \| head -20"` | Cached, buffers, slab |
| 5 | `ssh_exec host=HOST command="slabtop -o -s c \| head -15"` | Kernel slab leaks |

**Common causes:** Memory leak in app, too many worker processes, insufficient swap, no memory limits on containers.

## Playbook: Disk Full

**Goal:** Find what filled the disk and free space.

| Step | Command | Look for |
|------|---------|----------|
| 1 | `ssh_disk_usage host=HOST` | Partitions > 90% |
| 2 | `ssh_exec host=HOST command="df -i"` | Inode exhaustion (100%) |
| 3 | `ssh_exec host=HOST command="du -sh /* 2>/dev/null \| sort -rh \| head -10"` | Largest directories |
| 4 | `ssh_exec host=HOST command="find /var/log -type f -size +100M 2>/dev/null"` | Large log files |
| 5 | `ssh_exec host=HOST command="docker system df 2>/dev/null"` | Docker disk usage |

**Common causes:** Unrotated logs, Docker images/volumes, old backups, /tmp not cleaned, package cache.

## Playbook: Network Issues

**Goal:** Identify connectivity or port/firewall problems.

| Step | Command | Look for |
|------|---------|----------|
| 1 | `ssh_net_interfaces host=HOST` | Interface down, no IP |
| 2 | `ssh_net_connections host=HOST` | ESTABLISHED/TIME_WAIT counts |
| 3 | `ssh_exec host=HOST command="ss -tlnp"` | Expected ports listening |
| 4 | `ssh_exec host=HOST command="cat /proc/net/dev \| column -t"` | Dropped packets, errors |
| 5 | `ssh_firewall_list host=HOST` | Blocked ports |
| 6 | `ssh_net_dns host=HOST` | DNS resolution working |

**Common causes:** DNS failure, firewall blocking, port not listening, too many connections (FD limit), NIC errors.
