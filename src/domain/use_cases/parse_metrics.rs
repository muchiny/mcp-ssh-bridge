//! System Metrics Parsing
//!
//! Pure parsing functions that transform raw Linux command output
//! into structured metric types. No I/O — only string parsing.

use serde::Serialize;

/// Separator used between metric sections in the compound command output
pub const SECTION_SEPARATOR: &str = "---METRIC_SEP---";

/// Structured system metrics
#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<Vec<DiskMetrics>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Vec<NetworkMetrics>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<LoadMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuMetrics {
    pub cores: u32,
    pub user_percent: f64,
    pub system_percent: f64,
    pub idle_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskMetrics {
    pub filesystem: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkMetrics {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadMetrics {
    pub load_1min: f64,
    pub load_5min: f64,
    pub load_15min: f64,
    pub uptime_seconds: u64,
}

/// Parse CPU metrics from `/proc/stat` first line + `nproc` output.
///
/// Expected input format:
/// ```text
/// cpu  12345 678 9012 345678 ...
/// 4
/// ```
#[must_use]
pub fn parse_cpu(raw: &str) -> Option<CpuMetrics> {
    let mut lines = raw.lines();
    let cpu_line = lines.next()?;
    let nproc_line = lines.next().unwrap_or("1");

    let cores: u32 = nproc_line.trim().parse().unwrap_or(1);

    let parts: Vec<&str> = cpu_line.split_whitespace().collect();
    if parts.len() < 5 || parts[0] != "cpu" {
        return None;
    }

    let user: f64 = parts[1].parse().ok()?;
    let nice: f64 = parts[2].parse().ok()?;
    let system: f64 = parts[3].parse().ok()?;
    let idle: f64 = parts[4].parse().ok()?;
    let iowait: f64 = parts.get(5).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let irq: f64 = parts.get(6).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let softirq: f64 = parts.get(7).and_then(|v| v.parse().ok()).unwrap_or(0.0);

    let total = user + nice + system + idle + iowait + irq + softirq;
    if total == 0.0 {
        return None;
    }

    Some(CpuMetrics {
        cores,
        user_percent: round2((user + nice) / total * 100.0),
        system_percent: round2((system + irq + softirq) / total * 100.0),
        idle_percent: round2(idle / total * 100.0),
    })
}

/// Parse memory metrics from `free -b` output.
///
/// Expected format:
/// ```text
///               total        used        free      shared  buff/cache   available
/// Mem:    16384000000  8192000000  4096000000      123456  4096000000  7168000000
/// Swap:    2048000000   512000000  1536000000
/// ```
#[must_use]
pub fn parse_memory(raw: &str) -> Option<MemoryMetrics> {
    let mut mem_total = 0u64;
    let mut mem_used = 0u64;
    let mut mem_available = 0u64;
    let mut swap_total = 0u64;
    let mut swap_used = 0u64;

    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with("Mem:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                mem_total = parts[1].parse().unwrap_or(0);
                mem_used = parts[2].parse().unwrap_or(0);
                mem_available = parts.get(6).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        } else if line.starts_with("Swap:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                swap_total = parts[1].parse().unwrap_or(0);
                swap_used = parts[2].parse().unwrap_or(0);
            }
        }
    }

    if mem_total == 0 {
        return None;
    }

    #[allow(clippy::cast_precision_loss)]
    let usage_percent = round2(mem_used as f64 / mem_total as f64 * 100.0);

    Some(MemoryMetrics {
        total_bytes: mem_total,
        used_bytes: mem_used,
        available_bytes: mem_available,
        usage_percent,
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_used,
    })
}

/// Parse disk metrics from `df -B1` output.
///
/// Expected format:
/// ```text
/// Filesystem     1B-blocks         Used    Available Use% Mounted on
/// /dev/sda1    107374182400  53687091200  48318382080  53% /
/// tmpfs          8388608000            0   8388608000   0% /dev/shm
/// ```
#[must_use]
pub fn parse_disk(raw: &str) -> Option<Vec<DiskMetrics>> {
    let mut disks = Vec::new();

    for line in raw.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let filesystem = parts[0];
        // Skip pseudo-filesystems
        if filesystem == "tmpfs"
            || filesystem == "devtmpfs"
            || filesystem == "none"
            || filesystem.starts_with("overlay")
        {
            continue;
        }

        let total: u64 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let used: u64 = parts[2].parse().unwrap_or(0);
        let available: u64 = parts[3].parse().unwrap_or(0);
        let percent_str = parts[4].trim_end_matches('%');
        let usage_percent: f64 = percent_str.parse().unwrap_or(0.0);

        disks.push(DiskMetrics {
            filesystem: filesystem.to_string(),
            mount_point: parts[5].to_string(),
            total_bytes: total,
            used_bytes: used,
            available_bytes: available,
            usage_percent,
        });
    }

    if disks.is_empty() { None } else { Some(disks) }
}

/// Parse network metrics from `/proc/net/dev` output.
///
/// Expected format:
/// ```text
/// Inter-|   Receive                                                |  Transmit
///  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets ...
///   eth0: 12345678 1234 0 0 0 0 0 0 87654321 4321 0 0 0 0 0 0
///     lo:     5678    90 0 0 0 0 0 0     5678   90 0 0 0 0 0 0
/// ```
#[must_use]
pub fn parse_network(raw: &str) -> Option<Vec<NetworkMetrics>> {
    let mut interfaces = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if !line.contains(':') || line.starts_with("Inter") || line.starts_with("face") {
            continue;
        }

        let (iface, rest) = line.split_once(':')?;
        let iface = iface.trim();

        // Skip loopback
        if iface == "lo" {
            continue;
        }

        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let rx_bytes: u64 = parts[0].parse().unwrap_or(0);
        let tx_bytes: u64 = parts[8].parse().unwrap_or(0);

        interfaces.push(NetworkMetrics {
            interface: iface.to_string(),
            rx_bytes,
            tx_bytes,
        });
    }

    if interfaces.is_empty() {
        None
    } else {
        Some(interfaces)
    }
}

/// Parse load metrics from `/proc/loadavg` + `/proc/uptime` output.
///
/// Expected format:
/// ```text
/// 1.23 0.45 0.67 1/234 5678
/// 12345.67 98765.43
/// ```
#[must_use]
#[allow(clippy::similar_names)]
pub fn parse_load(raw: &str) -> Option<LoadMetrics> {
    let mut lines = raw.lines();
    let loadavg_line = lines.next()?;
    let uptime_line = lines.next().unwrap_or("0");

    let parts: Vec<&str> = loadavg_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let load_1min: f64 = parts[0].parse().ok()?;
    let load_5min: f64 = parts[1].parse().ok()?;
    let load_15min: f64 = parts[2].parse().ok()?;

    let uptime_parts: Vec<&str> = uptime_line.split_whitespace().collect();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let uptime_seconds: u64 = uptime_parts
        .first()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;

    Some(LoadMetrics {
        load_1min,
        load_5min,
        load_15min,
        uptime_seconds,
    })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== CPU Tests ==============

    #[test]
    fn test_parse_cpu() {
        let raw = "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n";
        let cpu = parse_cpu(raw).unwrap();
        assert_eq!(cpu.cores, 4);
        assert!(cpu.user_percent > 0.0);
        assert!(cpu.system_percent > 0.0);
        assert!(cpu.idle_percent > 0.0);
        let total = cpu.user_percent + cpu.system_percent + cpu.idle_percent;
        assert!(total > 90.0);
    }

    #[test]
    fn test_parse_cpu_invalid() {
        assert!(parse_cpu("").is_none());
        assert!(parse_cpu("not cpu data").is_none());
    }

    #[test]
    fn test_parse_cpu_minimal_fields() {
        let raw = "cpu  10000 500 3000 86000\n2\n";
        let cpu = parse_cpu(raw).unwrap();
        assert_eq!(cpu.cores, 2);
        assert!(cpu.idle_percent > 0.0);
    }

    #[test]
    fn test_parse_cpu_missing_nproc() {
        let raw = "cpu  10000 500 3000 86000 200 100 200 0 0 0\n";
        let cpu = parse_cpu(raw).unwrap();
        assert_eq!(cpu.cores, 1);
    }

    #[test]
    fn test_parse_cpu_invalid_nproc() {
        let raw = "cpu  10000 500 3000 86000 200 100 200 0 0 0\nabc\n";
        let cpu = parse_cpu(raw).unwrap();
        assert_eq!(cpu.cores, 1);
    }

    #[test]
    fn test_parse_cpu_zero_total() {
        let raw = "cpu  0 0 0 0 0 0 0 0 0 0\n4\n";
        assert!(parse_cpu(raw).is_none());
    }

    #[test]
    fn test_parse_cpu_high_core_count() {
        let raw = "cpu  10000 500 3000 86000 200 100 200 0 0 0\n256\n";
        let cpu = parse_cpu(raw).unwrap();
        assert_eq!(cpu.cores, 256);
    }

    #[test]
    fn test_parse_cpu_too_few_fields() {
        let raw = "cpu  10000 500 3000\n4\n";
        assert!(parse_cpu(raw).is_none());
    }

    #[test]
    fn test_parse_cpu_wrong_prefix() {
        let raw = "cpus 10000 500 3000 86000 200 100 200 0 0 0\n4\n";
        assert!(parse_cpu(raw).is_none());
    }

    // ============== Memory Tests ==============

    #[test]
    fn test_parse_memory() {
        let raw = "\
              total        used        free      shared  buff/cache   available
Mem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000
Swap:    2000000000   500000000  1500000000";
        let mem = parse_memory(raw).unwrap();
        assert_eq!(mem.total_bytes, 16_000_000_000);
        assert_eq!(mem.used_bytes, 8_000_000_000);
        assert_eq!(mem.available_bytes, 7_000_000_000);
        assert_eq!(mem.swap_total_bytes, 2_000_000_000);
        assert_eq!(mem.swap_used_bytes, 500_000_000);
        assert!((mem.usage_percent - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_parse_memory_invalid() {
        assert!(parse_memory("").is_none());
        assert!(parse_memory("header only\n").is_none());
    }

    #[test]
    fn test_parse_memory_no_swap() {
        let raw = "\
              total        used        free      shared  buff/cache   available
Mem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000";
        let mem = parse_memory(raw).unwrap();
        assert_eq!(mem.swap_total_bytes, 0);
        assert_eq!(mem.swap_used_bytes, 0);
    }

    #[test]
    fn test_parse_memory_zero_total() {
        let raw = "\
              total        used        free      shared  buff/cache   available
Mem:    0  0  0      0  0  0";
        assert!(parse_memory(raw).is_none());
    }

    #[test]
    fn test_parse_memory_minimal_fields() {
        let raw = "Mem:    16000000000  8000000000  4000000000";
        let mem = parse_memory(raw).unwrap();
        assert_eq!(mem.total_bytes, 16_000_000_000);
        assert_eq!(mem.available_bytes, 0);
    }

    #[test]
    fn test_parse_memory_100_percent() {
        let raw = "\
              total        used        free      shared  buff/cache   available
Mem:    1000  1000  0      0  0  0
Swap:    0   0  0";
        let mem = parse_memory(raw).unwrap();
        assert!((mem.usage_percent - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_parse_memory_whitespace() {
        let raw =
            "   Mem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000   ";
        let mem = parse_memory(raw).unwrap();
        assert_eq!(mem.total_bytes, 16_000_000_000);
    }

    // ============== Disk Tests ==============

    #[test]
    fn test_parse_disk() {
        let raw = "\
Filesystem     1B-blocks         Used    Available Use% Mounted on
/dev/sda1    107374182400  53687091200  48318382080  53% /
tmpfs          8388608000            0   8388608000   0% /dev/shm
/dev/sdb1     53687091200  21474836480  29802322944  42% /data";
        let disks = parse_disk(raw).unwrap();
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].mount_point, "/");
        assert!((disks[0].usage_percent - 53.0).abs() < 0.1);
        assert_eq!(disks[1].mount_point, "/data");
    }

    #[test]
    fn test_parse_disk_empty() {
        assert!(parse_disk("Filesystem\n").is_none());
    }

    #[test]
    fn test_parse_disk_filters_pseudo() {
        let raw = "\
Filesystem     1B-blocks         Used    Available Use% Mounted on
tmpfs          8388608000            0   8388608000   0% /dev/shm
devtmpfs       8388608000            0   8388608000   0% /dev
none           8388608000            0   8388608000   0% /sys
overlay1       8388608000            0   8388608000   0% /var/lib";
        assert!(parse_disk(raw).is_none());
    }

    #[test]
    fn test_parse_disk_100_percent() {
        let raw = "\
Filesystem     1B-blocks         Used    Available Use% Mounted on
/dev/sda1    100000  100000  0  100% /";
        let disks = parse_disk(raw).unwrap();
        assert!((disks[0].usage_percent - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_parse_disk_0_percent() {
        let raw = "\
Filesystem     1B-blocks         Used    Available Use% Mounted on
/dev/sda1    100000  0  100000  0% /";
        let disks = parse_disk(raw).unwrap();
        assert!((disks[0].usage_percent - 0.0).abs() < 0.1);
    }

    #[test]
    fn test_parse_disk_invalid_size() {
        let raw = "\
Filesystem     1B-blocks         Used    Available Use% Mounted on
/dev/sda1    invalid  50000  50000  50% /";
        assert!(parse_disk(raw).is_none());
    }

    // ============== Network Tests ==============

    #[test]
    fn test_parse_network() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 12345678   1234    0    0    0     0          0         0 87654321   4321    0    0    0     0       0          0
    lo:     5678     90    0    0    0     0          0         0     5678     90    0    0    0     0       0          0";
        let nets = parse_network(raw).unwrap();
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].interface, "eth0");
        assert_eq!(nets[0].rx_bytes, 12_345_678);
        assert_eq!(nets[0].tx_bytes, 87_654_321);
    }

    #[test]
    fn test_parse_network_empty() {
        assert!(parse_network("Inter-|\n face |\n").is_none());
    }

    #[test]
    fn test_parse_network_multiple_interfaces() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 12345678   1234    0    0    0     0          0         0 87654321   4321    0    0    0     0       0          0
  eth1: 11111111   1111    0    0    0     0          0         0 22222222   2222    0    0    0     0       0          0
 wlan0: 33333333   3333    0    0    0     0          0         0 44444444   4444    0    0    0     0       0          0";
        let nets = parse_network(raw).unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0].interface, "eth0");
        assert_eq!(nets[1].interface, "eth1");
        assert_eq!(nets[2].interface, "wlan0");
    }

    #[test]
    fn test_parse_network_filters_loopback() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     5678     90    0    0    0     0          0         0     5678     90    0    0    0     0       0          0";
        assert!(parse_network(raw).is_none());
    }

    #[test]
    fn test_parse_network_zero_bytes() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 0   0    0    0    0     0          0         0 0   0    0    0    0     0       0          0";
        let nets = parse_network(raw).unwrap();
        assert_eq!(nets[0].rx_bytes, 0);
        assert_eq!(nets[0].tx_bytes, 0);
    }

    #[test]
    fn test_parse_network_large_values() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 18446744073709551615   1234    0    0    0     0          0         0 18446744073709551615   4321    0    0    0     0       0          0";
        let nets = parse_network(raw).unwrap();
        assert_eq!(nets[0].rx_bytes, u64::MAX);
        assert_eq!(nets[0].tx_bytes, u64::MAX);
    }

    // ============== Load Tests ==============

    #[test]
    fn test_parse_load() {
        let raw = "1.23 0.45 0.67 1/234 5678\n12345.67 98765.43\n";
        let load = parse_load(raw).unwrap();
        assert!((load.load_1min - 1.23).abs() < 0.001);
        assert!((load.load_5min - 0.45).abs() < 0.001);
        assert!((load.load_15min - 0.67).abs() < 0.001);
        assert_eq!(load.uptime_seconds, 12345);
    }

    #[test]
    fn test_parse_load_invalid() {
        assert!(parse_load("").is_none());
        assert!(parse_load("abc").is_none());
    }

    #[test]
    fn test_parse_load_high_values() {
        let raw = "100.50 75.25 50.00 1/234 5678\n9999999.99 98765.43\n";
        let load = parse_load(raw).unwrap();
        assert!((load.load_1min - 100.50).abs() < 0.001);
        assert_eq!(load.uptime_seconds, 9_999_999);
    }

    #[test]
    fn test_parse_load_zero_load() {
        let raw = "0.00 0.00 0.00 0/0 0\n0.00 0.00\n";
        let load = parse_load(raw).unwrap();
        assert!((load.load_1min - 0.0).abs() < 0.001);
        assert_eq!(load.uptime_seconds, 0);
    }

    #[test]
    fn test_parse_load_missing_uptime() {
        let raw = "1.23 0.45 0.67 1/234 5678\n";
        let load = parse_load(raw).unwrap();
        assert_eq!(load.uptime_seconds, 0);
    }

    #[test]
    fn test_parse_load_too_few_fields() {
        let raw = "1.23 0.45\n12345.67\n";
        assert!(parse_load(raw).is_none());
    }

    // ============== round2 Tests ==============

    #[test]
    fn test_round2() {
        assert!((round2(1.23456) - 1.23).abs() < 0.001);
        assert!((round2(99.999) - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_round2_zero() {
        assert!((round2(0.0) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_round2_negative() {
        assert!((round2(-1.23456) - -1.23).abs() < 0.001);
    }

    #[test]
    fn test_round2_very_small() {
        assert!((round2(0.001) - 0.0).abs() < 0.01);
        assert!((round2(0.005) - 0.01).abs() < 0.01);
    }

    #[test]
    fn test_round2_large() {
        assert!((round2(12345.6789) - 12345.68).abs() < 0.01);
    }

    // ============== Struct Tests ==============

    #[test]
    fn test_system_metrics_serialization() {
        let metrics = SystemMetrics {
            host: "test".to_string(),
            cpu: None,
            memory: None,
            disk: None,
            network: None,
            load: None,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("\"host\":\"test\""));
        assert!(!json.contains("cpu"));
    }

    #[test]
    fn test_cpu_metrics_clone() {
        let cpu = CpuMetrics {
            cores: 8,
            user_percent: 25.0,
            system_percent: 10.0,
            idle_percent: 65.0,
        };
        let cloned = cpu.clone();
        assert_eq!(cpu.cores, cloned.cores);
        assert!((cpu.user_percent - cloned.user_percent).abs() < 0.001);
    }

    #[test]
    fn test_memory_metrics_clone() {
        let mem = MemoryMetrics {
            total_bytes: 16_000_000_000,
            used_bytes: 8_000_000_000,
            available_bytes: 8_000_000_000,
            usage_percent: 50.0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
        };
        let cloned = mem.clone();
        assert_eq!(mem.total_bytes, cloned.total_bytes);
    }

    #[test]
    fn test_disk_metrics_debug() {
        let disk = DiskMetrics {
            filesystem: "/dev/sda1".to_string(),
            mount_point: "/".to_string(),
            total_bytes: 100_000,
            used_bytes: 50_000,
            available_bytes: 50_000,
            usage_percent: 50.0,
        };
        let debug = format!("{disk:?}");
        assert!(debug.contains("DiskMetrics"));
        assert!(debug.contains("/dev/sda1"));
    }

    #[test]
    fn test_network_metrics_debug() {
        let net = NetworkMetrics {
            interface: "eth0".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
        };
        let debug = format!("{net:?}");
        assert!(debug.contains("NetworkMetrics"));
        assert!(debug.contains("eth0"));
    }

    #[test]
    fn test_load_metrics_debug() {
        let load = LoadMetrics {
            load_1min: 1.0,
            load_5min: 0.5,
            load_15min: 0.25,
            uptime_seconds: 3600,
        };
        let debug = format!("{load:?}");
        assert!(debug.contains("LoadMetrics"));
    }

    #[test]
    fn test_section_separator_constant() {
        assert_eq!(SECTION_SEPARATOR, "---METRIC_SEP---");
    }

    #[test]
    fn test_system_metrics_with_all_fields() {
        let metrics = SystemMetrics {
            host: "server1".to_string(),
            cpu: Some(CpuMetrics {
                cores: 4,
                user_percent: 25.0,
                system_percent: 10.0,
                idle_percent: 65.0,
            }),
            memory: Some(MemoryMetrics {
                total_bytes: 16_000_000_000,
                used_bytes: 8_000_000_000,
                available_bytes: 8_000_000_000,
                usage_percent: 50.0,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            }),
            disk: Some(vec![DiskMetrics {
                filesystem: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                total_bytes: 100_000,
                used_bytes: 50_000,
                available_bytes: 50_000,
                usage_percent: 50.0,
            }]),
            network: Some(vec![NetworkMetrics {
                interface: "eth0".to_string(),
                rx_bytes: 1000,
                tx_bytes: 2000,
            }]),
            load: Some(LoadMetrics {
                load_1min: 1.0,
                load_5min: 0.5,
                load_15min: 0.25,
                uptime_seconds: 3600,
            }),
        };

        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("cpu"));
        assert!(json.contains("memory"));
        assert!(json.contains("disk"));
        assert!(json.contains("network"));
        assert!(json.contains("load"));
    }
}
