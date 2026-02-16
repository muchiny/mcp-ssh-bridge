//! Windows Performance Counter Command Builder
//!
//! Builds `PowerShell` commands for querying Windows performance counters via SSH.
//! Supports CPU, memory, disk, network, and combined overview queries using
//! `Get-Counter` cmdlets.

/// Builds `PowerShell` `Get-Counter` commands for Windows performance monitoring.
pub struct WindowsPerfCommandBuilder;

impl WindowsPerfCommandBuilder {
    /// Build a command to query CPU usage via performance counters.
    ///
    /// Constructs: `Get-Counter '\Processor(_Total)\% Processor Time'
    /// -SampleInterval 1 -MaxSamples 3
    /// | Select-Object -ExpandProperty CounterSamples
    /// | Select-Object Path,CookedValue`
    #[must_use]
    pub fn build_cpu_command() -> String {
        "Get-Counter '\\Processor(_Total)\\% Processor Time' \
         -SampleInterval 1 -MaxSamples 3 \
         | Select-Object -ExpandProperty CounterSamples \
         | Select-Object Path,CookedValue"
            .to_string()
    }

    /// Build a command to query memory usage via performance counters.
    ///
    /// Constructs: `Get-Counter '\Memory\Available MBytes',
    /// '\Memory\% Committed Bytes In Use'
    /// | Select-Object -ExpandProperty CounterSamples
    /// | Select-Object Path,CookedValue`
    #[must_use]
    pub fn build_memory_command() -> String {
        "Get-Counter '\\Memory\\Available MBytes',\
         '\\Memory\\% Committed Bytes In Use' \
         | Select-Object -ExpandProperty CounterSamples \
         | Select-Object Path,CookedValue"
            .to_string()
    }

    /// Build a command to query disk usage via performance counters.
    ///
    /// Constructs: `Get-Counter '\PhysicalDisk(_Total)\% Disk Time',
    /// '\LogicalDisk(*)\Free Megabytes'
    /// | Select-Object -ExpandProperty CounterSamples
    /// | Select-Object Path,CookedValue`
    #[must_use]
    pub fn build_disk_command() -> String {
        "Get-Counter '\\PhysicalDisk(_Total)\\% Disk Time',\
         '\\LogicalDisk(*)\\Free Megabytes' \
         | Select-Object -ExpandProperty CounterSamples \
         | Select-Object Path,CookedValue"
            .to_string()
    }

    /// Build a command to query network usage via performance counters.
    ///
    /// Constructs: `Get-Counter '\Network Interface(*)\Bytes Total/sec'
    /// | Select-Object -ExpandProperty CounterSamples
    /// | Select-Object Path,CookedValue`
    #[must_use]
    pub fn build_network_command() -> String {
        "Get-Counter '\\Network Interface(*)\\Bytes Total/sec' \
         | Select-Object -ExpandProperty CounterSamples \
         | Select-Object Path,CookedValue"
            .to_string()
    }

    /// Build a combined overview command querying CPU, memory, and disk counters.
    ///
    /// Constructs: `Get-Counter '\Processor(_Total)\% Processor Time',
    /// '\Memory\Available MBytes','\Memory\% Committed Bytes In Use',
    /// '\PhysicalDisk(_Total)\% Disk Time'
    /// | Select-Object -ExpandProperty CounterSamples
    /// | Select-Object Path,CookedValue`
    #[must_use]
    pub fn build_overview_command() -> String {
        "Get-Counter '\\Processor(_Total)\\% Processor Time',\
         '\\Memory\\Available MBytes',\
         '\\Memory\\% Committed Bytes In Use',\
         '\\PhysicalDisk(_Total)\\% Disk Time' \
         | Select-Object -ExpandProperty CounterSamples \
         | Select-Object Path,CookedValue"
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_cpu_command ───────────────────────────────────────────

    #[test]
    fn test_cpu_command() {
        let cmd = WindowsPerfCommandBuilder::build_cpu_command();
        assert!(cmd.contains("Get-Counter"));
        assert!(cmd.contains("\\Processor(_Total)\\% Processor Time"));
        assert!(cmd.contains("-SampleInterval 1"));
        assert!(cmd.contains("-MaxSamples 3"));
        assert!(cmd.contains("Select-Object -ExpandProperty CounterSamples"));
        assert!(cmd.contains("Select-Object Path,CookedValue"));
    }

    #[test]
    fn test_cpu_command_counter_path() {
        let cmd = WindowsPerfCommandBuilder::build_cpu_command();
        assert!(cmd.contains("'\\Processor(_Total)\\% Processor Time'"));
    }

    // ── build_memory_command ────────────────────────────────────────

    #[test]
    fn test_memory_command() {
        let cmd = WindowsPerfCommandBuilder::build_memory_command();
        assert!(cmd.contains("Get-Counter"));
        assert!(cmd.contains("\\Memory\\Available MBytes"));
        assert!(cmd.contains("\\Memory\\% Committed Bytes In Use"));
        assert!(cmd.contains("Select-Object -ExpandProperty CounterSamples"));
        assert!(cmd.contains("Select-Object Path,CookedValue"));
    }

    #[test]
    fn test_memory_command_both_counters() {
        let cmd = WindowsPerfCommandBuilder::build_memory_command();
        assert!(cmd.contains("'\\Memory\\Available MBytes'"));
        assert!(cmd.contains("'\\Memory\\% Committed Bytes In Use'"));
    }

    // ── build_disk_command ──────────────────────────────────────────

    #[test]
    fn test_disk_command() {
        let cmd = WindowsPerfCommandBuilder::build_disk_command();
        assert!(cmd.contains("Get-Counter"));
        assert!(cmd.contains("\\PhysicalDisk(_Total)\\% Disk Time"));
        assert!(cmd.contains("\\LogicalDisk(*)\\Free Megabytes"));
        assert!(cmd.contains("Select-Object -ExpandProperty CounterSamples"));
        assert!(cmd.contains("Select-Object Path,CookedValue"));
    }

    #[test]
    fn test_disk_command_both_counters() {
        let cmd = WindowsPerfCommandBuilder::build_disk_command();
        assert!(cmd.contains("'\\PhysicalDisk(_Total)\\% Disk Time'"));
        assert!(cmd.contains("'\\LogicalDisk(*)\\Free Megabytes'"));
    }

    // ── build_network_command ───────────────────────────────────────

    #[test]
    fn test_network_command() {
        let cmd = WindowsPerfCommandBuilder::build_network_command();
        assert!(cmd.contains("Get-Counter"));
        assert!(cmd.contains("\\Network Interface(*)\\Bytes Total/sec"));
        assert!(cmd.contains("Select-Object -ExpandProperty CounterSamples"));
        assert!(cmd.contains("Select-Object Path,CookedValue"));
    }

    #[test]
    fn test_network_command_counter_path() {
        let cmd = WindowsPerfCommandBuilder::build_network_command();
        assert!(cmd.contains("'\\Network Interface(*)\\Bytes Total/sec'"));
    }

    // ── build_overview_command ──────────────────────────────────────

    #[test]
    fn test_overview_command() {
        let cmd = WindowsPerfCommandBuilder::build_overview_command();
        assert!(cmd.contains("Get-Counter"));
        assert!(cmd.contains("\\Processor(_Total)\\% Processor Time"));
        assert!(cmd.contains("\\Memory\\Available MBytes"));
        assert!(cmd.contains("\\Memory\\% Committed Bytes In Use"));
        assert!(cmd.contains("\\PhysicalDisk(_Total)\\% Disk Time"));
        assert!(cmd.contains("Select-Object -ExpandProperty CounterSamples"));
        assert!(cmd.contains("Select-Object Path,CookedValue"));
    }

    #[test]
    fn test_overview_combines_cpu_memory_disk() {
        let cpu = WindowsPerfCommandBuilder::build_cpu_command();
        let memory = WindowsPerfCommandBuilder::build_memory_command();
        let disk = WindowsPerfCommandBuilder::build_disk_command();
        let overview = WindowsPerfCommandBuilder::build_overview_command();

        // Overview should contain counter paths from CPU, memory, and disk
        assert!(overview.contains("\\Processor(_Total)\\% Processor Time"));
        assert!(overview.contains("\\Memory\\Available MBytes"));
        assert!(overview.contains("\\PhysicalDisk(_Total)\\% Disk Time"));

        // But should be a single Get-Counter call, not multiple
        assert_eq!(overview.matches("Get-Counter").count(), 1);

        // Individual commands also use Get-Counter
        assert!(cpu.contains("Get-Counter"));
        assert!(memory.contains("Get-Counter"));
        assert!(disk.contains("Get-Counter"));
    }

    #[test]
    fn test_overview_does_not_include_network() {
        let overview = WindowsPerfCommandBuilder::build_overview_command();
        assert!(!overview.contains("Network Interface"));
    }

    // ── Output format consistency ───────────────────────────────────

    #[test]
    fn test_all_commands_select_path_and_cooked_value() {
        let commands = [
            WindowsPerfCommandBuilder::build_cpu_command(),
            WindowsPerfCommandBuilder::build_memory_command(),
            WindowsPerfCommandBuilder::build_disk_command(),
            WindowsPerfCommandBuilder::build_network_command(),
            WindowsPerfCommandBuilder::build_overview_command(),
        ];
        for cmd in &commands {
            assert!(
                cmd.contains("Select-Object Path,CookedValue"),
                "Command missing Path,CookedValue: {cmd}"
            );
        }
    }

    #[test]
    fn test_all_commands_expand_counter_samples() {
        let commands = [
            WindowsPerfCommandBuilder::build_cpu_command(),
            WindowsPerfCommandBuilder::build_memory_command(),
            WindowsPerfCommandBuilder::build_disk_command(),
            WindowsPerfCommandBuilder::build_network_command(),
            WindowsPerfCommandBuilder::build_overview_command(),
        ];
        for cmd in &commands {
            assert!(
                cmd.contains("Select-Object -ExpandProperty CounterSamples"),
                "Command missing ExpandProperty CounterSamples: {cmd}"
            );
        }
    }

    #[test]
    fn test_all_commands_use_get_counter() {
        let commands = [
            WindowsPerfCommandBuilder::build_cpu_command(),
            WindowsPerfCommandBuilder::build_memory_command(),
            WindowsPerfCommandBuilder::build_disk_command(),
            WindowsPerfCommandBuilder::build_network_command(),
            WindowsPerfCommandBuilder::build_overview_command(),
        ];
        for cmd in &commands {
            assert!(
                cmd.starts_with("Get-Counter"),
                "Command does not start with Get-Counter: {cmd}"
            );
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn test_cpu_has_sample_interval() {
        let cmd = WindowsPerfCommandBuilder::build_cpu_command();
        assert!(cmd.contains("-SampleInterval 1"));
        assert!(cmd.contains("-MaxSamples 3"));
    }

    #[test]
    fn test_memory_has_no_sample_interval() {
        let cmd = WindowsPerfCommandBuilder::build_memory_command();
        assert!(!cmd.contains("-SampleInterval"));
    }

    #[test]
    fn test_disk_has_no_sample_interval() {
        let cmd = WindowsPerfCommandBuilder::build_disk_command();
        assert!(!cmd.contains("-SampleInterval"));
    }

    #[test]
    fn test_network_has_no_sample_interval() {
        let cmd = WindowsPerfCommandBuilder::build_network_command();
        assert!(!cmd.contains("-SampleInterval"));
    }

    #[test]
    fn test_overview_has_no_sample_interval() {
        let cmd = WindowsPerfCommandBuilder::build_overview_command();
        assert!(!cmd.contains("-SampleInterval"));
    }

    // ── No user input (no injection surface) ────────────────────────

    #[test]
    fn test_no_methods_accept_user_input() {
        // All builder methods are parameterless, so there is no injection
        // surface. This test documents that design decision.
        let _cpu = WindowsPerfCommandBuilder::build_cpu_command();
        let _mem = WindowsPerfCommandBuilder::build_memory_command();
        let _disk = WindowsPerfCommandBuilder::build_disk_command();
        let _net = WindowsPerfCommandBuilder::build_network_command();
        let _overview = WindowsPerfCommandBuilder::build_overview_command();
        // If this compiles and runs, all methods are parameterless.
    }
}
