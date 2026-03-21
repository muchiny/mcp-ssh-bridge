//! Network Equipment Command Builder
//!
//! Builds commands for network devices (Cisco IOS, `JunOS`, `MikroTik`, Fortinet, generic).
//! Network equipment uses non-POSIX shells, so commands are sent as-is without shell escaping.


/// Equipment vendor/OS type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquipmentType {
    /// Cisco IOS/IOS-XE
    Cisco,
    /// Juniper `JunOS`
    Juniper,
    /// `MikroTik` `RouterOS`
    MikroTik,
    /// Fortinet `FortiOS`
    Fortinet,
    /// Generic / auto-detect
    Generic,
}

impl EquipmentType {
    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "cisco" | "ios" => Self::Cisco,
            "juniper" | "junos" => Self::Juniper,
            "mikrotik" | "routeros" => Self::MikroTik,
            "fortinet" | "fortios" | "fortigate" => Self::Fortinet,
            _ => Self::Generic,
        }
    }
}

/// Builds commands for network equipment.
pub struct NetworkEquipmentCommandBuilder;

impl NetworkEquipmentCommandBuilder {
    /// Build show running-config command.
    #[must_use]
    pub fn build_show_run_command(equipment: EquipmentType, section: Option<&str>) -> String {
        match equipment {
            EquipmentType::Cisco => {
                if let Some(s) = section {
                    format!("show running-config | section {s}")
                } else {
                    "show running-config".to_string()
                }
            }
            EquipmentType::Juniper => "show configuration | display set".to_string(),
            EquipmentType::MikroTik => "/export".to_string(),
            EquipmentType::Fortinet => "show full-configuration".to_string(),
            EquipmentType::Generic => "show running-config".to_string(),
        }
    }

    /// Build show interfaces command.
    #[must_use]
    pub fn build_show_interfaces_command(equipment: EquipmentType, interface: Option<&str>) -> String {
        match equipment {
            EquipmentType::Cisco => {
                if let Some(i) = interface {
                    format!("show interfaces {i}")
                } else {
                    "show ip interface brief".to_string()
                }
            }
            EquipmentType::Juniper => {
                if let Some(i) = interface {
                    format!("show interfaces {i} extensive")
                } else {
                    "show interfaces terse".to_string()
                }
            }
            EquipmentType::MikroTik => "/interface print".to_string(),
            EquipmentType::Fortinet => "get system interface".to_string(),
            EquipmentType::Generic => "show interfaces".to_string(),
        }
    }

    /// Build show routes command.
    #[must_use]
    pub fn build_show_routes_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show ip route".to_string(),
            EquipmentType::Juniper => "show route".to_string(),
            EquipmentType::MikroTik => "/ip route print".to_string(),
            EquipmentType::Fortinet => "get router info routing-table all".to_string(),
        }
    }

    /// Build show ARP command.
    #[must_use]
    pub fn build_show_arp_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show arp".to_string(),
            EquipmentType::Juniper => "show arp no-resolve".to_string(),
            EquipmentType::MikroTik => "/ip arp print".to_string(),
            EquipmentType::Fortinet => "get system arp".to_string(),
        }
    }

    /// Build show version command.
    #[must_use]
    pub fn build_show_version_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Juniper | EquipmentType::Generic => {
                "show version".to_string()
            }
            EquipmentType::MikroTik => "/system resource print".to_string(),
            EquipmentType::Fortinet => "get system status".to_string(),
        }
    }

    /// Build show VLANs command.
    #[must_use]
    pub fn build_show_vlans_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show vlan brief".to_string(),
            EquipmentType::Juniper => "show vlans".to_string(),
            EquipmentType::MikroTik => "/interface vlan print".to_string(),
            EquipmentType::Fortinet => "show system interface | grep vlan".to_string(),
        }
    }

    /// Build config command (wraps in configure mode).
    #[must_use]
    pub fn build_config_command(equipment: EquipmentType, commands: &str) -> String {
        match equipment {
            EquipmentType::Cisco => {
                format!("configure terminal\n{commands}\nend")
            }
            EquipmentType::Juniper => {
                format!("configure\n{commands}\ncommit\nexit")
            }
            EquipmentType::MikroTik | EquipmentType::Generic => commands.to_string(),
            EquipmentType::Fortinet => {
                format!("config system global\n{commands}\nend")
            }
        }
    }

    /// Build save config command.
    #[must_use]
    pub fn build_save_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "write memory".to_string(),
            EquipmentType::Juniper => "request system configuration rescue save".to_string(),
            EquipmentType::MikroTik => "/system backup save name=mcp-backup".to_string(),
            EquipmentType::Fortinet => "execute backup config flash".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equipment_type_parse() {
        assert_eq!(EquipmentType::from_str_loose("cisco"), EquipmentType::Cisco);
        assert_eq!(EquipmentType::from_str_loose("IOS"), EquipmentType::Cisco);
        assert_eq!(EquipmentType::from_str_loose("juniper"), EquipmentType::Juniper);
        assert_eq!(EquipmentType::from_str_loose("mikrotik"), EquipmentType::MikroTik);
        assert_eq!(EquipmentType::from_str_loose("fortinet"), EquipmentType::Fortinet);
        assert_eq!(EquipmentType::from_str_loose("unknown"), EquipmentType::Generic);
    }

    #[test]
    fn test_show_run_cisco() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::Cisco, None);
        assert_eq!(cmd, "show running-config");
    }

    #[test]
    fn test_show_run_cisco_section() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::Cisco, Some("interface"));
        assert!(cmd.contains("section interface"));
    }

    #[test]
    fn test_show_run_juniper() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::Juniper, None);
        assert!(cmd.contains("display set"));
    }

    #[test]
    fn test_show_run_mikrotik() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::MikroTik, None);
        assert_eq!(cmd, "/export");
    }

    #[test]
    fn test_show_interfaces_cisco() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_interfaces_command(EquipmentType::Cisco, None);
        assert!(cmd.contains("ip interface brief"));
    }

    #[test]
    fn test_show_interfaces_cisco_specific() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_interfaces_command(EquipmentType::Cisco, Some("GigabitEthernet0/1"));
        assert!(cmd.contains("GigabitEthernet0/1"));
    }

    #[test]
    fn test_show_routes() {
        assert!(NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::Cisco).contains("ip route"));
        assert!(NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::Juniper).contains("show route"));
        assert!(NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::MikroTik).contains("/ip route"));
    }

    #[test]
    fn test_show_arp() {
        assert!(NetworkEquipmentCommandBuilder::build_show_arp_command(EquipmentType::Cisco).contains("show arp"));
        assert!(NetworkEquipmentCommandBuilder::build_show_arp_command(EquipmentType::MikroTik).contains("/ip arp"));
    }

    #[test]
    fn test_show_version() {
        assert!(NetworkEquipmentCommandBuilder::build_show_version_command(EquipmentType::Cisco).contains("show version"));
        assert!(NetworkEquipmentCommandBuilder::build_show_version_command(EquipmentType::MikroTik).contains("resource print"));
    }

    #[test]
    fn test_config_cisco() {
        let cmd = NetworkEquipmentCommandBuilder::build_config_command(EquipmentType::Cisco, "interface Gi0/1\nno shutdown");
        assert!(cmd.starts_with("configure terminal"));
        assert!(cmd.ends_with("end"));
    }

    #[test]
    fn test_config_juniper() {
        let cmd = NetworkEquipmentCommandBuilder::build_config_command(EquipmentType::Juniper, "set interfaces ge-0/0/0 disable");
        assert!(cmd.contains("commit"));
    }

    #[test]
    fn test_save() {
        assert_eq!(NetworkEquipmentCommandBuilder::build_save_command(EquipmentType::Cisco), "write memory");
        assert!(NetworkEquipmentCommandBuilder::build_save_command(EquipmentType::Juniper).contains("rescue save"));
    }
}
