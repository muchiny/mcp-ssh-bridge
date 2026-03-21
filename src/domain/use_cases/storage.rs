//! Storage Command Builder
//!
//! Builds commands for disk, filesystem, and LVM operations.

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds storage management commands.
pub struct StorageCommandBuilder;

impl StorageCommandBuilder {
    /// Build lsblk command.
    #[must_use]
    pub fn build_lsblk_command(json: bool) -> String {
        if json {
            "lsblk -J -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL".to_string()
        } else {
            "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL".to_string()
        }
    }

    /// Build detailed df command.
    #[must_use]
    pub fn build_df_command(path: Option<&str>, inodes: bool) -> String {
        let mut cmd = String::from("df -h");
        if inodes {
            cmd.push_str(" -i");
        }
        cmd.push_str(" -T"); // show filesystem type
        if let Some(p) = path {
            cmd.push(' ');
            cmd.push_str(&shell_escape(p));
        }
        cmd
    }

    /// Build mount command.
    #[must_use]
    pub fn build_mount_command(
        device: &str,
        mount_point: &str,
        fs_type: Option<&str>,
        options: Option<&str>,
    ) -> String {
        let mut cmd = String::from("mount");
        if let Some(t) = fs_type {
            cmd.push_str(" -t ");
            cmd.push_str(&shell_escape(t));
        }
        if let Some(o) = options {
            cmd.push_str(" -o ");
            cmd.push_str(&shell_escape(o));
        }
        cmd.push(' ');
        cmd.push_str(&shell_escape(device));
        cmd.push(' ');
        cmd.push_str(&shell_escape(mount_point));
        cmd
    }

    /// Build umount command.
    #[must_use]
    pub fn build_umount_command(path: &str, lazy: bool) -> String {
        let escaped = shell_escape(path);
        if lazy {
            format!("umount -l {escaped}")
        } else {
            format!("umount {escaped}")
        }
    }

    /// Build LVM listing command (PV, VG, LV).
    #[must_use]
    pub fn build_lvm_list_command() -> String {
        "pvs --noheadings 2>/dev/null; echo '---'; vgs --noheadings 2>/dev/null; echo '---'; lvs --noheadings 2>/dev/null".to_string()
    }

    /// Build fdisk list command (read-only).
    #[must_use]
    pub fn build_fdisk_command(device: Option<&str>) -> String {
        if let Some(d) = device {
            format!("fdisk -l {}", shell_escape(d))
        } else {
            "fdisk -l".to_string()
        }
    }

    /// Build fstab read command.
    #[must_use]
    pub fn build_fstab_command() -> String {
        "cat /etc/fstab".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsblk_json() {
        let cmd = StorageCommandBuilder::build_lsblk_command(true);
        assert!(cmd.contains("-J"));
    }

    #[test]
    fn test_lsblk_text() {
        let cmd = StorageCommandBuilder::build_lsblk_command(false);
        assert!(!cmd.contains("-J"));
        assert!(cmd.contains("lsblk"));
    }

    #[test]
    fn test_df_default() {
        let cmd = StorageCommandBuilder::build_df_command(None, false);
        assert!(cmd.contains("df -h"));
        assert!(cmd.contains("-T"));
    }

    #[test]
    fn test_df_inodes() {
        let cmd = StorageCommandBuilder::build_df_command(None, true);
        assert!(cmd.contains("-i"));
    }

    #[test]
    fn test_df_path() {
        let cmd = StorageCommandBuilder::build_df_command(Some("/home"), false);
        assert!(cmd.contains("/home"));
    }

    #[test]
    fn test_mount() {
        let cmd = StorageCommandBuilder::build_mount_command(
            "/dev/sda1",
            "/mnt",
            Some("ext4"),
            Some("ro"),
        );
        assert!(cmd.contains("mount"));
        assert!(cmd.contains("-t"));
        assert!(cmd.contains("-o"));
    }

    #[test]
    fn test_umount() {
        let cmd = StorageCommandBuilder::build_umount_command("/mnt", false);
        assert!(cmd.contains("umount"));
        assert!(!cmd.contains("-l"));
    }

    #[test]
    fn test_umount_lazy() {
        let cmd = StorageCommandBuilder::build_umount_command("/mnt", true);
        assert!(cmd.contains("-l"));
    }

    #[test]
    fn test_lvm_list() {
        let cmd = StorageCommandBuilder::build_lvm_list_command();
        assert!(cmd.contains("pvs"));
        assert!(cmd.contains("vgs"));
        assert!(cmd.contains("lvs"));
    }

    #[test]
    fn test_fdisk_all() {
        let cmd = StorageCommandBuilder::build_fdisk_command(None);
        assert_eq!(cmd, "fdisk -l");
    }

    #[test]
    fn test_fdisk_device() {
        let cmd = StorageCommandBuilder::build_fdisk_command(Some("/dev/sda"));
        assert!(cmd.contains("/dev/sda"));
    }

    #[test]
    fn test_fstab() {
        let cmd = StorageCommandBuilder::build_fstab_command();
        assert!(cmd.contains("/etc/fstab"));
    }
}
