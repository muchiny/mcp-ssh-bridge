//! LDAP Command Builder
//!
//! Builds ldapsearch, ldapadd, and ldapmodify commands for `OpenLDAP` operations.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Escape a value for safe inclusion inside an LDAP filter (RFC 4515 §3).
///
/// Encodes the four filter metacharacters `( ) * \` plus NUL.
fn ldap_filter_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'(' => out.push_str(r"\28"),
            b')' => out.push_str(r"\29"),
            b'*' => out.push_str(r"\2a"),
            b'\\' => out.push_str(r"\5c"),
            0 => out.push_str(r"\00"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Builds LDAP CLI commands for remote execution.
pub struct LdapCommandBuilder;

impl LdapCommandBuilder {
    /// Build an ldapsearch command.
    #[must_use]
    pub fn build_search_command(
        base_dn: &str,
        filter: Option<&str>,
        attributes: Option<&str>,
        scope: Option<&str>,
        uri: Option<&str>,
    ) -> String {
        let mut cmd = String::from("ldapsearch -x -LLL");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let _ = write!(cmd, " -b {}", shell_escape(base_dn));
        if let Some(s) = scope {
            let _ = write!(cmd, " -s {}", shell_escape(s));
        }
        if let Some(f) = filter {
            let _ = write!(cmd, " {}", shell_escape(f));
        }
        if let Some(a) = attributes {
            cmd.push(' ');
            cmd.push_str(a); // attributes are space-separated field names
        }
        cmd
    }

    /// Build an ldapsearch for a specific user.
    #[must_use]
    pub fn build_user_info_command(base_dn: &str, username: &str, uri: Option<&str>) -> String {
        let filter = format!("(uid={})", ldap_filter_escape(username));
        Self::build_search_command(base_dn, Some(&filter), None, Some("sub"), uri)
    }

    /// Build an ldapsearch for group members.
    #[must_use]
    pub fn build_group_members_command(base_dn: &str, group: &str, uri: Option<&str>) -> String {
        let filter = format!("(cn={})", ldap_filter_escape(group));
        Self::build_search_command(
            base_dn,
            Some(&filter),
            Some("member memberUid"),
            Some("sub"),
            uri,
        )
    }

    /// Build an ldapadd command (from LDIF on stdin).
    #[must_use]
    pub fn build_add_command(ldif_content: &str, uri: Option<&str>) -> String {
        let mut cmd = String::from("ldapadd -x");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf {escaped} | {cmd}")
    }

    /// Build an ldapmodify command (from LDIF on stdin).
    #[must_use]
    pub fn build_modify_command(ldif_content: &str, uri: Option<&str>) -> String {
        let mut cmd = String::from("ldapmodify -x");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf {escaped} | {cmd}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_simple() {
        let cmd =
            LdapCommandBuilder::build_search_command("dc=example,dc=com", None, None, None, None);
        assert!(cmd.contains("ldapsearch"));
        assert!(cmd.contains("-b"));
    }

    #[test]
    fn test_search_with_filter() {
        let cmd = LdapCommandBuilder::build_search_command(
            "dc=example,dc=com",
            Some("(objectClass=person)"),
            Some("cn mail"),
            Some("sub"),
            Some("ldap://ldap.example.com"),
        );
        assert!(cmd.contains("-H"));
        assert!(cmd.contains("-s"));
        assert!(cmd.contains("cn mail"));
    }

    #[test]
    fn test_user_info() {
        let cmd = LdapCommandBuilder::build_user_info_command("dc=example,dc=com", "jdoe", None);
        assert!(cmd.contains("uid=jdoe"));
    }

    #[test]
    fn test_group_members() {
        let cmd = LdapCommandBuilder::build_group_members_command(
            "dc=example,dc=com",
            "developers",
            None,
        );
        assert!(cmd.contains("cn=developers"));
        assert!(cmd.contains("member"));
    }

    #[test]
    fn test_add() {
        let cmd = LdapCommandBuilder::build_add_command("dn: cn=test\nobjectClass: top", None);
        assert!(cmd.contains("ldapadd"));
        assert!(cmd.contains("printf"));
    }

    #[test]
    fn test_modify() {
        let cmd = LdapCommandBuilder::build_modify_command(
            "dn: cn=test\nchangetype: modify",
            Some("ldap://localhost"),
        );
        assert!(cmd.contains("ldapmodify"));
        assert!(cmd.contains("-H"));
    }

    #[test]
    fn test_user_info_escapes_filter_metacharacters() {
        let cmd = LdapCommandBuilder::build_user_info_command(
            "dc=example,dc=com",
            "*)(uid=*",
            None,
        );
        assert!(!cmd.contains("(uid=*)(uid=*"), "raw injection must not appear");
        assert!(cmd.contains(r"\2a"), "asterisk must be RFC 4515 encoded");
        assert!(cmd.contains(r"\28") || cmd.contains(r"\29"), "parens must be encoded");
    }

    #[test]
    fn test_group_members_escapes_filter_metacharacters() {
        let cmd = LdapCommandBuilder::build_group_members_command(
            "dc=example,dc=com",
            "admins)(member=*",
            None,
        );
        assert!(!cmd.contains("(cn=admins)(member="));
        assert!(cmd.contains(r"\29"));
    }

    #[test]
    fn test_user_info_passthrough_clean_value() {
        let cmd = LdapCommandBuilder::build_user_info_command(
            "dc=example,dc=com",
            "alice",
            None,
        );
        // The filter string can be quoted by shell_escape, so accept either form.
        assert!(cmd.contains("(uid=alice)") || cmd.contains("'(uid=alice)'"));
    }

    #[test]
    fn test_group_members_passthrough_clean_value() {
        let cmd = LdapCommandBuilder::build_group_members_command(
            "dc=example,dc=com",
            "admins",
            None,
        );
        assert!(cmd.contains("(cn=admins)") || cmd.contains("'(cn=admins)'"));
    }
}
