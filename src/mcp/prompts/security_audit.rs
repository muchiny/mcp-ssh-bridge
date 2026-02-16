//! Security Audit Prompt Handler
//!
//! Provides a prompt for performing security audits on a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Security audit prompt
pub struct SecurityAuditPrompt;

#[async_trait]
impl PromptHandler for SecurityAuditPrompt {
    fn name(&self) -> &'static str {
        "security-audit"
    }

    fn description(&self) -> &'static str {
        "Perform a security audit on a remote host"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![
            PromptArgument {
                name: "host".to_string(),
                description: "SSH host alias to audit".to_string(),
                required: true,
            },
            PromptArgument {
                name: "scope".to_string(),
                description: "Audit scope: quick, standard, or thorough".to_string(),
                required: false,
            },
        ]
    }

    async fn get(
        &self,
        args: HashMap<String, String>,
        _ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>> {
        let host = args.get("host").map_or("the target host", String::as_str);
        let scope = args.get("scope").map_or("standard", String::as_str);

        let scope_instructions = match scope {
            "quick" => {
                r"Perform a quick security check focusing on:
- SSH configuration basics
- Currently logged in users
- Recent authentication failures"
            }
            "thorough" => {
                r"Perform a comprehensive security audit including:
- All standard checks
- Package vulnerability scan (if available)
- File permission audit on sensitive directories
- Network configuration review
- Cron job inspection
- Detailed service configuration review"
            }
            _ => {
                r"Perform a standard security audit including:
- SSH configuration
- User account analysis
- Running services
- Open ports
- Recent security events"
            }
        };

        Ok(vec![PromptMessage::user(format!(
            r#"Please perform a {scope} security audit on host '{host}'.

{scope_instructions}

## Security Checks to Perform

### 1. SSH Configuration
```
cat /etc/ssh/sshd_config | grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)" 2>/dev/null
```

### 2. Currently Logged In Users
```
who
last -n 10
```

### 3. Failed Login Attempts
```
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -i "failed" | tail -20
```

### 4. Running Services
```
systemctl list-units --type=service --state=running 2>/dev/null | head -30 || service --status-all 2>/dev/null
```

### 5. Open Network Ports
```
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null
```

### 6. Sudo Configuration
```
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "Cannot read sudoers"
```

### 7. World-Writable Files in Sensitive Locations
```
find /etc /usr -type f -perm -002 2>/dev/null | head -20
```

## Expected Output

After running these checks, provide:
1. **Security Score**: Rate the host's security (A/B/C/D/F)
2. **Critical Issues**: Any immediate security concerns
3. **Warnings**: Potential security improvements
4. **Recommendations**: Specific actions to improve security
5. **Compliance Notes**: Any notable security configurations

Focus on actionable findings and prioritize critical issues."#
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PromptHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_security_audit_name() {
        let prompt = SecurityAuditPrompt;
        assert_eq!(prompt.name(), "security-audit");
    }

    #[test]
    fn test_security_audit_description() {
        let prompt = SecurityAuditPrompt;
        assert!(prompt.description().contains("security"));
        assert!(prompt.description().contains("audit"));
    }

    #[test]
    fn test_security_audit_arguments() {
        let prompt = SecurityAuditPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 2);

        let host_arg = args.iter().find(|a| a.name == "host").unwrap();
        assert!(host_arg.required);

        let scope_arg = args.iter().find(|a| a.name == "scope").unwrap();
        assert!(!scope_arg.required);
    }

    #[tokio::test]
    async fn test_security_audit_quick_scope() {
        let prompt = SecurityAuditPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server1".to_string());
        args.insert("scope".to_string(), "quick".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("quick"));
        assert!(text.contains("SSH configuration basics"));
    }

    #[tokio::test]
    async fn test_security_audit_thorough_scope() {
        let prompt = SecurityAuditPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server1".to_string());
        args.insert("scope".to_string(), "thorough".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("thorough"));
        assert!(text.contains("comprehensive"));
        assert!(text.contains("Package vulnerability"));
    }

    #[tokio::test]
    async fn test_security_audit_standard_scope_default() {
        let prompt = SecurityAuditPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server1".to_string());
        // No scope specified - should default to standard

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("standard"));
    }

    #[tokio::test]
    async fn test_security_audit_contains_security_checks() {
        let prompt = SecurityAuditPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "myhost".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        // Check that security commands are included
        assert!(text.contains("/etc/ssh/sshd_config"));
        assert!(text.contains("who"));
        assert!(text.contains("Failed password"));
        assert!(text.contains("ss -tuln"));
        assert!(text.contains("sudoers"));
    }

    #[tokio::test]
    async fn test_security_audit_expected_output_section() {
        let prompt = SecurityAuditPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "host".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("Security Score"));
        assert!(text.contains("Critical Issues"));
        assert!(text.contains("Recommendations"));
    }
}
