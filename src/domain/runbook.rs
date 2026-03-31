//! Runbook Domain Model & Engine
//!
//! Defines the YAML-based runbook schema and execution engine for
//! automated multi-step operational procedures.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// A runbook definition loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbook {
    pub name: String,
    pub description: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub params: HashMap<String, RunbookParam>,
    pub steps: Vec<RunbookStep>,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Runbook parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookParam {
    #[serde(rename = "type", default = "default_param_type")]
    pub param_type: String,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_param_type() -> String {
    "string".to_string()
}

/// A single step in a runbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookStep {
    pub name: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub save_as: Option<String>,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub on_false: Option<String>,
    #[serde(default = "default_confirm")]
    pub confirm: bool,
    #[serde(default)]
    pub rollback: Option<String>,
}

const fn default_confirm() -> bool {
    false
}

/// Result of executing a runbook step
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub name: String,
    pub command: String,
    pub output: String,
    pub exit_code: u32,
    pub skipped: bool,
    pub error: Option<String>,
}

/// Result of a full runbook execution
#[derive(Debug, Clone, Serialize)]
pub struct RunbookResult {
    pub runbook_name: String,
    pub steps: Vec<StepResult>,
    pub completed: bool,
    pub error: Option<String>,
}

/// Validate a runbook definition
pub fn validate_runbook(runbook: &Runbook) -> Result<(), String> {
    if runbook.name.is_empty() {
        return Err("Runbook name cannot be empty".to_string());
    }
    if runbook.steps.is_empty() {
        return Err("Runbook must have at least one step".to_string());
    }
    for (i, step) in runbook.steps.iter().enumerate() {
        if step.name.is_empty() {
            return Err(format!("Step {i} has no name"));
        }
        if step.command.is_none() && step.condition.is_none() {
            return Err(format!(
                "Step '{}' has neither command nor condition",
                step.name
            ));
        }
    }
    Ok(())
}

/// Apply template variables to a command string
///
/// Replaces `{{ variable }}` patterns with values from params.
#[must_use]
pub fn apply_template<S: ::std::hash::BuildHasher>(
    template: &str,
    vars: &HashMap<String, String, S>,
) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        let patterns = [format!("{{{{ {key} }}}}"), format!("{{{{{key}}}}}")];
        for pattern in &patterns {
            result = result.replace(pattern, value);
        }
    }
    result
}

/// Load all runbooks from a directory
pub fn load_runbooks_from_dir(dir: &Path) -> Vec<Runbook> {
    let mut runbooks = Vec::new();

    let Ok(entries) = std::fs::read_dir(dir) else {
        warn!(path = %dir.display(), "Failed to read runbooks directory");
        return runbooks;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            match load_runbook(&path) {
                Ok(rb) => {
                    info!(name = %rb.name, path = %path.display(), "Loaded runbook");
                    runbooks.push(rb);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to load runbook");
                }
            }
        }
    }

    runbooks
}

/// Load a single runbook from a YAML file
pub fn load_runbook(path: &Path) -> Result<Runbook, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let runbook: Runbook = serde_saphyr::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;

    validate_runbook(&runbook)?;
    Ok(runbook)
}

/// Get the default runbooks directory path
#[must_use]
pub fn default_runbooks_dir() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
    config_dir.join("mcp-ssh-bridge").join("runbooks")
}

/// Get built-in runbook definitions (embedded in binary)
#[must_use]
pub fn builtin_runbooks() -> Vec<Runbook> {
    let definitions = [
        include_str!("../../config/runbooks/disk_full.yaml"),
        include_str!("../../config/runbooks/service_restart.yaml"),
        include_str!("../../config/runbooks/oom_recovery.yaml"),
        include_str!("../../config/runbooks/log_rotation.yaml"),
        include_str!("../../config/runbooks/cert_renewal.yaml"),
    ];

    definitions
        .iter()
        .filter_map(|yaml| {
            serde_saphyr::from_str(yaml)
                .map_err(|e| warn!(error = %e, "Failed to parse built-in runbook"))
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_template() {
        let mut vars = HashMap::new();
        vars.insert("threshold".to_string(), "90".to_string());
        vars.insert("dir".to_string(), "/var/log".to_string());

        let result = apply_template("df {{ dir }} | check > {{ threshold }}", &vars);
        assert_eq!(result, "df /var/log | check > 90");
    }

    #[test]
    fn test_apply_template_no_spaces() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "test".to_string());

        let result = apply_template("echo {{name}}", &vars);
        assert_eq!(result, "echo test");
    }

    #[test]
    fn test_validate_empty_name() {
        let rb = Runbook {
            name: String::new(),
            description: "test".to_string(),
            version: "1.0".to_string(),
            params: HashMap::new(),
            steps: vec![RunbookStep {
                name: "s1".to_string(),
                command: Some("echo hi".to_string()),
                save_as: None,
                condition: None,
                on_false: None,
                confirm: false,
                rollback: None,
            }],
        };
        assert!(validate_runbook(&rb).is_err());
    }

    #[test]
    fn test_validate_no_steps() {
        let rb = Runbook {
            name: "test".to_string(),
            description: "test".to_string(),
            version: "1.0".to_string(),
            params: HashMap::new(),
            steps: Vec::new(),
        };
        assert!(validate_runbook(&rb).is_err());
    }

    #[test]
    fn test_validate_step_no_command() {
        let rb = Runbook {
            name: "test".to_string(),
            description: "test".to_string(),
            version: "1.0".to_string(),
            params: HashMap::new(),
            steps: vec![RunbookStep {
                name: "bad".to_string(),
                command: None,
                save_as: None,
                condition: None,
                on_false: None,
                confirm: false,
                rollback: None,
            }],
        };
        assert!(validate_runbook(&rb).is_err());
    }

    #[test]
    fn test_validate_valid_runbook() {
        let rb = Runbook {
            name: "disk_check".to_string(),
            description: "Check disk".to_string(),
            version: "1.0".to_string(),
            params: HashMap::new(),
            steps: vec![
                RunbookStep {
                    name: "check".to_string(),
                    command: Some("df -h".to_string()),
                    save_as: Some("usage".to_string()),
                    condition: None,
                    on_false: None,
                    confirm: false,
                    rollback: None,
                },
                RunbookStep {
                    name: "evaluate".to_string(),
                    command: None,
                    save_as: None,
                    condition: Some("{{ usage }} > 90".to_string()),
                    on_false: Some("skip_to_end".to_string()),
                    confirm: false,
                    rollback: None,
                },
            ],
        };
        assert!(validate_runbook(&rb).is_ok());
    }

    #[test]
    fn test_builtin_runbooks_parse() {
        let runbooks = builtin_runbooks();
        assert_eq!(runbooks.len(), 5, "Should have 5 built-in runbooks");
        for rb in &runbooks {
            assert!(!rb.name.is_empty());
            assert!(!rb.steps.is_empty());
        }
    }

    #[test]
    fn test_default_runbooks_dir() {
        let dir = default_runbooks_dir();
        assert!(dir.to_string_lossy().contains("mcp-ssh-bridge"));
        assert!(dir.to_string_lossy().contains("runbooks"));
    }

    #[test]
    fn test_load_runbooks_from_nonexistent_dir() {
        let runbooks = load_runbooks_from_dir(Path::new("/nonexistent/path"));
        assert!(runbooks.is_empty());
    }
}
