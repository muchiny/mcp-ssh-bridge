//! MCP Apps — Interactive UI Components (early 2026)
//!
//! Provides builder helpers for creating rich UI components
//! that MCP clients can render directly in the conversation.
//!
//! Supported app types:
//! - **Dashboard**: Key-value metrics with optional refresh action
//! - **Table**: Tabular data with optional row-level actions
//! - **Form**: Structured input form that invokes a tool on submit
//! - **Chart**: Simple chart data (bar, line, pie)

use serde_json::{Value, json};

use crate::ports::protocol::{AppAction, AppContent};

// ============================================================================
// Dashboard Builder
// ============================================================================

/// Build a dashboard app component showing key-value metrics.
///
/// # Example
/// ```ignore
/// let app = dashboard("System Metrics")
///     .metric("CPU", "23%")
///     .metric("Memory", "4.2 / 8.0 GB")
///     .refresh_action("ssh_metrics", json!({"host": "web1"}))
///     .build();
/// ```
pub struct DashboardBuilder {
    title: String,
    metrics: Vec<Value>,
    actions: Vec<AppAction>,
}

/// Create a new dashboard builder.
#[must_use]
pub fn dashboard(title: impl Into<String>) -> DashboardBuilder {
    DashboardBuilder {
        title: title.into(),
        metrics: Vec::new(),
        actions: Vec::new(),
    }
}

impl DashboardBuilder {
    /// Add a metric entry.
    #[must_use]
    pub fn metric(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.metrics.push(json!({
            "label": label.into(),
            "value": value.into(),
        }));
        self
    }

    /// Add a refresh action that invokes a tool.
    #[must_use]
    pub fn refresh_action(mut self, tool: impl Into<String>, args: Value) -> Self {
        self.actions.push(AppAction {
            id: "refresh".to_string(),
            label: "Refresh".to_string(),
            tool: tool.into(),
            args: Some(args),
        });
        self
    }

    /// Add a custom action.
    #[must_use]
    pub fn action(
        mut self,
        id: impl Into<String>,
        label: impl Into<String>,
        tool: impl Into<String>,
        args: Option<Value>,
    ) -> Self {
        self.actions.push(AppAction {
            id: id.into(),
            label: label.into(),
            tool: tool.into(),
            args,
        });
        self
    }

    /// Build the `AppContent`.
    #[must_use]
    pub fn build(self) -> AppContent {
        AppContent {
            app_type: "dashboard".to_string(),
            title: Some(self.title),
            data: json!({ "metrics": self.metrics }),
            actions: if self.actions.is_empty() {
                None
            } else {
                Some(self.actions)
            },
        }
    }
}

// ============================================================================
// Table Builder
// ============================================================================

/// Build a table app component with columns and rows.
pub struct TableBuilder {
    title: String,
    columns: Vec<Value>,
    rows: Vec<Value>,
    actions: Vec<AppAction>,
}

/// Create a new table builder.
#[must_use]
pub fn table(title: impl Into<String>) -> TableBuilder {
    TableBuilder {
        title: title.into(),
        columns: Vec::new(),
        rows: Vec::new(),
        actions: Vec::new(),
    }
}

impl TableBuilder {
    /// Add a column definition.
    #[must_use]
    pub fn column(mut self, key: impl Into<String>, label: impl Into<String>) -> Self {
        self.columns.push(json!({
            "key": key.into(),
            "label": label.into(),
        }));
        self
    }

    /// Add a row of data.
    #[must_use]
    pub fn row(mut self, data: Value) -> Self {
        self.rows.push(data);
        self
    }

    /// Add a table-level action.
    #[must_use]
    pub fn action(
        mut self,
        id: impl Into<String>,
        label: impl Into<String>,
        tool: impl Into<String>,
        args: Option<Value>,
    ) -> Self {
        self.actions.push(AppAction {
            id: id.into(),
            label: label.into(),
            tool: tool.into(),
            args,
        });
        self
    }

    /// Build the `AppContent`.
    #[must_use]
    pub fn build(self) -> AppContent {
        AppContent {
            app_type: "table".to_string(),
            title: Some(self.title),
            data: json!({
                "columns": self.columns,
                "rows": self.rows,
            }),
            actions: if self.actions.is_empty() {
                None
            } else {
                Some(self.actions)
            },
        }
    }
}

// ============================================================================
// Form Builder
// ============================================================================

/// Build a form app component with fields.
pub struct FormBuilder {
    title: String,
    fields: Vec<Value>,
    submit_tool: String,
    submit_args: Option<Value>,
}

/// Create a new form builder with a submit action.
#[must_use]
pub fn form(title: impl Into<String>, submit_tool: impl Into<String>) -> FormBuilder {
    FormBuilder {
        title: title.into(),
        fields: Vec::new(),
        submit_tool: submit_tool.into(),
        submit_args: None,
    }
}

impl FormBuilder {
    /// Add a text input field.
    #[must_use]
    pub fn text_field(
        mut self,
        name: impl Into<String>,
        label: impl Into<String>,
        required: bool,
    ) -> Self {
        self.fields.push(json!({
            "name": name.into(),
            "label": label.into(),
            "type": "text",
            "required": required,
        }));
        self
    }

    /// Add a select dropdown field.
    #[must_use]
    pub fn select_field(
        mut self,
        name: impl Into<String>,
        label: impl Into<String>,
        options: &[String],
    ) -> Self {
        self.fields.push(json!({
            "name": name.into(),
            "label": label.into(),
            "type": "select",
            "options": options,
        }));
        self
    }

    /// Set pre-filled arguments to merge with form values on submit.
    #[must_use]
    pub fn submit_args(mut self, args: Value) -> Self {
        self.submit_args = Some(args);
        self
    }

    /// Build the `AppContent`.
    #[must_use]
    pub fn build(self) -> AppContent {
        AppContent {
            app_type: "form".to_string(),
            title: Some(self.title),
            data: json!({
                "fields": self.fields,
            }),
            actions: Some(vec![AppAction {
                id: "submit".to_string(),
                label: "Submit".to_string(),
                tool: self.submit_tool,
                args: self.submit_args,
            }]),
        }
    }
}

// ============================================================================
// Chart Builder
// ============================================================================

/// Build a chart app component.
pub struct ChartBuilder {
    title: String,
    chart_type: String,
    labels: Vec<String>,
    datasets: Vec<Value>,
}

/// Create a new chart builder.
///
/// `chart_type` should be one of: `"bar"`, `"line"`, `"pie"`.
#[must_use]
pub fn chart(title: impl Into<String>, chart_type: impl Into<String>) -> ChartBuilder {
    ChartBuilder {
        title: title.into(),
        chart_type: chart_type.into(),
        labels: Vec::new(),
        datasets: Vec::new(),
    }
}

impl ChartBuilder {
    /// Set the x-axis labels.
    #[must_use]
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Add a dataset (series) to the chart.
    #[must_use]
    pub fn dataset(mut self, label: impl Into<String>, values: &[f64]) -> Self {
        self.datasets.push(json!({
            "label": label.into(),
            "values": values,
        }));
        self
    }

    /// Build the `AppContent`.
    #[must_use]
    pub fn build(self) -> AppContent {
        AppContent {
            app_type: "chart".to_string(),
            title: Some(self.title),
            data: json!({
                "chartType": self.chart_type,
                "labels": self.labels,
                "datasets": self.datasets,
            }),
            actions: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_builder() {
        let app = dashboard("System Metrics")
            .metric("CPU", "23%")
            .metric("Memory", "4.2 GB")
            .refresh_action("ssh_metrics", json!({"host": "web1"}))
            .build();

        assert_eq!(app.app_type, "dashboard");
        assert_eq!(app.title.as_deref(), Some("System Metrics"));
        assert_eq!(app.data["metrics"].as_array().unwrap().len(), 2);
        assert!(app.actions.is_some());
        assert_eq!(app.actions.as_ref().unwrap()[0].tool, "ssh_metrics");
    }

    #[test]
    fn test_table_builder() {
        let app = table("Docker Containers")
            .column("name", "Name")
            .column("status", "Status")
            .row(json!({"name": "web", "status": "running"}))
            .row(json!({"name": "db", "status": "running"}))
            .action("logs", "View Logs", "ssh_docker_logs", None)
            .build();

        assert_eq!(app.app_type, "table");
        assert_eq!(app.data["columns"].as_array().unwrap().len(), 2);
        assert_eq!(app.data["rows"].as_array().unwrap().len(), 2);
        assert!(app.actions.is_some());
    }

    #[test]
    fn test_form_builder() {
        let app = form("Deploy Application", "ssh_ansible_playbook")
            .text_field("host", "Target Host", true)
            .select_field(
                "env",
                "Environment",
                &["dev".into(), "staging".into(), "prod".into()],
            )
            .submit_args(json!({"playbook": "deploy.yml"}))
            .build();

        assert_eq!(app.app_type, "form");
        assert_eq!(app.data["fields"].as_array().unwrap().len(), 2);
        assert!(app.actions.is_some());
        assert_eq!(
            app.actions.as_ref().unwrap()[0].tool,
            "ssh_ansible_playbook"
        );
    }

    #[test]
    fn test_chart_builder() {
        let app = chart("CPU Usage (24h)", "line")
            .labels(vec![
                "00:00".into(),
                "06:00".into(),
                "12:00".into(),
                "18:00".into(),
            ])
            .dataset("web1", &[23.0, 45.0, 67.0, 34.0])
            .dataset("web2", &[12.0, 34.0, 56.0, 23.0])
            .build();

        assert_eq!(app.app_type, "chart");
        assert_eq!(app.data["chartType"], "line");
        assert_eq!(app.data["datasets"].as_array().unwrap().len(), 2);
        assert!(app.actions.is_none());
    }

    #[test]
    fn test_dashboard_no_actions() {
        let app = dashboard("Simple").metric("Uptime", "42 days").build();

        assert!(app.actions.is_none());
    }

    #[test]
    fn test_app_content_serialization() {
        let app = dashboard("Test").metric("k", "v").build();
        let json = serde_json::to_value(&app).unwrap();
        assert_eq!(json["appType"], "dashboard");
        assert_eq!(json["title"], "Test");
        assert!(json["data"]["metrics"].is_array());
    }

    #[test]
    fn test_tool_content_app_variant() {
        use crate::ports::protocol::{ToolCallResult, ToolContent};

        let app = dashboard("Metrics").metric("CPU", "10%").build();
        let result = ToolCallResult::text("CPU: 10%").with_app(app);

        assert_eq!(result.content.len(), 2);
        match &result.content[1] {
            ToolContent::App { app } => {
                assert_eq!(app.app_type, "dashboard");
            }
            _ => panic!("Expected App content"),
        }
    }
}
