//! Kubernetes Exec protocol adapter — direct pod command execution
//!
//! Executes commands inside Kubernetes pods via the K8s API (`exec` subresource),
//! bypassing the need for SSH on the pod. Requires a kubeconfig or in-cluster
//! service account.
//!
//! Feature-gated behind `k8s-exec`.

use std::time::Instant;

use k8s_openapi::api::core::v1::Pod;
use kube::{
    Client, Config,
    api::{Api, AttachParams},
};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Kubernetes Exec connection — wraps a K8s API client.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → pod name (or `namespace/pod` format)
/// - `user` → namespace (default: "default")
/// - `description` → container name (optional, uses default container)
pub struct K8sExecConnection {
    client: Client,
    namespace: String,
    pod_name: String,
    container: Option<String>,
    host_name: String,
    failed: bool,
}

impl K8sExecConnection {
    /// Create a Kubernetes API client and resolve the target pod.
    ///
    /// # Errors
    ///
    /// Returns an error if the kubeconfig cannot be loaded or the cluster
    /// is unreachable.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, "Connecting via Kubernetes API");

        // Try in-cluster config first, fall back to kubeconfig
        let config = Config::infer().await.map_err(|e| BridgeError::SshExec {
            reason: format!("K8s config inference failed: {e}"),
        })?;

        let client = Client::try_from(config).map_err(|e| BridgeError::SshExec {
            reason: format!("K8s client creation failed: {e}"),
        })?;

        // Parse pod reference: "namespace/pod" or just "pod"
        let (namespace, pod_name) = if host_config.hostname.contains('/') {
            let parts: Vec<&str> = host_config.hostname.splitn(2, '/').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (host_config.user.clone(), host_config.hostname.clone())
        };

        // Container from description field (optional)
        let container = host_config.description.clone();

        info!(
            host = %host_name,
            namespace = %namespace,
            pod = %pod_name,
            container = ?container,
            "K8s exec target resolved"
        );

        Ok(Self {
            client,
            namespace,
            pod_name,
            container,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command inside the target pod.
    ///
    /// Uses the Kubernetes `exec` API (WebSocket-based).
    ///
    /// # Errors
    ///
    /// Returns an error if the exec call fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            pod = %self.pod_name,
            command = %command,
            "Executing K8s exec"
        );

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);

        let mut attach_params = AttachParams::default()
            .stdout(true)
            .stderr(true)
            .stdin(false);

        if let Some(ref container) = self.container {
            attach_params = attach_params.container(container);
        }

        // Split command into argv for exec
        let argv: Vec<&str> = vec!["/bin/sh", "-c", command];

        let mut attached = pods
            .exec(&self.pod_name, argv, &attach_params)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("K8s exec failed for pod {}: {e}", self.pod_name),
            })?;

        // Read stdout
        let mut stdout_buf = Vec::new();
        if let Some(mut stdout_reader) = attached.stdout() {
            stdout_reader
                .read_to_end(&mut stdout_buf)
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("K8s stdout read failed: {e}"),
                })?;
        }

        // Read stderr
        let mut stderr_buf = Vec::new();
        if let Some(mut stderr_reader) = attached.stderr() {
            stderr_reader
                .read_to_end(&mut stderr_buf)
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("K8s stderr read failed: {e}"),
                })?;
        }

        // Wait for completion and get exit code
        let exit_code = if let Some(status_future) = attached.take_status() {
            match status_future.await {
                Some(status) if status.status.as_deref() == Some("Success") => 0,
                Some(_) => 1,
                None => 0,
            }
        } else {
            0
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
            stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
            exit_code,
            duration_ms,
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "K8s exec connection marked as failed");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pod_name_parsing() {
        // "namespace/pod" format
        let hostname = "kube-system/coredns-abc123";
        let parts: Vec<&str> = hostname.splitn(2, '/').collect();
        assert_eq!(parts[0], "kube-system");
        assert_eq!(parts[1], "coredns-abc123");

        // Plain pod name
        let hostname2 = "my-pod";
        assert!(!hostname2.contains('/'));
    }
}
