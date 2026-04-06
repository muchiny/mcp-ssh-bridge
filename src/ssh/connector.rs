//! SSH Connector Adapter
//!
//! Concrete implementation of the `SshConnector` and `SshClientTrait` ports
//! using the russh SSH client.

use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;
use crate::ports::{SshClientTrait, SshConnector};
use crate::ssh::{CommandOutput, SshClient};

/// Real SSH connector using russh
#[derive(Default, Clone)]
pub struct RealSshConnector;

impl RealSshConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SshConnector for RealSshConnector {
    type Client = SshClient;

    async fn connect(
        &self,
        host_name: &str,
        host: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Self::Client> {
        SshClient::connect(host_name, host, limits).await
    }

    async fn connect_via_jump(
        &self,
        host_name: &str,
        host: &HostConfig,
        jump_host_name: &str,
        jump_host: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Self::Client> {
        SshClient::connect_via_jump(host_name, host, jump_host_name, jump_host, limits).await
    }
}

impl SshClientTrait for SshClient {
    async fn exec(&self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        self.exec(command, limits).await
    }

    async fn is_connected(&self) -> bool {
        self.is_connected().await
    }

    fn host_name(&self) -> &str {
        self.host_name()
    }

    async fn close(self) -> Result<()> {
        self.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_ssh_connector_new() {
        let connector = RealSshConnector::new();
        let _clone = connector.clone();
    }

    #[test]
    fn test_real_ssh_connector_default() {
        let connector = RealSshConnector;
        let _clone = connector.clone();
    }

    #[test]
    fn test_real_ssh_connector_clone() {
        let connector = RealSshConnector::new();
        let cloned = connector.clone();
        assert_eq!(std::mem::size_of_val(&cloned), 0); // ZST
    }

    #[test]
    fn test_real_ssh_connector_is_zero_sized() {
        assert_eq!(std::mem::size_of::<RealSshConnector>(), 0);
    }

    #[test]
    fn test_real_ssh_connector_default_is_same_as_new() {
        let from_new = RealSshConnector::new();
        let from_default = RealSshConnector::default();
        // Both are ZSTs so they are identical
        assert_eq!(
            std::mem::size_of_val(&from_new),
            std::mem::size_of_val(&from_default)
        );
    }

    #[test]
    fn test_real_ssh_connector_multiple_clones() {
        let connector = RealSshConnector::new();
        let c1 = connector.clone();
        let c2 = c1.clone();
        let c3 = c2.clone();
        // All clones should be valid ZSTs
        assert_eq!(std::mem::size_of_val(&c3), 0);
    }
}
