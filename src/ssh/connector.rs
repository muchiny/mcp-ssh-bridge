//! SSH Connector Adapter
//!
//! Concrete implementation of the `SshConnector` and `SshClientTrait` ports
//! using the russh SSH client.

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

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

#[async_trait]
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

#[async_trait]
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

    fn close(self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { self.close().await })
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
}
