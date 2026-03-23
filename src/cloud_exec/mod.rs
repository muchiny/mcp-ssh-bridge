//! Cloud execution adapters — Azure Run Command and GCP OS Command
//!
//! These adapters execute commands on cloud VMs without SSH by using
//! the respective cloud provider APIs. They require cloud API access
//! and are **not air-gapped compatible**.
//!
//! Feature-gated behind `azure` and `gcp` respectively.

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;
