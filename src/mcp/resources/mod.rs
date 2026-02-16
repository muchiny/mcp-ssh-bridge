//! MCP Resource Handlers
//!
//! This module contains resource handler implementations that
//! expose remote data through the MCP Resources primitive.

mod file_resource;
mod history_resource;
mod log_resource;
mod metrics_resource;
mod services_resource;

pub use file_resource::FileResourceHandler;
pub use history_resource::HistoryResourceHandler;
pub use log_resource::LogResourceHandler;
pub use metrics_resource::MetricsResourceHandler;
pub use services_resource::ServicesResourceHandler;
