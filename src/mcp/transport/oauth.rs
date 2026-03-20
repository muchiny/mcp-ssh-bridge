//! OAuth 2.0 Authentication Middleware for MCP HTTP Transport
//!
//! Validates Bearer tokens on incoming HTTP requests when OAuth is enabled.
//! Supports JWT validation with configurable issuer, audience, and scope checks.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, warn};

/// OAuth configuration for the HTTP transport.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthConfig {
    /// Enable OAuth authentication (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Expected issuer (e.g., `"https://auth.example.com"`).
    #[serde(default)]
    pub issuer: String,
    /// Expected audience.
    #[serde(default)]
    pub audience: String,
    /// JWKS endpoint for key validation (auto-discovered from issuer if not set).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OAuth client ID for this server.
    #[serde(default)]
    pub client_id: String,
    /// Required scopes for access.
    #[serde(default)]
    pub required_scopes: Vec<String>,
}

/// Validated token claims extracted from a Bearer token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// Subject (user/client identifier).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Scopes granted.
    pub scopes: Vec<String>,
}

impl TokenClaims {
    /// Check if the token has a specific scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// MCP-specific OAuth scopes.
pub mod scopes {
    /// Read tool definitions.
    pub const TOOLS_READ: &str = "mcp:tools:read";
    /// Execute tools.
    pub const TOOLS_EXECUTE: &str = "mcp:tools:execute";
    /// Read resources.
    pub const RESOURCES_READ: &str = "mcp:resources:read";
    /// Admin operations (logging, tasks).
    pub const ADMIN: &str = "mcp:admin";
}

/// OAuth validator that checks Bearer tokens.
pub struct OAuthValidator {
    config: OAuthConfig,
}

impl OAuthValidator {
    /// Create a new OAuth validator.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }

    /// Validate a Bearer token string.
    ///
    /// In a production implementation, this would verify JWT signatures
    /// against JWKS keys. For now, it performs basic structural validation
    /// and extracts claims from the JWT payload.
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, String> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format: expected 3 parts".to_string());
        }

        // Decode the payload (base64url)
        let payload =
            base64url_decode(parts[1]).map_err(|e| format!("Invalid JWT payload encoding: {e}"))?;

        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| format!("Invalid JWT payload JSON: {e}"))?;

        // Validate issuer
        if !self.config.issuer.is_empty() {
            let iss = claims["iss"].as_str().unwrap_or_default();
            if iss != self.config.issuer {
                return Err(format!(
                    "Invalid issuer: expected '{}', got '{iss}'",
                    self.config.issuer
                ));
            }
        }

        // Validate audience
        if !self.config.audience.is_empty() {
            let aud = claims["aud"].as_str().unwrap_or_default();
            if aud != self.config.audience {
                return Err(format!(
                    "Invalid audience: expected '{}', got '{aud}'",
                    self.config.audience
                ));
            }
        }

        // Extract scopes
        let scopes_str = claims["scope"].as_str().unwrap_or_default();
        let scopes: Vec<String> = scopes_str.split_whitespace().map(String::from).collect();

        // Check required scopes
        for required in &self.config.required_scopes {
            if !scopes.iter().any(|s| s == required) {
                return Err(format!("Missing required scope: {required}"));
            }
        }

        Ok(TokenClaims {
            sub: claims["sub"].as_str().unwrap_or_default().to_string(),
            iss: claims["iss"].as_str().unwrap_or_default().to_string(),
            scopes,
        })
    }
}

/// Axum middleware that validates OAuth Bearer tokens.
pub async fn oauth_middleware(request: Request, next: Next) -> Response {
    // Extract the OAuth config from extensions
    let config = request.extensions().get::<Arc<OAuthConfig>>().cloned();

    let Some(config) = config else {
        // No OAuth config in extensions — pass through
        return next.run(request).await;
    };

    if !config.enabled {
        return next.run(request).await;
    }

    // Extract Bearer token
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let Some(auth) = auth_header else {
        return unauthorized("Missing Authorization header");
    };

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return unauthorized("Invalid Authorization scheme, expected Bearer");
    };
    let token = token.trim();

    // Validate the token
    let validator = OAuthValidator::new((*config).clone());
    match validator.validate_token(token) {
        Ok(claims) => {
            debug!(sub = %claims.sub, scopes = ?claims.scopes, "Token validated");
            next.run(request).await
        }
        Err(e) => {
            warn!(error = %e, "Token validation failed");
            unauthorized(&e)
        }
    }
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "unauthorized",
            "message": message,
        })),
    )
        .into_response()
}

/// Decode a base64url-encoded string (no padding).
fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    // Replace URL-safe chars with standard base64
    let standard = input.replace('-', "+").replace('_', "/");

    // Add padding
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => standard,
    };

    base64_decode_simple(&padded).map_err(|e| format!("base64 decode error: {e}"))
}

/// Simple base64 decoder (avoids adding a base64 crate dependency).
#[allow(clippy::cast_possible_truncation)]
fn base64_decode_simple(input: &str) -> Result<Vec<u8>, &'static str> {
    fn decode_char(c: u8) -> Result<u8, &'static str> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err("invalid base64 character"),
        }
    }

    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("invalid base64 length");
    }

    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;

        let triple = u32::from(a) << 18 | u32::from(b) << 12 | u32::from(c) << 6 | u32::from(d);

        output.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(triple as u8);
        }
    }

    Ok(output)
}

/// OAuth Authorization Server Metadata (RFC 8414).
///
/// Returned by `GET /.well-known/oauth-authorization-server`.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

impl OAuthMetadata {
    /// Build metadata from an OAuth config.
    #[must_use]
    pub fn from_config(config: &OAuthConfig, base_url: &str) -> Self {
        Self {
            issuer: if config.issuer.is_empty() {
                base_url.to_string()
            } else {
                config.issuer.clone()
            },
            token_endpoint: format!("{base_url}/oauth/token"),
            scopes_supported: vec![
                scopes::TOOLS_READ.to_string(),
                scopes::TOOLS_EXECUTE.to_string(),
                scopes::RESOURCES_READ.to_string(),
                scopes::ADMIN.to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_decode() {
        // "Hello" in base64url
        let encoded = "SGVsbG8";
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");
    }

    #[test]
    fn test_base64url_decode_with_padding() {
        let encoded = "dGVzdA";
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "test");
    }

    #[test]
    fn test_token_claims_has_scope() {
        let claims = TokenClaims {
            sub: "user1".to_string(),
            iss: "test".to_string(),
            scopes: vec!["mcp:tools:read".to_string(), "mcp:admin".to_string()],
        };
        assert!(claims.has_scope("mcp:tools:read"));
        assert!(claims.has_scope("mcp:admin"));
        assert!(!claims.has_scope("mcp:tools:execute"));
    }

    #[test]
    fn test_oauth_config_default() {
        let config = OAuthConfig::default();
        assert!(!config.enabled);
        assert!(config.issuer.is_empty());
        assert!(config.required_scopes.is_empty());
    }

    #[test]
    fn test_oauth_metadata_from_config() {
        let config = OAuthConfig {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            ..Default::default()
        };
        let metadata = OAuthMetadata::from_config(&config, "https://mcp.example.com");
        assert_eq!(metadata.issuer, "https://auth.example.com");
        assert!(
            metadata
                .grant_types_supported
                .contains(&"client_credentials".to_string())
        );
    }

    #[test]
    fn test_validate_token_invalid_format() {
        let config = OAuthConfig::default();
        let validator = OAuthValidator::new(config);
        let result = validator.validate_token("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_token_valid_structure() {
        let config = OAuthConfig::default();
        let validator = OAuthValidator::new(config);

        // Create a minimal JWT with base64url-encoded payload
        let payload = serde_json::json!({
            "sub": "test-user",
            "iss": "",
            "aud": "",
            "scope": "mcp:tools:read mcp:admin"
        });
        let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let header_b64 = base64url_encode(b"{\"alg\":\"none\"}");
        let token = format!("{header_b64}.{payload_b64}.sig");

        let claims = validator.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.scopes.len(), 2);
        assert!(claims.has_scope("mcp:tools:read"));
    }

    #[allow(clippy::cast_possible_truncation)]
    fn base64url_encode(data: &[u8]) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let triple = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
            result.push(CHARSET[(triple >> 18) as usize & 63] as char);
            result.push(CHARSET[(triple >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                result.push(CHARSET[(triple >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                result.push(CHARSET[triple as usize & 63] as char);
            }
        }
        result.replace('+', "-").replace('/', "_")
    }
}
