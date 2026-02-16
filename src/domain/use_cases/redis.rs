//! Redis Command Builder
//!
//! Builds Redis CLI commands for remote execution via SSH.
//! Supports info, arbitrary CLI commands, and key scanning.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds Redis CLI commands for remote execution.
pub struct RedisCommandBuilder;

impl RedisCommandBuilder {
    /// Build a `redis-cli INFO` command.
    ///
    /// Constructs: `redis-cli [-h {host}] [-p {port}] [-a {password}] INFO [{section}]`
    #[must_use]
    pub fn build_info_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        section: Option<&str>,
    ) -> String {
        let mut cmd = String::from("redis-cli");

        if let Some(h) = redis_host {
            let _ = write!(cmd, " -h {}", shell_escape(h));
        }

        if let Some(p) = redis_port {
            let _ = write!(cmd, " -p {p}");
        }

        cmd.push_str(" INFO");

        if let Some(s) = section {
            let _ = write!(cmd, " {}", shell_escape(s));
        }

        cmd
    }

    /// Validate that a Redis command starts with an allowed keyword.
    ///
    /// Blocks dangerous commands like `FLUSHALL`, `FLUSHDB`, `SHUTDOWN`, `EVAL`,
    /// `SCRIPT`, and `BGSAVE`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the command is not in the allow-list.
    pub fn validate_redis_command(command: &str) -> Result<()> {
        const ALLOWED: &[&str] = &[
            // String operations
            "GET",
            "SET",
            "DEL",
            "EXISTS",
            "EXPIRE",
            "TTL",
            "PTTL",
            "TYPE",
            "RENAME",
            "PERSIST",
            "KEYS",
            "SCAN",
            "MGET",
            "MSET",
            "INCR",
            "DECR",
            "INCRBY",
            "DECRBY",
            "APPEND",
            "STRLEN",
            "GETRANGE",
            "SETRANGE",
            "SETNX",
            "SETEX",
            "PSETEX",
            "GETSET",
            "GETDEL",
            // Hash operations
            "HGET",
            "HSET",
            "HDEL",
            "HEXISTS",
            "HGETALL",
            "HKEYS",
            "HVALS",
            "HLEN",
            "HMGET",
            "HMSET",
            "HINCRBY",
            "HSCAN",
            // List operations
            "LPUSH",
            "RPUSH",
            "LPOP",
            "RPOP",
            "LRANGE",
            "LLEN",
            "LINDEX",
            "LSET",
            "LREM",
            "LTRIM",
            // Set operations
            "SADD",
            "SREM",
            "SMEMBERS",
            "SISMEMBER",
            "SCARD",
            "SUNION",
            "SINTER",
            "SDIFF",
            "SSCAN",
            // Sorted set operations
            "ZADD",
            "ZREM",
            "ZRANGE",
            "ZRANGEBYSCORE",
            "ZREVRANGE",
            "ZRANK",
            "ZSCORE",
            "ZCARD",
            "ZCOUNT",
            "ZSCAN",
            // General/info
            "PING",
            "ECHO",
            "INFO",
            "DBSIZE",
            "TIME",
            "LASTSAVE",
            "SLOWLOG",
            "OBJECT",
            "MEMORY",
            "CLIENT",
            "PUBSUB",
            "SELECT",
            "DUMP",
            "RESTORE",
        ];
        let first_word = command.split_whitespace().next().unwrap_or("");
        let upper = first_word.to_uppercase();
        if ALLOWED.contains(&upper.as_str()) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Redis command '{first_word}' is not allowed. Dangerous commands \
                     (FLUSHALL, FLUSHDB, SHUTDOWN, EVAL, SCRIPT, etc.) are blocked."
                ),
            })
        }
    }

    /// Build a `redis-cli` command for arbitrary operations.
    ///
    /// Constructs: `redis-cli [-h {host}] [-p {port}] {command}`
    #[must_use]
    pub fn build_cli_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        command: &str,
    ) -> String {
        let mut cmd = String::from("redis-cli");

        if let Some(h) = redis_host {
            let _ = write!(cmd, " -h {}", shell_escape(h));
        }

        if let Some(p) = redis_port {
            let _ = write!(cmd, " -p {p}");
        }

        let _ = write!(cmd, " {}", shell_escape(command));
        cmd
    }

    /// Build a `redis-cli SCAN` command to find keys.
    ///
    /// Uses SCAN instead of KEYS to avoid blocking.
    /// Constructs: `redis-cli [-h {host}] [-p {port}] --scan --pattern {pattern} [--count {n}]`
    #[must_use]
    pub fn build_keys_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        pattern: Option<&str>,
        count: Option<u32>,
    ) -> String {
        let mut cmd = String::from("redis-cli");

        if let Some(h) = redis_host {
            let _ = write!(cmd, " -h {}", shell_escape(h));
        }

        if let Some(p) = redis_port {
            let _ = write!(cmd, " -p {p}");
        }

        let pat = pattern.unwrap_or("*");
        let _ = write!(cmd, " --scan --pattern {}", shell_escape(pat));

        if let Some(c) = count {
            let _ = write!(cmd, " --count {c}");
        }

        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_default() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, None);
        assert_eq!(cmd, "redis-cli INFO");
    }

    #[test]
    fn test_info_with_host_port() {
        let cmd = RedisCommandBuilder::build_info_command(Some("10.0.0.1"), Some(6380), None);
        assert!(cmd.contains("-h '10.0.0.1'"));
        assert!(cmd.contains("-p 6380"));
    }

    #[test]
    fn test_info_with_section() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, Some("memory"));
        assert!(cmd.contains("INFO 'memory'"));
    }

    #[test]
    fn test_cli_command() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "GET mykey");
        assert_eq!(cmd, "redis-cli 'GET mykey'");
    }

    #[test]
    fn test_cli_with_host() {
        let cmd = RedisCommandBuilder::build_cli_command(Some("redis.local"), Some(6379), "PING");
        assert!(cmd.contains("-h 'redis.local'"));
        assert!(cmd.contains("-p 6379"));
        assert!(cmd.contains("PING"));
    }

    #[test]
    fn test_keys_default() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, None);
        assert!(cmd.contains("--scan --pattern '*'"));
    }

    #[test]
    fn test_keys_with_pattern() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, Some("user:*"), None);
        assert!(cmd.contains("--pattern 'user:*'"));
    }

    #[test]
    fn test_keys_with_count() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(100));
        assert!(cmd.contains("--count 100"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_info_injection_in_host() {
        let cmd =
            RedisCommandBuilder::build_info_command(Some("redis.local; rm -rf /"), None, None);
        assert!(cmd.contains("-h 'redis.local; rm -rf /'"));
    }

    #[test]
    fn test_info_injection_in_section() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, Some("memory; whoami"));
        assert!(cmd.contains("INFO 'memory; whoami'"));
    }

    #[test]
    fn test_keys_injection_in_pattern() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, Some("*; rm -rf /"), None);
        assert!(cmd.contains("--pattern '*; rm -rf /'"));
    }

    #[test]
    fn test_cli_command_escaped() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "GET key; rm -rf /");
        assert!(cmd.contains("'GET key; rm -rf /'"));
    }

    #[test]
    fn test_validate_redis_command_allowed() {
        assert!(RedisCommandBuilder::validate_redis_command("GET mykey").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("SET key value").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("HGETALL myhash").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("PING").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("INFO").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("KEYS *").is_ok());
    }

    #[test]
    fn test_validate_redis_command_denied() {
        assert!(RedisCommandBuilder::validate_redis_command("FLUSHALL").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("FLUSHDB").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SHUTDOWN").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SHUTDOWN NOSAVE").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("EVAL script").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SCRIPT LOAD").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("BGSAVE").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("CONFIG SET").is_err());
    }

    #[test]
    fn test_validate_redis_command_case_insensitive() {
        assert!(RedisCommandBuilder::validate_redis_command("get mykey").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("flushall").is_err());
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_info_all_options() {
        let cmd = RedisCommandBuilder::build_info_command(
            Some("redis.prod"),
            Some(6380),
            Some("replication"),
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("INFO 'replication'"));
    }

    #[test]
    fn test_cli_all_options() {
        let cmd = RedisCommandBuilder::build_cli_command(
            Some("redis.prod"),
            Some(6380),
            "SET mykey myvalue",
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("'SET mykey myvalue'"));
    }

    #[test]
    fn test_keys_all_options() {
        let cmd = RedisCommandBuilder::build_keys_command(
            Some("redis.prod"),
            Some(6380),
            Some("session:*"),
            Some(200),
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("--pattern 'session:*'"));
        assert!(cmd.contains("--count 200"));
    }

    // ============== Minimal Command Tests ==============

    #[test]
    fn test_cli_minimal() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "PING");
        assert_eq!(cmd, "redis-cli 'PING'");
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_info_host_with_single_quotes() {
        let cmd = RedisCommandBuilder::build_info_command(Some("it's-redis"), None, None);
        assert!(cmd.contains("-h 'it'\\''s-redis'"));
    }

    #[test]
    fn test_info_port_boundary_low() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(1), None);
        assert!(cmd.contains("-p 1"));
    }

    #[test]
    fn test_info_port_boundary_high() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(65535), None);
        assert!(cmd.contains("-p 65535"));
    }

    #[test]
    fn test_keys_pattern_complex_glob() {
        let cmd =
            RedisCommandBuilder::build_keys_command(None, None, Some("user:*:session:*"), None);
        assert!(cmd.contains("--pattern 'user:*:session:*'"));
    }

    #[test]
    fn test_keys_count_zero() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(0));
        assert!(cmd.contains("--count 0"));
    }

    #[test]
    fn test_keys_count_large() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(100_000));
        assert!(cmd.contains("--count 100000"));
    }

    #[test]
    fn test_info_host_only() {
        let cmd = RedisCommandBuilder::build_info_command(Some("10.0.0.1"), None, None);
        assert!(cmd.contains("-h '10.0.0.1'"));
        assert!(!cmd.contains("-p"));
    }

    #[test]
    fn test_info_port_only() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(6380), None);
        assert!(cmd.contains("-p 6380"));
        assert!(!cmd.contains("-h"));
    }

    #[test]
    fn test_keys_no_count() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, Some("*"), None);
        assert!(!cmd.contains("--count"));
    }

    #[test]
    fn test_cli_empty_command() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "");
        assert_eq!(cmd, "redis-cli ''");
    }
}
