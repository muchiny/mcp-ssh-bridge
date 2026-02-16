//! Database Command Builder
//!
//! Builds CLI commands for executing SQL queries, database dumps,
//! and restores on remote hosts via SSH.
//!
//! Supports `MySQL` and `PostgreSQL` databases. Commands are constructed
//! as shell strings to be executed on the remote host through the
//! standard SSH execution pipeline.

use std::fmt::Write;

use regex::Regex;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

/// Supported database types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
}

impl DatabaseType {
    /// Parse a database type from a string.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::DatabaseCommand` if the string is not a recognized database type.
    pub fn from_str_checked(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "mysql" => Ok(Self::MySQL),
            "postgresql" | "postgres" | "psql" => Ok(Self::PostgreSQL),
            other => Err(BridgeError::DatabaseCommand {
                reason: format!(
                    "Unsupported database type: '{other}'. Supported types: mysql, postgresql"
                ),
            }),
        }
    }

    /// Return the default port for this database type.
    #[must_use]
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::MySQL => 3306,
            Self::PostgreSQL => 5432,
        }
    }

    /// Return the default user for this database type.
    #[must_use]
    pub const fn default_user(&self) -> &'static str {
        match self {
            Self::MySQL => "root",
            Self::PostgreSQL => "postgres",
        }
    }
}

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Helper to write the password environment variable prefix.
///
/// **Security note:** Environment variables set this way (`MYSQL_PWD=... mysql ...`)
/// may be visible in `/proc/PID/environ` on Linux. This is more secure than passing
/// passwords as command-line arguments (visible in `ps`), but for maximum security
/// consider using connection files (`~/.my.cnf`, `~/.pgpass`) on the remote host.
fn write_password_env(cmd: &mut String, env_var: &str, password: &str) {
    let escaped_pw = password.replace('\'', "'\\''");
    let _ = write!(cmd, "{env_var}='{escaped_pw}' ");
}

/// Helper to write the compression suffix or plain redirect.
fn write_compression_suffix(cmd: &mut String, compress: Option<&str>, output_file: &str) {
    let escaped_file = shell_escape(output_file);
    match compress {
        Some("gzip") => {
            let _ = write!(cmd, " | gzip > {escaped_file}");
        }
        Some("bzip2") => {
            let _ = write!(cmd, " | bzip2 > {escaped_file}");
        }
        Some("xz") => {
            let _ = write!(cmd, " | xz > {escaped_file}");
        }
        _ => {
            let _ = write!(cmd, " > {escaped_file}");
        }
    }
}

/// Builds database CLI commands for remote execution.
pub struct DatabaseCommandBuilder;

impl DatabaseCommandBuilder {
    /// Build a SQL query command.
    ///
    /// For `MySQL`: `MYSQL_PWD='password' mysql -h host -P port -u user database -e "query"`
    /// For `PostgreSQL`: `PGPASSWORD='password' psql -h host -p port -U user -d database -c "query"`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_query_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        query: &str,
        format: Option<&str>,
    ) -> String {
        let escaped_query = query.replace('\'', "'\\''");
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "MYSQL_PWD", password);
                }

                let _ = write!(
                    cmd,
                    "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} -e '{escaped_query}'"
                );

                if let Some("csv") = format {
                    cmd.push_str(" -B");
                }
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "PGPASSWORD", password);
                }

                let _ = write!(
                    cmd,
                    "psql -h {escaped_host} -p {db_port} -U {escaped_user} -d {escaped_db} -c '{escaped_query}'"
                );

                if let Some("csv") = format {
                    cmd.push_str(" --csv");
                }
            }
        }

        cmd
    }

    /// Build a database dump command.
    ///
    /// For `MySQL`: `MYSQL_PWD='password' mysqldump -h host -P port -u user database`
    /// For `PostgreSQL`: `PGPASSWORD='password' pg_dump -h host -p port -U user database`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_dump_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        tables: Option<&[String]>,
        compress: Option<&str>,
        output_file: &str,
    ) -> String {
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "MYSQL_PWD", password);
                }

                let _ = write!(
                    cmd,
                    "mysqldump -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db}"
                );

                if let Some(table_list) = tables {
                    for table in table_list {
                        let _ = write!(cmd, " {}", shell_escape(table));
                    }
                }
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "PGPASSWORD", password);
                }

                let _ = write!(
                    cmd,
                    "pg_dump -h {escaped_host} -p {db_port} -U {escaped_user} {escaped_db}"
                );

                if let Some(table_list) = tables {
                    for table in table_list {
                        let _ = write!(cmd, " -t {}", shell_escape(table));
                    }
                }
            }
        }

        write_compression_suffix(&mut cmd, compress, output_file);

        cmd
    }

    /// Build a database restore command.
    ///
    /// For `MySQL`: `MYSQL_PWD='password' mysql -h host -P port -u user database < input_file`
    /// For `PostgreSQL`: `PGPASSWORD='password' psql -h host -p port -U user -d database < input_file`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_restore_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        input_file: &str,
    ) -> String {
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let escaped_file = shell_escape(input_file);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "MYSQL_PWD", password);
                }

                let _ = write!(
                    cmd,
                    "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} < {escaped_file}"
                );
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_password_env(&mut cmd, "PGPASSWORD", password);
                }

                let _ = write!(
                    cmd,
                    "psql -h {escaped_host} -p {db_port} -U {escaped_user} -d {escaped_db} < {escaped_file}"
                );
            }
        }

        cmd
    }

    /// Validate a SQL query for dangerous patterns.
    ///
    /// Rejects queries containing DROP DATABASE, DROP TABLE, TRUNCATE,
    /// DELETE FROM, ALTER TABLE ... DROP, GRANT, REVOKE.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the query matches a dangerous pattern.
    pub fn validate_query(query: &str) -> Result<()> {
        let dangerous_patterns = [
            (r"(?i)\bDROP\s+DATABASE\b", "DROP DATABASE"),
            (r"(?i)\bDROP\s+TABLE\b", "DROP TABLE"),
            (r"(?i)\bTRUNCATE\b", "TRUNCATE"),
            (r"(?i)\bDELETE\s+FROM\b", "DELETE FROM"),
            (r"(?i)\bALTER\s+TABLE\b.*\bDROP\b", "ALTER TABLE ... DROP"),
            (r"(?i)\bGRANT\b", "GRANT"),
            (r"(?i)\bREVOKE\b", "REVOKE"),
        ];

        for (pattern, name) in &dangerous_patterns {
            let re = Regex::new(pattern).expect("invalid regex in dangerous_patterns");
            if re.is_match(query) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Dangerous SQL operation '{name}' is not allowed via ssh_db_query. \
                         Use a direct database client for destructive operations."
                    ),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== DatabaseType Tests ==============

    #[test]
    fn test_database_type_from_str_mysql() {
        let dt = DatabaseType::from_str_checked("mysql").unwrap();
        assert_eq!(dt, DatabaseType::MySQL);
    }

    #[test]
    fn test_database_type_from_str_postgresql() {
        let dt = DatabaseType::from_str_checked("postgresql").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_postgres() {
        let dt = DatabaseType::from_str_checked("postgres").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_psql() {
        let dt = DatabaseType::from_str_checked("psql").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_case_insensitive() {
        assert_eq!(
            DatabaseType::from_str_checked("MySQL").unwrap(),
            DatabaseType::MySQL
        );
        assert_eq!(
            DatabaseType::from_str_checked("POSTGRESQL").unwrap(),
            DatabaseType::PostgreSQL
        );
    }

    #[test]
    fn test_database_type_from_str_invalid() {
        let result = DatabaseType::from_str_checked("sqlite");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::DatabaseCommand { reason } => {
                assert!(reason.contains("sqlite"));
            }
            e => panic!("Expected DatabaseCommand error, got: {e:?}"),
        }
    }

    #[test]
    fn test_database_type_default_port() {
        assert_eq!(DatabaseType::MySQL.default_port(), 3306);
        assert_eq!(DatabaseType::PostgreSQL.default_port(), 5432);
    }

    #[test]
    fn test_database_type_default_user() {
        assert_eq!(DatabaseType::MySQL.default_user(), "root");
        assert_eq!(DatabaseType::PostgreSQL.default_user(), "postgres");
    }

    #[test]
    fn test_database_type_debug() {
        let dt = DatabaseType::MySQL;
        let debug = format!("{dt:?}");
        assert!(debug.contains("MySQL"));
    }

    #[test]
    fn test_database_type_clone() {
        let dt = DatabaseType::PostgreSQL;
        let cloned = dt.clone();
        assert_eq!(dt, cloned);
    }

    // ============== build_query_command Tests (MySQL) ==============

    #[test]
    fn test_build_query_mysql_all_options() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "dbhost",
            3306,
            "admin",
            Some("secret"),
            "mydb",
            "SELECT * FROM users",
            Some("csv"),
        );
        assert!(cmd.starts_with("MYSQL_PWD='secret' "));
        assert!(cmd.contains("mysql -h 'dbhost' -P 3306 -u 'admin' 'mydb'"));
        assert!(cmd.contains("-e 'SELECT * FROM users'"));
        assert!(cmd.contains("-B"));
    }

    #[test]
    fn test_build_query_mysql_no_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        assert!(!cmd.contains("MYSQL_PWD"));
        assert!(cmd.starts_with("mysql -h 'localhost'"));
        assert!(cmd.contains("-e 'SELECT 1'"));
    }

    #[test]
    fn test_build_query_mysql_table_format() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            Some("table"),
        );
        assert!(!cmd.contains("-B"));
    }

    #[test]
    fn test_build_query_mysql_json_format() {
        // JSON not natively supported, should use default (no extra flag)
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            Some("json"),
        );
        assert!(!cmd.contains("-B"));
    }

    // ============== build_query_command Tests (PostgreSQL) ==============

    #[test]
    fn test_build_query_postgresql_all_options() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "pghost",
            5432,
            "pguser",
            Some("pgpass"),
            "pgdb",
            "SELECT * FROM orders",
            Some("csv"),
        );
        assert!(cmd.starts_with("PGPASSWORD='pgpass' "));
        assert!(cmd.contains("psql -h 'pghost' -p 5432 -U 'pguser' -d 'pgdb'"));
        assert!(cmd.contains("-c 'SELECT * FROM orders'"));
        assert!(cmd.contains("--csv"));
    }

    #[test]
    fn test_build_query_postgresql_no_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        assert!(!cmd.contains("PGPASSWORD"));
        assert!(cmd.starts_with("psql -h 'localhost'"));
    }

    #[test]
    fn test_build_query_postgresql_table_format() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "testdb",
            "SELECT 1",
            Some("table"),
        );
        assert!(!cmd.contains("--csv"));
    }

    // ============== build_query_command with special characters ==============

    #[test]
    fn test_build_query_escapes_single_quotes_in_query() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT * FROM users WHERE name = 'O'Brien'",
            None,
        );
        assert!(cmd.contains("O'\\''Brien"));
    }

    #[test]
    fn test_build_query_escapes_single_quotes_in_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass'word"),
            "testdb",
            "SELECT 1",
            None,
        );
        assert!(cmd.contains("MYSQL_PWD='pass'\\''word'"));
    }

    // ============== build_dump_command Tests ==============

    #[test]
    fn test_build_dump_mysql_basic() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass"),
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("MYSQL_PWD='pass'"));
        assert!(cmd.contains("mysqldump -h 'localhost' -P 3306 -u 'root' 'mydb'"));
        assert!(cmd.contains("> '/tmp/dump.sql'"));
        assert!(!cmd.contains("| gzip"));
    }

    #[test]
    fn test_build_dump_mysql_with_tables() {
        let tables = vec!["users".to_string(), "orders".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("'mydb' 'users' 'orders'"));
    }

    #[test]
    fn test_build_dump_mysql_gzip() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("gzip"),
            "/tmp/dump.sql.gz",
        );
        assert!(cmd.contains("| gzip > '/tmp/dump.sql.gz'"));
    }

    #[test]
    fn test_build_dump_mysql_bzip2() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("bzip2"),
            "/tmp/dump.sql.bz2",
        );
        assert!(cmd.contains("| bzip2 > '/tmp/dump.sql.bz2'"));
    }

    #[test]
    fn test_build_dump_mysql_xz() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("xz"),
            "/tmp/dump.sql.xz",
        );
        assert!(cmd.contains("| xz > '/tmp/dump.sql.xz'"));
    }

    #[test]
    fn test_build_dump_postgresql_basic() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            Some("pgpass"),
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("PGPASSWORD='pgpass'"));
        assert!(cmd.contains("pg_dump -h 'localhost' -p 5432 -U 'postgres' 'mydb'"));
        assert!(cmd.contains("> '/tmp/dump.sql'"));
    }

    #[test]
    fn test_build_dump_postgresql_with_tables() {
        let tables = vec!["users".to_string(), "orders".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("-t 'users'"));
        assert!(cmd.contains("-t 'orders'"));
    }

    #[test]
    fn test_build_dump_postgresql_gzip() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "mydb",
            None,
            Some("gzip"),
            "/tmp/dump.sql.gz",
        );
        assert!(cmd.contains("| gzip > '/tmp/dump.sql.gz'"));
    }

    #[test]
    fn test_build_dump_no_password() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        assert!(!cmd.contains("MYSQL_PWD"));
    }

    // ============== build_restore_command Tests ==============

    #[test]
    fn test_build_restore_mysql() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass"),
            "mydb",
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("MYSQL_PWD='pass'"));
        assert!(cmd.contains("mysql -h 'localhost' -P 3306 -u 'root' 'mydb' < '/tmp/dump.sql'"));
    }

    #[test]
    fn test_build_restore_postgresql() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            Some("pgpass"),
            "mydb",
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("PGPASSWORD='pgpass'"));
        assert!(
            cmd.contains("psql -h 'localhost' -p 5432 -U 'postgres' -d 'mydb' < '/tmp/dump.sql'")
        );
    }

    #[test]
    fn test_build_restore_no_password() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            "/tmp/dump.sql",
        );
        assert!(!cmd.contains("MYSQL_PWD"));
        assert!(cmd.starts_with("mysql"));
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_build_query_host_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost && whoami > /tmp/pwned",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        // The malicious host should be wrapped in single quotes, neutralizing the injection
        assert!(cmd.contains("-h 'localhost && whoami > /tmp/pwned'"));
        assert!(!cmd.contains("-h localhost && whoami"));
    }

    #[test]
    fn test_build_dump_table_injection_prevented() {
        let tables = vec!["users; rm -rf /".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        // Table name should be escaped, not interpreted as a command
        assert!(cmd.contains("'users; rm -rf /'"));
        assert!(!cmd.contains("mydb users; rm -rf /"));
    }

    #[test]
    fn test_build_dump_output_file_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            None,
            "/tmp/dump.sql; cat /etc/passwd",
        );
        // output_file should be escaped
        assert!(cmd.contains("> '/tmp/dump.sql; cat /etc/passwd'"));
    }

    #[test]
    fn test_build_restore_input_file_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            "/tmp/dump.sql; cat /etc/shadow",
        );
        assert!(cmd.contains("< '/tmp/dump.sql; cat /etc/shadow'"));
    }

    // ============== validate_query Tests ==============

    #[test]
    fn test_validate_query_safe_select() {
        assert!(DatabaseCommandBuilder::validate_query("SELECT * FROM users").is_ok());
    }

    #[test]
    fn test_validate_query_safe_insert() {
        assert!(
            DatabaseCommandBuilder::validate_query("INSERT INTO logs (msg) VALUES ('test')")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_query_safe_update() {
        assert!(
            DatabaseCommandBuilder::validate_query("UPDATE users SET name='test' WHERE id=1")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_query_drop_database() {
        let result = DatabaseCommandBuilder::validate_query("DROP DATABASE mydb");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("DROP DATABASE"));
            }
            e => panic!("Expected CommandDenied error, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_query_drop_table() {
        let result = DatabaseCommandBuilder::validate_query("DROP TABLE users");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_truncate() {
        let result = DatabaseCommandBuilder::validate_query("TRUNCATE TABLE users");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_delete_from() {
        let result = DatabaseCommandBuilder::validate_query("DELETE FROM users WHERE id=1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_alter_drop() {
        let result = DatabaseCommandBuilder::validate_query("ALTER TABLE users DROP COLUMN email");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_grant() {
        let result =
            DatabaseCommandBuilder::validate_query("GRANT ALL PRIVILEGES ON mydb.* TO 'user'@'%'");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_revoke() {
        let result =
            DatabaseCommandBuilder::validate_query("REVOKE ALL PRIVILEGES ON mydb.* FROM 'user'");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_case_insensitive() {
        assert!(DatabaseCommandBuilder::validate_query("drop database mydb").is_err());
        assert!(DatabaseCommandBuilder::validate_query("Drop Table users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("TRUNCATE table users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("delete from users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("grant all on mydb").is_err());
        assert!(DatabaseCommandBuilder::validate_query("revoke all on mydb").is_err());
    }

    #[test]
    fn test_validate_query_mixed_case() {
        assert!(DatabaseCommandBuilder::validate_query("dRoP dAtAbAsE mydb").is_err());
    }

    #[test]
    fn test_validate_query_alter_without_drop_is_ok() {
        assert!(
            DatabaseCommandBuilder::validate_query("ALTER TABLE users ADD COLUMN age INT").is_ok()
        );
    }

    #[test]
    fn test_validate_query_show_tables_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("SHOW TABLES").is_ok());
    }

    #[test]
    fn test_validate_query_describe_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("DESCRIBE users").is_ok());
    }

    #[test]
    fn test_validate_query_explain_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("EXPLAIN SELECT * FROM users").is_ok());
    }
}
