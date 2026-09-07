use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Database {
    #[cfg(feature = "db")]
    conn: rusqlite::Connection,
}

impl Database {
    #[cfg(feature = "db")]
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = rusqlite::Connection::open(path).context("failed to open sqlite database")?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    #[cfg(not(feature = "db"))]
    pub fn open(path: &std::path::Path) -> Result<Self> {
        tracing::trace!(
            "db open requested for {} (db feature disabled)",
            path.display()
        );
        anyhow::bail!("database support not compiled (enable 'db' feature)");
    }

    #[cfg(feature = "db")]
    fn init_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                hostname TEXT,
                os TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                version TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                UNIQUE(host_id, port, protocol)
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                username TEXT NOT NULL,
                password TEXT,
                source_module TEXT,
                discovered DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
            CREATE INDEX IF NOT EXISTS idx_credentials_host ON credentials(host);",
            )
            .context("initializing sqlite tables")?;
        Ok(())
    }

    #[cfg(feature = "db")]
    pub fn insert_host(&self, ip: &str, hostname: Option<&str>, os: Option<&str>) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO hosts (ip, hostname, os, last_seen) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)",
                rusqlite::params![ip, hostname, os],
            )
            .context("insert host")?;
        Ok(())
    }

    #[cfg(not(feature = "db"))]
    pub fn insert_host(&self, ip: &str, hostname: Option<&str>, os: Option<&str>) -> Result<()> {
        tracing::trace!(
            "db insert_host no-op without 'db' feature (ip: {ip}, hostname: {:?}, os: {:?})",
            hostname,
            os
        );
        Ok(())
    }

    #[cfg(feature = "db")]
    pub fn insert_credential(
        &self,
        host: &str,
        port: u16,
        service: &str,
        username: &str,
        password: &str,
        source_module: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO credentials (host, port, service, username, password, source_module) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![host, port, service, username, password, source_module],
            )
            .context("insert credential")?;
        Ok(())
    }

    #[cfg(not(feature = "db"))]
    pub fn insert_credential(
        &self,
        host: &str,
        port: u16,
        service: &str,
        username: &str,
        password: &str,
        source_module: &str,
    ) -> Result<()> {
        // Never log the credential value itself — only its shape.
        tracing::trace!(
            "db insert_credential no-op without 'db' feature (host: {host}, port: {port}, service: {service}, user: {username}, pass len: {}, source: {source_module})",
            password.len()
        );
        Ok(())
    }
}

pub type SharedDb = Arc<Mutex<Database>>;

pub fn open_default() -> Result<SharedDb> {
    let mut path = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    path.push(".rustsploit");
    std::fs::create_dir_all(&path).context("create .rustsploit directory")?;
    path.push("rustsploit.db");
    let db = Database::open(&path)?;
    Ok(Arc::new(Mutex::new(db)))
}
