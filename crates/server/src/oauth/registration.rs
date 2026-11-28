use super::{OAuth, OAuthError, Result};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::OptionalExtension;
use rusqlite::{Connection, TransactionBehavior};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_SOURCES: usize = 4096;
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct RegistrationRate(Mutex<HashMap<IpAddr, (Instant, usize)>>);

pub(super) async fn limit(
    State(oauth): State<Arc<OAuth>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if oauth
        .registration_rate
        .admit(peer.ip(), oauth.config.oauth_registrations_per_minute)
    {
        return next.run(request).await;
    }
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "registration_rate_limit"
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    response
}

impl RegistrationRate {
    fn admit(&self, source: IpAddr, limit: usize) -> bool {
        let Ok(mut sources) = self.0.lock() else {
            return false;
        };
        let now = Instant::now();
        sources.retain(|_, (started, _)| now.duration_since(*started) < WINDOW);
        let source = source.to_canonical();
        if sources.len() == MAX_SOURCES && !sources.contains_key(&source) {
            return false;
        }
        let (_, count) = sources.entry(source).or_insert((now, 0));
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    }
}

pub(super) fn migrate(db: &Connection, cap: usize) -> rusqlite::Result<()> {
    let has_last_used: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('oauth_clients') WHERE name = 'last_used')",
        [],
        |row| row.get(0),
    )?;
    let has_secret: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('oauth_clients') WHERE name = 'secret_hash')",
        [],
        |row| row.get(0),
    )?;
    if !has_secret {
        db.execute_batch("ALTER TABLE oauth_clients ADD COLUMN secret_hash BLOB;")?;
    }
    if !has_last_used {
        db.execute_batch(
            "ALTER TABLE oauth_clients ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0;
             UPDATE oauth_clients SET last_used = unixepoch();",
        )?;
    }
    // Existing databases may predate the cap. Keep the most recently used clients.
    db.execute(
        "DELETE FROM oauth_clients WHERE id IN (
            SELECT id FROM oauth_clients ORDER BY last_used DESC, rowid DESC LIMIT -1 OFFSET ?1
         )",
        [cap],
    )?;
    purge(db)
}

fn purge(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "DELETE FROM oauth_clients WHERE last_used <= unixepoch() - 30 * 86400;
         DELETE FROM oauth_codes WHERE client NOT IN (SELECT id FROM oauth_clients);
         DELETE FROM oauth_sessions WHERE client NOT IN (SELECT id FROM oauth_clients);
         DELETE FROM oauth_rotated_refresh WHERE client NOT IN (SELECT id FROM oauth_clients);",
    )
}

impl OAuth {
    /// The secret hash of a client, when it registered as a confidential one (`client_secret_post` or `_basic`).
    pub(super) fn client_secret_hash(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db()?;
        Ok(db
            .query_row(
                "SELECT secret_hash FROM oauth_clients WHERE id = ?1",
                [id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
    }

    pub(super) fn register_client(
        &self,
        id: &str,
        name: &str,
        redirects: &[String],
        secret_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        let redirects = serde_json::to_string(redirects)?;
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge(&tx)?;
        let count: usize =
            tx.query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| row.get(0))?;
        if count >= self.config.oauth_registration_cap {
            tx.commit()?;
            return Err(OAuthError::RegistrationCapacity);
        }
        tx.execute(
            "INSERT INTO oauth_clients (id, name, redirects, last_used, secret_hash)
             VALUES (?1, ?2, ?3, unixepoch(), ?4)",
            (id, name, redirects, secret_hash.map(|hash| hash.to_vec())),
        )?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn touch(db: &Connection, client: &str) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE oauth_clients SET last_used = unixepoch()
         WHERE id = ?1 AND last_used > unixepoch() - 30 * 86400",
        [client],
    )
}
