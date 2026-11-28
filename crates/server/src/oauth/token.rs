use super::{
    field, hash, random_secret, registration::touch, resource_matches, Fields, OAuth, OAuthError,
    Result, ACCESS_TTL, REFRESH_TTL,
};
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// The client credentials of a token request: HTTP Basic (`client_secret_basic`) or the form fields
/// (`client_secret_post`, or `client_id` alone for a public client).
fn credentials(headers: &HeaderMap, fields: &Fields) -> (String, Option<String>) {
    if let Some((id, secret)) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Basic ")
                .or_else(|| value.strip_prefix("basic "))
        })
        .and_then(|encoded| STANDARD.decode(encoded.trim()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|pair| {
            pair.split_once(':')
                .map(|(id, secret)| (id.to_owned(), secret.to_owned()))
        })
    {
        let id = urlencoding_decode(&id);
        let secret = urlencoding_decode(&secret);
        return (id, Some(secret));
    }
    let secret = field(fields, "client_secret");
    (
        field(fields, "client_id").to_owned(),
        (!secret.is_empty()).then(|| secret.to_owned()),
    )
}

/// RFC 6749 section 2.3.1: Basic credentials are form-urlencoded before being base64 encoded.
fn urlencoding_decode(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_default()
}

pub(super) async fn token(
    State(oauth): State<Arc<OAuth>>,
    headers: HeaderMap,
    Form(fields): Form<Fields>,
) -> Result<Response> {
    resource_matches(&oauth, &fields)?;
    let (client_id, secret) = credentials(&headers, &fields);
    let client = client_id.as_str();
    // A client that registered with a secret must present it (PKCE is still required below); a public one has none.
    if let Some(expected) = oauth.client_secret_hash(client)? {
        let presented = secret.as_deref().map(hash);
        if !presented.is_some_and(|presented| bool::from(presented.as_slice().ct_eq(&expected))) {
            return Err(OAuthError::InvalidClient);
        }
    }
    let mut db = oauth.db()?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scope: String = match field(&fields, "grant_type") {
        "authorization_code" => {
            let code = hash(field(&fields, "code"));
            let (challenge, scope): (String, String) = tx
                .query_row(
                    "DELETE FROM oauth_codes WHERE hash = ?1 AND client = ?2 AND redirect = ?3
                    AND expires_at > unixepoch() RETURNING challenge, scope",
                    (code, client, field(&fields, "redirect_uri")),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(OAuthError::BadRequest("invalid_grant"))?;
            let verifier = field(&fields, "code_verifier");
            if !(43..=128).contains(&verifier.len())
                || !verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                || !bool::from(
                    challenge
                        .as_bytes()
                        .ct_eq(URL_SAFE_NO_PAD.encode(hash(verifier)).as_bytes()),
                )
            {
                return Err(OAuthError::BadRequest("invalid_grant"));
            }
            scope
        }
        "refresh_token" => {
            let refresh_hash = hash(field(&fields, "refresh_token"));
            let Some(scope) = rotate_refresh(&tx, client, refresh_hash)? else {
                tx.commit()?;
                return Err(OAuthError::BadRequest("invalid_grant"));
            };
            scope
        }
        _ => return Err(OAuthError::BadRequest("unsupported_grant_type")),
    };
    if touch(&tx, client)? == 0 {
        return Err(OAuthError::BadRequest("invalid_grant"));
    }
    let access = random_secret()?;
    let refresh = random_secret()?;
    let expired = tx.execute(
        "DELETE FROM oauth_sessions WHERE refresh_until <= unixepoch()",
        [],
    )?;
    tx.execute(
        "INSERT INTO oauth_sessions VALUES (?1, ?2, ?3, ?4, unixepoch() + ?5, unixepoch() + ?6)",
        (
            hash(&access),
            hash(&refresh),
            client,
            scope,
            ACCESS_TTL,
            REFRESH_TTL,
        ),
    )?;
    if expired > 0 {
        prune_rotated_refreshes(&tx)?;
    }
    tx.commit()?;
    Ok(Json(json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "scope": "memory",
    }))
    .into_response())
}

fn rotate_refresh(
    tx: &Transaction<'_>,
    client: &str,
    refresh_hash: [u8; 32],
) -> Result<Option<String>> {
    let scope: Option<String> = tx
        .query_row(
            "DELETE FROM oauth_sessions WHERE refresh_hash = ?1 AND client = ?2
             AND refresh_until > unixepoch() RETURNING scope",
            (refresh_hash, client),
            |row| row.get(0),
        )
        .optional()?;
    if let Some(scope) = &scope {
        tx.execute(
            "INSERT INTO oauth_rotated_refresh (hash, client, scope) VALUES (?1, ?2, ?3)",
            (refresh_hash, client, scope),
        )?;
    } else if let Some(reused_scope) = tx
        .query_row(
            "SELECT scope FROM oauth_rotated_refresh WHERE hash = ?1 AND client = ?2",
            (refresh_hash, client),
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        // The scope contains a unique ID minted when consent is granted.
        tx.execute(
            "DELETE FROM oauth_sessions WHERE client = ?1 AND scope = ?2",
            (client, &reused_scope),
        )?;
        tx.execute(
            "DELETE FROM oauth_rotated_refresh WHERE client = ?1 AND scope = ?2",
            (client, &reused_scope),
        )?;
    }
    Ok(scope)
}

fn prune_rotated_refreshes(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "DELETE FROM oauth_rotated_refresh AS rotated WHERE NOT EXISTS (
            SELECT 1 FROM oauth_sessions AS active
            WHERE active.client = rotated.client AND active.scope = rotated.scope
         )",
        [],
    )?;
    Ok(())
}

impl OAuth {
    pub(super) fn principal(&self, bearer: &str) -> Result<Option<pensine_access::Principal>> {
        use pensine_access::{Connection, Grant, Principal};
        let db = self.db()?;
        let session = db
            .query_row(
                "SELECT session.scope, session.client, client.last_used < unixepoch()
             FROM oauth_sessions session JOIN oauth_clients client ON client.id = session.client
             WHERE session.access_hash = ?1 AND session.access_until > unixepoch()
               AND client.last_used > unixepoch() - 30 * 86400",
                [hash(bearer)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((scope, client, needs_touch)) = session else {
            return Ok(None);
        };
        if needs_touch && touch(&db, &client)? == 0 {
            return Ok(None);
        }
        drop(db);
        let scope: super::Scope = serde_json::from_str(&scope)?;
        let account = self
            .accounts
            .account(&scope.account)
            .map_err(crate::ServerError::from)?;
        let connection = Connection {
            id: scope.id,
            account: scope.account,
            name: scope.name,
            grants: scope
                .spaces
                .into_iter()
                .map(|space| Grant {
                    space,
                    write: !scope.read_only,
                })
                .collect(),
            read_only: scope.read_only,
        };
        Ok(Some(
            Principal::new(account, connection).map_err(crate::ServerError::from)?,
        ))
    }
}
