use super::consent::{authorize, consent};
use super::token::token;
use super::{hash, random_secret, OAuth, OAuthError, Result};
use crate::config::parse_web_url;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pensine_access::{validate_alias, AccessError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub(crate) fn routes(oauth: Arc<OAuth>) -> Router {
    Router::new()
        .route(
            "/register",
            post(register).layer(middleware::from_fn_with_state(
                oauth.clone(),
                super::registration::limit,
            )),
        )
        .route("/authorize", get(authorize).post(consent))
        .route("/token", post(token))
        .route_layer(middleware::from_fn(oauth_no_store))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp/{alias}",
            get(alias_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(oauth)
}

async fn protected_resource(State(oauth): State<Arc<OAuth>>) -> Response {
    // The legacy URL carries no account selector. It is unambiguous only
    // on a single-account server.
    match oauth.accounts.account_list() {
        Ok(accounts) => match accounts.as_slice() {
            [(_, alias)] => resource_document(&oauth.issuer(), alias).into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn alias_resource(State(oauth): State<Arc<OAuth>>, Path(alias): Path<String>) -> Response {
    if validate_alias(&alias).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match oauth.accounts.account_id_for_alias(&alias) {
        Ok(_) => resource_document(&oauth.issuer(), &alias).into_response(),
        Err(AccessError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn resource_document(issuer: &str, alias: &str) -> Json<Value> {
    Json(json!({
        "resource": format!("{issuer}/mcp/{alias}"),
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["memory"],
    }))
}

async fn authorization_server(State(oauth): State<Arc<OAuth>>) -> Json<Value> {
    let issuer = oauth.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "registration_endpoint": format!("{issuer}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["memory"],
    }))
}

#[derive(Deserialize)]
struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

async fn register(
    State(oauth): State<Arc<OAuth>>,
    Json(registration): Json<Registration>,
) -> Result<Response> {
    let redirects = registration.redirect_uris;
    if redirects.is_empty()
        || redirects.iter().any(|uri| {
            parse_web_url(uri).is_none_or(|url| {
                url.query_pairs()
                    .any(|(key, _)| matches!(key.as_ref(), "code" | "error" | "state" | "iss"))
            })
        })
    {
        return Err(OAuthError::BadRequest("invalid_redirect_uri"));
    }
    // Claude and other assistants may register as confidential clients: accept the three methods the earlier
    // implementation did. A confidential client gets a secret, checked at the token endpoint on top of PKCE.
    let method = registration
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none")
        .to_owned();
    if !matches!(
        method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return Err(OAuthError::BadRequest("invalid_client_metadata"));
    }
    let secret = (method != "none").then(random_secret).transpose()?;
    let name = registration
        .client_name
        .unwrap_or_else(|| "OAuth client".into());
    let id = random_secret()?;
    oauth.register_client(&id, &name, &redirects, secret.as_deref().map(hash))?;
    let mut body = json!({
        "client_id": id,
        "client_name": name,
        "redirect_uris": redirects,
        "token_endpoint_auth_method": method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    });
    if let Some(secret) = secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

async fn oauth_no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
