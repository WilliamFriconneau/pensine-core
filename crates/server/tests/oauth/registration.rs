use super::{body, Fixture, CALLBACK, VERIFIER};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn registrations_are_capped_and_expire() {
    let mut env = Fixture::start().await;
    env.handle.shutdown();
    let config = pensine_server::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: env.dir.path().into(),
        oauth_registration_cap: 2,
        ..Default::default()
    };
    env.handle = pensine_server::Server::start(config.clone()).await.unwrap();
    let first = env.client();
    let second = env.client();
    assert_eq!(env.register(CALLBACK).status(), 503);

    let db = rusqlite::Connection::open(env.dir.path().join("oauth.db")).unwrap();
    db.execute(
        "UPDATE oauth_clients SET last_used = unixepoch() - 31 * 86400 WHERE id = ?1",
        [&first],
    )
    .unwrap();
    assert_eq!(env.register(CALLBACK).status(), 201);
    let remaining: Vec<String> = db
        .prepare("SELECT id FROM oauth_clients")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(!remaining.contains(&first));
    assert!(remaining.contains(&second));

    for _ in 0..6 {
        assert_eq!(env.register(CALLBACK).status(), 503);
    }
    let limited = env.register(CALLBACK);
    assert_eq!(limited.status(), 429);
    assert!(limited.header("Retry-After").is_some());
    assert_eq!(body(limited)["error"], "registration_rate_limit");
    env.handle.shutdown();
    let smaller = pensine_server::Config {
        oauth_registration_cap: 1,
        ..config
    };
    env.handle = pensine_server::Server::start(smaller).await.unwrap();
    let count: usize = db
        .query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    env.handle.shutdown();
}

fn register_with(env: &Fixture, method: &str) -> ureq::Response {
    env.agent
        .post(&env.url("/register"))
        .set("Content-Type", "application/json")
        .send_string(
            &json!({"client_name": "Connector", "redirect_uris": [CALLBACK],
                    "token_endpoint_auth_method": method})
            .to_string(),
        )
        .unwrap_or_else(super::status_response)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_lists_the_three_client_authentication_methods() {
    let env = Fixture::start().await;
    let metadata = body(
        env.agent
            .get(&env.url("/.well-known/oauth-authorization-server"))
            .call()
            .unwrap(),
    );
    let methods: Vec<&str> = metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        ["none", "client_secret_post", "client_secret_basic"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_authentication_method_is_refused() {
    let env = Fixture::start().await;
    assert_eq!(register_with(&env, "private_key_jwt").status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confidential_client_gets_a_secret_and_must_present_it() {
    let env = Fixture::start().await;
    for method in ["client_secret_post", "client_secret_basic"] {
        let registration = body(register_with(&env, method));
        assert_eq!(registration["token_endpoint_auth_method"], method);
        let client = registration["client_id"].as_str().unwrap().to_owned();
        let secret = registration["client_secret"].as_str().unwrap().to_owned();
        let code = env.code(&client);

        // No secret, then a wrong one: refused, and the code stays valid.
        assert_eq!(env.exchange(&client, &code, VERIFIER).status(), 401);
        let wrong = env.post(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", client.clone()),
                ("client_secret", "not-the-secret".into()),
                ("redirect_uri", CALLBACK.into()),
                ("code", code.clone()),
                ("code_verifier", VERIFIER.into()),
            ],
        );
        assert_eq!(wrong.status(), 401);

        let accepted = if method == "client_secret_post" {
            env.post(
                "/token",
                &[
                    ("grant_type", "authorization_code".into()),
                    ("client_id", client.clone()),
                    ("client_secret", secret),
                    ("redirect_uri", CALLBACK.into()),
                    ("code", code),
                    ("code_verifier", VERIFIER.into()),
                ],
            )
        } else {
            env.agent
                .post(&env.url("/token"))
                .set(
                    "Authorization",
                    &format!("Basic {}", STANDARD.encode(format!("{client}:{secret}"))),
                )
                .send_form(&[
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", CALLBACK),
                    ("code", &code),
                    ("code_verifier", VERIFIER),
                ])
                .unwrap_or_else(super::status_response)
        };
        assert_eq!(accepted.status(), 200, "{method}");
        assert!(body(accepted)["access_token"].is_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_public_client_needs_no_secret_and_pkce_stays_required() {
    let env = Fixture::start().await;
    let client = env.client();
    let code = env.code(&client);
    assert_eq!(env.exchange(&client, &code, VERIFIER).status(), 200);
}
