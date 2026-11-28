#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{status_response, Fixture};

const ALPHABET: &str = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

fn submit(env: &Fixture, client: &str, invite: &str, language: &str) -> ureq::Response {
    let mut fields = env.authorize_fields(client, "S256");
    fields.push(("invite", invite.into()));
    env.agent
        .post(&env.url("/authorize"))
        .set("Accept-Language", language)
        .send_form(
            &fields
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(status_response)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_code_is_twelve_symbols_in_three_groups_from_the_clear_alphabet() {
    let env = Fixture::start().await;
    let code = env.handle.oauth_invitation("demo").unwrap();
    let groups: Vec<_> = code.split('-').collect();
    assert_eq!(groups.len(), 3);
    assert!(groups
        .iter()
        .all(|g| g.len() == 4 && g.chars().all(|c| ALPHABET.contains(c))));
    let db = rusqlite::Connection::open(env.dir.path().join("oauth.db")).unwrap();
    let hash: Vec<u8> = db
        .query_row("SELECT hash FROM oauth_invites", [], |r| r.get(0))
        .unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(hash, Sha256::digest(groups.join("")).to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_is_accepted_in_any_case_with_spaces_or_dashes() {
    let env = Fixture::start().await;
    let client = env.client();
    let code = env.handle.oauth_invitation("demo").unwrap();
    let mixed = format!("  {} _ ", code.to_ascii_lowercase().replace('-', " - "));
    assert_eq!(submit(&env, &client, &mixed, "en").status(), 200);
    assert_eq!(submit(&env, &client, &code, "en").status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_code_re_renders_the_consent_page_in_html_with_the_field() {
    let env = Fixture::start().await;
    let response = submit(&env, &env.client(), "<truncated>", "en");
    assert_eq!(response.status(), 403);
    assert!(response
        .header("Content-Type")
        .unwrap()
        .starts_with("text/html"));
    let page = response.into_string().unwrap();
    assert!(page.contains("This code is wrong, expired or already used."));
    for attribute in [
        "name=\"invite\"",
        "autocomplete=\"off\"",
        "autocapitalize=\"characters\"",
        "spellcheck=\"false\"",
        "inputmode=\"text\"",
        "placeholder=\"K7QM-X2RD-9FHT\"",
    ] {
        assert!(page.contains(attribute));
    }
    assert!(page.contains("name=\"state\" value=\"one &amp; two\""));
    assert!(!page.contains("<truncated>"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_error_page_is_french_when_the_browser_asks_for_french() {
    let env = Fixture::start().await;
    let response = submit(&env, &env.client(), "short", "fr-CA,en;q=0.8");
    assert_eq!(response.status(), 403);
    let page = response.into_string().unwrap();
    assert!(page.contains("lang=\"fr\""));
    assert!(page.contains("Ce code est incorrect, a expiré ou a déjà été utilisé."));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_failures_lock_every_submission_even_the_right_code_until_the_window_clears() {
    let mut env = Fixture::start().await;
    let client = env.client();
    let other = env.client();
    let code = env.handle.oauth_invitation("demo").unwrap();
    let accepted = env.handle.oauth_invitation("demo").unwrap();
    for wrong in ["?", "2222-2222-2222", "short", "O000-1111-IIII"] {
        assert_eq!(submit(&env, &client, wrong, "en").status(), 403);
    }
    assert_eq!(submit(&env, &other, &accepted, "en").status(), 200);
    assert_eq!(submit(&env, &other, &accepted, "en").status(), 403);
    env.restart().await;
    let locked = submit(&env, &other, &code, "en");
    assert_eq!(locked.status(), 429);
    assert!((1..=600).contains(
        &locked
            .header("Retry-After")
            .unwrap()
            .parse::<u32>()
            .unwrap()
    ));
    let page = locked.into_string().unwrap();
    assert!(page.contains("name=\"invite\""));
    assert!(page.contains("Too many attempts"));
    let db = rusqlite::Connection::open(env.dir.path().join("oauth.db")).unwrap();
    db.execute(
        "UPDATE oauth_invite_failures SET failed_at = unixepoch() - 600",
        [],
    )
    .unwrap();
    assert_eq!(submit(&env, &other, &code, "en").status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_a_code_clears_the_failure_window() {
    let env = Fixture::start().await;
    let client = env.client();
    for wrong in [
        "?",
        "2222-2222-2222",
        "short",
        "O000-1111-IIII",
        "3333-3333-3333",
    ] {
        assert_eq!(submit(&env, &client, wrong, "en").status(), 403);
    }
    // Locked: even a fresh, valid code would be refused...
    let stale = env.handle.oauth_invitation("demo").unwrap();
    // ...but making that code (which needs a signed-in Home Assistant user) cleared the window.
    assert_eq!(submit(&env, &client, &stale, "en").status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_consent_nonce_is_refused_with_a_readable_page_not_json() {
    let env = Fixture::start().await;
    let client = env.client();
    let mut fields = env.authorize_fields(&client, "S256");
    fields.push(("nonce", "never-issued".into()));
    fields.push(("decision", "allow".into()));
    let response = env
        .agent
        .post(&env.url("/authorize"))
        .set("Accept-Language", "fr")
        .send_form(
            &fields
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(status_response);
    assert_eq!(response.status(), 403);
    assert!(response.content_type().starts_with("text/html"));
    let page = response.into_string().unwrap();
    assert!(
        page.contains("Recommencez depuis votre assistant"),
        "{page}"
    );
    assert!(!page.contains("access_denied"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consent_post_from_another_origin_is_refused_with_a_readable_page_not_json() {
    let env = Fixture::start().await;
    let client = env.client();
    let mut fields = env.authorize_fields(&client, "S256");
    fields.push(("invite", "ABCD-EFGH-JKMN".into()));
    let response = env
        .agent
        .post(&env.url("/authorize"))
        .set("Origin", "https://elsewhere.example")
        .send_form(
            &fields
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(status_response);
    assert_eq!(response.status(), 403);
    assert!(response.content_type().starts_with("text/html"));
    assert!(!response.into_string().unwrap().contains("access_denied"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_form_post_with_a_null_origin_from_the_consent_page_is_accepted() {
    // The consent page sends Referrer-Policy: no-referrer, so browsers post it with Origin: null.
    let env = Fixture::start().await;
    let client = env.client();
    let code = env.handle.oauth_invitation("demo").unwrap();
    let mut fields = env.authorize_fields(&client, "S256");
    fields.push(("invite", code));
    let response = env
        .agent
        .post(&env.url("/authorize"))
        .set("Origin", "null")
        .set("Sec-Fetch-Site", "same-origin")
        .send_form(
            &fields
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(status_response);
    assert_eq!(response.status(), 200);
    assert!(response.into_string().unwrap().contains("name=\"nonce\""));
}
