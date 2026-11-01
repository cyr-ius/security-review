// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
use std::process::Command;

use axum::response::Html;
use jsonwebtoken::Validation;
use md5;
use sha2::{Digest, Sha256};
use tower_http::cors::CorsLayer;

async fn users(pool: &sqlx::PgPool, name: &str) {
    // ruleid: secreview.rust.sql-built-with-format
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name)).fetch_all(pool).await;
    // ok: secreview.rust.sql-built-with-format
    sqlx::query("SELECT * FROM users WHERE name = $1").bind(name).fetch_all(pool).await;
}

fn convert(format: &str) {
    // ruleid: secreview.rust.command-through-shell
    Command::new("sh").arg("-c").arg(format!("convert report.pdf report.{}", format)).status();
    // ok: secreview.rust.command-through-shell
    Command::new("sh").arg("-c").arg("uptime").status();
    // ok: secreview.rust.command-through-shell
    Command::new("convert").arg("report.pdf").arg(format).status();
}

fn client() -> reqwest::Client {
    // ruleid: secreview.rust.tls-verification-disabled
    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
    // ok: secreview.rust.tls-verification-disabled
    reqwest::Client::builder().danger_accept_invalid_certs(false).build().unwrap()
}

fn digest(data: &[u8]) {
    // ruleid: secreview.rust.weak-crypto
    let legacy = md5::compute(data);
    // ok: secreview.rust.weak-crypto
    let modern = Sha256::digest(data);
}

fn validation() -> Validation {
    let mut validation = Validation::default();
    // ruleid: secreview.rust.jwt-validation-disabled
    validation.insecure_disable_signature_validation();
    // ok: secreview.rust.jwt-validation-disabled
    validation.validate_exp = true;
    validation
}

fn cors() -> CorsLayer {
    // ruleid: secreview.rust.cors-permissive
    CorsLayer::very_permissive()
}

fn cors_strict() -> CorsLayer {
    // ok: secreview.rust.cors-permissive
    CorsLayer::new().allow_origin("https://app.example.com".parse::<http::HeaderValue>().unwrap())
}

fn cookie() {
    // ruleid: secreview.rust.cookie-insecure
    let session = Cookie::build(("session", "value")).secure(false).build();
    // ok: secreview.rust.cookie-insecure
    let strict = Cookie::build(("session", "value")).secure(true).http_only(true).build();
}

async fn hello(name: String) -> Html<String> {
    // ruleid: secreview.rust.html-built-with-format
    Html(format!("<p>Hello {}</p>", name))
}

async fn static_page() -> Html<&'static str> {
    // ok: secreview.rust.html-built-with-format
    Html("<p>Hello</p>")
}
