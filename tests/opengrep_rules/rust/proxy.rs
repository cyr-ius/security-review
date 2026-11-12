// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
use axum::extract::Query;
use axum::response::Redirect;

async fn fetch(client: reqwest::Client, Query(params): Query<Fetch>) {
    // ruleid: secreview.rust.taint-ssrf
    reqwest::get(&params.url).await.unwrap();
    // ruleid: secreview.rust.taint-ssrf
    client.get(format!("{}/status", params.url)).send().await.unwrap();
    // ok: secreview.rust.taint-ssrf
    client.get("https://api.example.com/status").send().await.unwrap();
    let cache: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // ok: secreview.rust.taint-ssrf
    cache.get(&params.url);
}

async fn back(Query(params): Query<Back>) -> Redirect {
    // ruleid: secreview.rust.taint-open-redirect
    Redirect::to(&params.next)
}

async fn home() -> Redirect {
    // ok: secreview.rust.taint-open-redirect
    Redirect::to("/")
}
