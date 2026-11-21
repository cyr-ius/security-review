// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// HTML answers and templates built from request data.
use axum::extract::Query;
use axum::response::Html;
use tera::{Context, Tera};

async fn greet(Query(params): Query<Greeting>) -> Html<String> {
    // ruleid: secreview.rust.taint-xss
    Html(params.name)
}

async fn greet_escaped(Query(params): Query<Greeting>) -> Html<String> {
    // ok: secreview.rust.taint-xss
    Html(html_escape::encode_text(&params.name).to_string())
}

async fn render(Query(params): Query<Page>) -> String {
    let mut context = Context::new();
    context.insert("name", &params.name);
    // ruleid: secreview.rust.taint-template-injection
    let custom = Tera::one_off(&params.template, &context, true).unwrap();
    // ok: secreview.rust.taint-template-injection
    let fixed = Tera::one_off("Hello {{ name }}", &context, true).unwrap();
    custom + &fixed
}
