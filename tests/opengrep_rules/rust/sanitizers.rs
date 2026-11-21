// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data encoded in a URL, or quoted for a shell.
use std::process::Command;

async fn profile(Query(params): Query<Profile>) {
    let user = urlencoding::encode(&params.user);
    let url = format!("https://api.example.com/users/{}", user);
    // ok: secreview.rust.taint-ssrf
    reqwest::get(url).await;
    let dir = shell_escape::escape(params.dir.into());
    let script = format!("ls {}", dir);
    // ok: secreview.rust.taint-command
    Command::new("sh").arg("-c").arg(script).output();
}
