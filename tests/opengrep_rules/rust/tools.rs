// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
use axum::extract::Query;
use std::process::Command;

async fn mirror(Query(params): Query<Params>) -> String {
    let url = params.url;
    // ruleid: secreview.rust.taint-argument-injection
    Command::new("git").arg("clone").arg(&url).output().unwrap();
    // ruleid: secreview.rust.taint-argument-injection
    Command::new("curl").args(["-s", &url]).output().unwrap();
    let mut ssh = Command::new("ssh");
    // ruleid: secreview.rust.taint-argument-injection
    ssh.arg(&url);
    // ok: secreview.rust.taint-argument-injection
    Command::new("git").arg("clone").arg("--").arg(&url).output().unwrap();
    // ok: secreview.rust.taint-argument-injection
    Command::new("git").arg(format!("--branch={}", url)).output().unwrap();
    // ok: secreview.rust.taint-argument-injection
    Command::new("/opt/tools/report").arg(&url).output().unwrap();
    String::new()
}
