// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
use std::path::Path as FsPath;
use std::process::Command;

use axum::extract::{Path, Query};

async fn download(Path(name): Path<String>) -> Vec<u8> {
    // ruleid: secreview.rust.taint-path-traversal
    let data = std::fs::read(FsPath::new("/srv/files").join(&name)).unwrap();
    let base = FsPath::new(&name).file_name().unwrap();
    // ok: secreview.rust.taint-path-traversal
    let safe = std::fs::read(FsPath::new("/srv/files").join(base)).unwrap();
    [data, safe].concat()
}

async fn report(Query(params): Query<Report>) {
    // ruleid: secreview.rust.taint-path-traversal
    tokio::fs::remove_file(&params.file).await.unwrap();
}

async fn ping(Query(params): Query<Ping>) {
    // ruleid: secreview.rust.taint-command
    Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", params.host)).status().unwrap();
    // ok: secreview.rust.taint-command
    Command::new("ping").arg("-c").arg("1").arg(&params.host).status().unwrap();
}

async fn tool(Path(tool): Path<String>) {
    // ruleid: secreview.rust.taint-command
    Command::new(&tool).status().unwrap();
}

async fn by_id(Path(id): Path<u64>) {
    // ok: secreview.rust.taint-path-traversal
    std::fs::read(format!("/srv/reports/{}.pdf", id)).unwrap();
}
