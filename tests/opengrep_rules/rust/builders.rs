// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data pushed to a Vec.

async fn columns(pool: &sqlx::PgPool, Query(params): Query<Columns>) {
    let mut columns = vec!["id".to_string()];
    columns.push(params.column);
    // A call inside the arguments of format! is not followed: join first
    let joined = columns.join(", ");
    let sql = format!("SELECT {} FROM users", joined);
    // ruleid: secreview.rust.taint-sql
    sqlx::query(&sql).fetch_all(pool).await;
}
