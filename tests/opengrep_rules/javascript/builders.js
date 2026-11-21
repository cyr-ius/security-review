// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data added to an array.
app.get('/columns', async (req, res) => {
  const columns = ['id'];
  columns.push(req.query.column);
  // ruleid: secreview.js.taint-sql
  res.json(await db.query(`SELECT ${columns.join(', ')} FROM users`));
});

app.get('/search', async (req, res) => {
  const url = new URL('https://api.example.com/search');
  url.searchParams.set('q', req.query.q);
  // ok: secreview.js.taint-ssrf
  res.json(await fetch(url));
});
