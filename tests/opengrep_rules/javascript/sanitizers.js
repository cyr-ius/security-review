// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data made safe for its sink: encoded in a URL, escaped as an SQL identifier, quoted for a shell.
const { exec } = require('child_process');
const querystring = require('querystring');
const shellQuote = require('shell-quote');
const mysql = require('mysql');

app.get('/report', async (req, res) => {
  // ok: secreview.js.taint-ssrf
  await fetch('https://api.example.com/search?q=' + querystring.escape(req.query.q));
  // ok: secreview.js.taint-sql
  db.query('SELECT * FROM users ORDER BY ' + mysql.escapeId(req.query.sort));
  // ok: secreview.js.taint-command
  exec('ls ' + shellQuote.quote([req.query.dir]));
  res.end();
});
