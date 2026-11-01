// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
const { exec, execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const vm = require('vm');

const app = express();

app.get('/users', async (req, res) => {
  const name = req.query.name;
  // ruleid: secreview.js.taint-sql
  const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ok: secreview.js.taint-sql
  await db.query('SELECT * FROM users WHERE name = $1', [name]);
  // ok: secreview.js.taint-sql
  await db.query('SELECT * FROM users LIMIT ' + parseInt(req.query.limit, 10));
  res.json(rows);
});

app.post('/ping', (req, res) => {
  const host = req.body.host;
  // ruleid: secreview.js.taint-command
  exec('ping -c 1 ' + host, () => res.end());
  // ok: secreview.js.taint-command
  execFile('ping', ['-c', '1', host], () => res.end());
});

app.post('/calc', (req, res) => {
  // ruleid: secreview.js.taint-code-eval
  res.json({ result: eval(req.body.expression) });
  // ruleid: secreview.js.taint-code-eval
  vm.runInNewContext(req.body.script, {});
  // ok: secreview.js.taint-code-eval
  setTimeout(() => res.end(), 10);
});

app.get('/files', (req, res) => {
  const file = path.join('/srv/files', req.query.name);
  // ruleid: secreview.js.taint-path-traversal
  fs.readFile(file, (err, data) => res.send(data));
  // ruleid: secreview.js.taint-path-traversal
  res.sendFile(file);
  // ok: secreview.js.taint-path-traversal
  res.sendFile(req.query.name, { root: '/srv/files' });
  // ok: secreview.js.taint-path-traversal
  fs.readFile(path.join('/srv/files', path.basename(req.query.name)), () => {});
});

app.get('/fetch', async (req, res) => {
  // ruleid: secreview.js.taint-ssrf
  const answer = await axios.get(req.query.url);
  // ruleid: secreview.js.taint-ssrf
  await fetch(req.query.url);
  // ok: secreview.js.taint-ssrf
  await fetch('https://api.example.com/search?q=' + encodeURIComponent(req.query.q));
  res.json(answer.data);
});

app.get('/login', (req, res) => {
  // ruleid: secreview.js.taint-open-redirect
  res.redirect(req.query.next);
});

app.get('/home', (req, res) => {
  // ok: secreview.js.taint-open-redirect
  res.redirect('/dashboard');
});

app.get('/hello', (req, res) => {
  // ruleid: secreview.js.taint-xss-response
  res.send('<p>Hello ' + req.query.name + '</p>');
  // ok: secreview.js.taint-xss-response
  res.send('<p>Hello ' + escapeHtml(req.query.name) + '</p>');
});

app.get('/search', (req, res) => {
  // ruleid: secreview.js.taint-regex-injection
  const matcher = new RegExp(req.query.pattern);
  // ok: secreview.js.taint-regex-injection
  const safe = new RegExp(_.escapeRegExp(req.query.pattern));
  res.json({ ok: matcher.test('a') && safe.test('a') });
});

// ruleid: secreview.js.tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ok: secreview.js.tls-verification-disabled
const strict = new https.Agent({ rejectUnauthorized: true, ca: caBundle });

// ruleid: secreview.js.cors-reflects-any-origin
app.use(cors({ origin: true, credentials: true }));
// ok: secreview.js.cors-reflects-any-origin
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use((req, res, next) => {
  // ruleid: secreview.js.cors-reflects-any-origin
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  next();
});

function check(token, key) {
  // ruleid: secreview.js.jwt-insecure-options
  jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
  // ok: secreview.js.jwt-insecure-options
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

// ruleid: secreview.js.cookie-insecure
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } }));
// ok: secreview.js.cookie-insecure
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: true, httpOnly: true } }));

function digest(data) {
  // ruleid: secreview.js.weak-crypto
  const legacy = crypto.createHash('md5').update(data).digest('hex');
  // ok: secreview.js.weak-crypto
  return [legacy, crypto.createHash('sha256').update(data).digest('hex')];
}
