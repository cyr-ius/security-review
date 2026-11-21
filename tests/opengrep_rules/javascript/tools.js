// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
const { execFile, exec } = require('child_process');
const shellQuote = require('shell-quote');

app.post('/mirror', (req, res) => {
  const url = req.body.url;
  // ruleid: secreview.js.taint-argument-injection
  execFile('git', ['clone', url, '/srv/mirror']);
  // ruleid: secreview.js.taint-argument-injection
  execFile('curl', [url]);
  // ruleid: secreview.js.taint-argument-injection
  exec('git ls-remote ' + shellQuote.quote([url]));
  // ok: secreview.js.taint-argument-injection
  execFile('git', ['clone', '--', url, '/srv/mirror']);
  // ok: secreview.js.taint-argument-injection
  execFile('git', ['clone', `--branch=${url}`, 'https://example.com/repo']);
  // ok: secreview.js.taint-argument-injection
  execFile('/opt/tools/report', [url]);
  res.send('ok');
});
