// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// XPath expressions and LDAP filters built from request data.
const xpath = require('xpath');
const ldapEscape = require('ldap-escape');

app.get('/books', (req, res) => {
  // ruleid: secreview.js.taint-xpath-injection
  const books = xpath.select(`//book[author='${req.query.author}']`, doc);
  // ok: secreview.js.taint-xpath-injection
  const all = xpath.select('//book', doc);
  res.json({ books, all });
});

app.get('/people', (req, res) => {
  // ruleid: secreview.js.taint-ldap-injection
  client.search('ou=people,dc=example,dc=com', { filter: `(uid=${req.query.uid})`, scope: 'sub' }, done);
  // ok: secreview.js.taint-ldap-injection
  client.search('ou=people,dc=example,dc=com', { filter: ldapEscape.filter`(uid=${req.query.uid})`, scope: 'sub' }, done);
  res.end();
});
