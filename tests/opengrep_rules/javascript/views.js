// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data choosing the view or the template rendered.
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  // ruleid: secreview.js.taint-view-injection
  res.render(req.query.page);
});

app.get('/profile', (req, res) => {
  // ruleid: secreview.js.taint-view-injection
  res.render('profile', req.query);
});

app.get('/help', (req, res) => {
  // ok: secreview.js.taint-view-injection
  res.render('help', { topic: req.query.topic });
});
