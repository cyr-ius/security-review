// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
const ejs = require('ejs');
const express = require('express');
const User = require('./models/user');

const app = express();

app.post('/preview', (req, res) => {
  // ruleid: secreview.js.taint-template-injection
  const html = ejs.render(req.body.template, { user: req.user });
  // ok: secreview.js.taint-template-injection
  const page = ejs.render('<p><%= name %></p>', { name: req.body.name });
  res.send(html + page);
});

app.post('/login', async (req, res) => {
  // ruleid: secreview.js.taint-nosql-injection
  const user = await User.findOne({ name: req.body.name, password: req.body.password });
  // ruleid: secreview.js.taint-nosql-injection
  await User.find(req.query);
  // ok: secreview.js.taint-nosql-injection
  await User.findOne({ name: String(req.body.name) });
  // ok: secreview.js.taint-nosql-injection
  await User.findById(req.params.id);
  // ok: secreview.js.taint-nosql-injection
  await User.findOne({ _id: req.params.id });
  // ruleid: secreview.js.taint-nosql-injection
  await User.find().$where(`this.name == '${req.params.name}'`);
  res.json({ found: Boolean(user) });
});

function notify(popup, token) {
  // ruleid: secreview.js.post-message-any-origin
  popup.postMessage({ token }, '*');
  // ok: secreview.js.post-message-any-origin
  popup.postMessage({ token }, 'https://app.example.com');
}
