// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
const crypto = require('crypto');
const express = require('express');
const serialize = require('node-serialize');
const _ = require('lodash');
const User = require('./models/user');

const app = express();

app.post('/users', async (req, res) => {
  // ruleid: secreview.js.taint-mass-assignment
  const user = await User.create(req.body);
  const { name, email } = req.body;
  // ok: secreview.js.taint-mass-assignment
  await User.create({ name, email });
  // ok: secreview.js.taint-mass-assignment
  await User.create(_.pick(req.body, ['name', 'email']));
  res.json(user);
});

app.put('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  // ruleid: secreview.js.taint-mass-assignment
  Object.assign(user, req.body);
  // ok: secreview.js.taint-mass-assignment
  const copy = Object.assign({}, req.body);
  await user.save();
  res.json(copy);
});

app.post('/session', (req, res) => {
  // ruleid: secreview.js.taint-deserialization
  const session = serialize.unserialize(req.cookies.session);
  // ok: secreview.js.taint-deserialization
  const data = JSON.parse(req.body.data);
  res.json({ session, data });
});
