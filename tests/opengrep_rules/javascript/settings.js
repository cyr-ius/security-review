// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
const express = require('express');
const _ = require('lodash');

const app = express();
const settings = {};

app.post('/settings', (req, res) => {
  const { section, key, value } = req.body;
  // ruleid: secreview.js.taint-prototype-pollution
  settings[section][key] = value;
  // ruleid: secreview.js.taint-prototype-pollution
  _.set(settings, req.body.path, value);
  // ok: secreview.js.taint-prototype-pollution
  settings.theme = value;
  res.json(settings);
});

app.post('/checked', (req, res) => {
  const { section, key, value } = req.body;
  if (['__proto__', 'constructor', 'prototype'].includes(section)) {
    return res.status(400).end();
  }
  // ok: secreview.js.taint-prototype-pollution
  settings[section][key] = value;
  res.json(settings);
});
