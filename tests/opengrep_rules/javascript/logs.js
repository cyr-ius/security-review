// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data written to a log.
const express = require('express');
const logger = require('./logger');

const app = express();

app.post('/login', (req, res) => {
  // ruleid: secreview.js.taint-log-injection
  console.log('failed login for ' + req.body.user);
  // ruleid: secreview.js.taint-log-injection
  logger.warn(`failed login for ${req.body.user}`);
  // ok: secreview.js.taint-log-injection
  logger.warn('failed login for ' + req.body.user.replace(/[\r\n]/g, ''));
  // ok: secreview.js.taint-log-injection
  console.log('failed login for', JSON.stringify(req.body.user));
  // ok: secreview.js.taint-log-injection
  console.log('login attempt');
  res.sendStatus(401);
});
