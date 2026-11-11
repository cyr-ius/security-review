// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
const crypto = require('crypto');

function invite() {
  // ruleid: secreview.js.insecure-random-for-secret
  const inviteToken = Math.random().toString(36).slice(2);
  // ok: secreview.js.insecure-random-for-secret
  const sessionId = crypto.randomBytes(32).toString('hex');
  // ok: secreview.js.insecure-random-for-secret
  const delay = Math.random() * 1000;
  return {
    // ruleid: secreview.js.insecure-random-for-secret
    resetToken: Math.random().toString(36),
    inviteToken,
    sessionId,
    delay,
  };
}

const libxmljs = require('libxmljs');

function parse(xml) {
  // ruleid: secreview.js.xxe-noent-enabled
  const doc = libxmljs.parseXml(xml, { noent: true, nocdata: true });
  // ok: secreview.js.xxe-noent-enabled
  const safe = libxmljs.parseXml(xml, { nocdata: true });
  return [doc, safe];
}
