// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Password reset links built from the Host header.
const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({ host: 'localhost' });

app.post('/password-reset', async (req, res) => {
  const token = await createToken(req.body.email);
  const link = `${req.protocol}://${req.get('host')}/reset?token=${token}`;
  // ruleid: secreview.js.taint-host-header
  await transport.sendMail({ to: req.body.email, subject: 'Reset', text: `Open ${link}` });
  // ok: secreview.js.taint-host-header
  await transport.sendMail({ to: req.body.email, subject: 'Reset', text: `Open ${process.env.BASE_URL}/reset?token=${token}` });
  res.sendStatus(202);
});
