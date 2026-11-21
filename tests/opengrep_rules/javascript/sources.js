// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data outside Express: Koa, Hono, AWS Lambda, sockets.
const { exec } = require('child_process');

router.get('/koa', async (ctx) => {
  // ruleid: secreview.js.taint-sql
  ctx.body = await db.query(`SELECT * FROM users WHERE id = ${ctx.query.id}`);
  // ok: secreview.js.taint-sql
  ctx.body = await db.query('SELECT * FROM users WHERE id = $1', [ctx.params.id]);
});

app.get('/hono', async (c) => {
  // ruleid: secreview.js.taint-command
  exec('ping ' + c.req.query('host'));
});

exports.handler = async (event) => {
  // ruleid: secreview.js.taint-sql
  await db.query('SELECT * FROM users WHERE id = ' + event.queryStringParameters.id);
};

io.on('connection', (socket) => {
  // ok: secreview.js.taint-sql
  db.query('INSERT INTO sessions VALUES (' + socket.id + ')');
  socket.on('rename', (name) => {
    // ruleid: secreview.js.taint-sql
    db.query("UPDATE users SET name = '" + name + "'");
  });
});

child.stdout.on('data', (chunk) => {
  // ok: secreview.js.taint-command
  exec('logger ' + chunk);
});
