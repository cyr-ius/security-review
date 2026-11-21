// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data naming a module, a class or a method reached by reflection.
const actions = { export: () => 'exported' };

app.post('/action', (req, res) => {
  // ruleid: secreview.js.taint-unsafe-reflection
  actions[req.body.action]();
  // ruleid: secreview.js.taint-unsafe-reflection
  const plugin = require(`./plugins/${req.body.plugin}`);
  // ok: secreview.js.taint-unsafe-reflection
  const label = actions[req.body.action];
  // ok: secreview.js.taint-unsafe-reflection
  actions['export']();
  res.send(String(label));
});
