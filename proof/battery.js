// Production-shape proof battery, run INSIDE the gate container.
// Exercises the exact browser flow a user would: fence -> login page ->
// wrong password -> correct login -> dsh UI served through the gate.
'use strict';
const os = require('node:os');

function ownIPv4() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return '127.0.0.1';
}
const BASE = `http://${ownIPv4()}:3081`;
const results = [];
function check(name, ok, detail) {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

(async () => {
  // 1. Unauthenticated root redirects to the login page.
  let r = await fetch(`${BASE}/`, { redirect: 'manual' });
  check('unauthenticated / redirects to login', r.status === 302 && (r.headers.get('location') || '') === '/__gate/login', `status ${r.status}`);

  // 2. Login page renders.
  r = await fetch(`${BASE}/__gate/login`);
  let body = await r.text();
  check('login page renders', r.status === 200 && body.includes('DeepSeek Harness'), `status ${r.status}`);

  // 3. Wrong password is rejected.
  r = await fetch(`${BASE}/__gate/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=braukw&password=wrong-password',
    redirect: 'manual',
  });
  check('wrong password rejected', r.status === 401, `status ${r.status}`);

  // 4. Correct seeded password (the "APP_PASSWORD") signs in.
  r = await fetch(`${BASE}/__gate/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=braukw&password=proof-pass-123',
    redirect: 'manual',
  });
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  check('correct password signs in', r.status === 302 && cookie.startsWith('dsh_gate='), `status ${r.status}`);

  // 5. The dsh UI loads through the gate with the gate session cookie.
  r = await fetch(`${BASE}/`, { headers: { Cookie: cookie } });
  body = await r.text();
  check('dsh UI served through gate', r.status === 200 && body.includes('DeepSeek Harness'), `status ${r.status}`);

  console.log(results.join('\n'));
  if (results.some((l) => l.startsWith('FAIL'))) process.exit(1);
})().catch((e) => { console.log(results.join('\n')); console.log('BATTERY ERROR', e.message); process.exit(2); });
