// Production-shape proof battery v2, run INSIDE the gate container.
// Exercises the password-only first-run flow a user would see: setup
// redirect -> setup page -> mismatched passwords rejected -> password
// created -> dsh UI through the gate -> setup closed forever -> login
// page for fresh visitors -> wrong password -> correct password -> UI.
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
const PW = 'proof-password-1';

(async () => {
  // 1. Fresh gate (no credential record): root funnels to setup.
  let r = await fetch(`${BASE}/`, { redirect: 'manual' });
  check('fresh / redirects to setup', r.status === 302 && (r.headers.get('location') || '') === '/__gate/setup', `status ${r.status}`);

  // 2. Setup page renders.
  r = await fetch(`${BASE}/__gate/setup`);
  let body = await r.text();
  check('setup page renders', r.status === 200 && body.includes('Create the password'), `status ${r.status}`);

  // 3. Mismatched passwords are rejected.
  r = await fetch(`${BASE}/__gate/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `password=${PW}&confirm=different-password`,
    redirect: 'manual',
  });
  check('mismatched setup passwords rejected', r.status === 400, `status ${r.status}`);

  // 4. Matching passwords create the record and sign in.
  r = await fetch(`${BASE}/__gate/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `password=${PW}&confirm=${PW}`,
    redirect: 'manual',
  });
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  check('setup creates password and signs in', r.status === 302 && cookie.startsWith('dsh_gate='), `status ${r.status}`);

  // 5. The dsh UI loads through the gate with the setup session.
  r = await fetch(`${BASE}/`, { headers: { Cookie: cookie } });
  body = await r.text();
  check('dsh UI served through gate after setup', r.status === 200 && body.includes('DeepSeek Harness'), `status ${r.status}`);

  // 6. Setup is closed now: unauthenticated setup page redirects to login.
  r = await fetch(`${BASE}/__gate/setup`, { redirect: 'manual' });
  check('setup page closed after setup', r.status === 302 && (r.headers.get('location') || '') === '/__gate/login', `status ${r.status}`);

  // 7. Fresh visitors now get the login page, not setup.
  r = await fetch(`${BASE}/`, { redirect: 'manual' });
  check('fresh / redirects to login after setup', r.status === 302 && (r.headers.get('location') || '') === '/__gate/login', `status ${r.status}`);

  // 8. Wrong password is rejected at login.
  r = await fetch(`${BASE}/__gate/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'password=wrong-password',
    redirect: 'manual',
  });
  check('wrong login password rejected', r.status === 401, `status ${r.status}`);

  // 9. Correct password signs in (password only, no username).
  r = await fetch(`${BASE}/__gate/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `password=${PW}`,
    redirect: 'manual',
  });
  const cookie2 = (r.headers.get('set-cookie') || '').split(';')[0];
  const okLogin = r.status === 302 && cookie2.startsWith('dsh_gate=');
  check('password-only login signs in', okLogin, `status ${r.status}`);

  // 10. And the UI loads with the login session too.
  if (okLogin) {
    r = await fetch(`${BASE}/`, { headers: { Cookie: cookie2 } });
    body = await r.text();
    check('dsh UI served through gate after login', r.status === 200 && body.includes('DeepSeek Harness'), `status ${r.status}`);
  }

  console.log(results.join('\n'));
  if (results.some((l) => l.startsWith('FAIL'))) process.exit(1);
})().catch((e) => { console.log(results.join('\n')); console.log('BATTERY ERROR', e.message); process.exit(2); });
