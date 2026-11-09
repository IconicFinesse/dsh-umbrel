#!/usr/bin/env node
// dsh-gate: a password front door for the DeepSeek Harness Web UI.
// Zero dependencies (node:http only). Lives OUTSIDE the dsh npm package so
// dsh updates never touch it. It depends only on dsh's public, browser-facing
// behavior: the launch-token link (read from the link file, refreshed by
// the harness launcher on every dsh start) and the cookie that exchange
// mints.
// The token is exchanged server-side and never appears in the browser.
'use strict';

const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const path = require('node:path');
const PORT = Number(process.env.GATE_PORT || 3081);
const LINK_FILE = process.env.GATE_LINK_FILE || '/data/home/dsh-link.txt';
const CONFIG_FILE = process.env.GATE_CONFIG || '/data/gate/gate.json';
const UPSTREAM_PORT = Number(process.env.GATE_UPSTREAM_PORT || 3080);
const COOKIE_NAME = 'dsh_gate';
// The gate session never expires server-side: the user's password is the
// credential, and the session it mints is permanent (logout or wiping the
// credential record are the only ways out). Browsers cap cookie lifetime
// (Chrome: 400 days), so the cookie carries the max allowed age and the
// gate silently re-issues it on responses once it is a day old — in
// practice the sign-in lasts forever. Behind the gate, dsh's own 30-day
// cookie lives in the server-side jar and is quietly re-exchanged with a
// fresh launch token whenever it lapses; that rotation is invisible here.
const COOKIE_MAX_AGE_S = 400 * 24 * 60 * 60;
const RENEW_AFTER_MS = 24 * 60 * 60 * 1000;
const SUBTITLE = process.env.GATE_SUBTITLE || 'sign in to continue';
// Auth modes:
//  - default (the original VM install): username + password, the credential
//    record is managed out-of-band (gate-init / dsh-gate-setpass).
//  - "password-only" (the Umbrel app): no username anywhere, and when no
//    credential record exists yet the gate serves a one-time setup page —
//    the first visitor creates the password, and that password is the
//    sign-in from then on. Nothing personal ships in the package.
const PASSWORD_ONLY = process.env.GATE_AUTH_MODE === 'password-only';

function ownIPv4() {
  const ifaces = os.networkInterfaces();
  for (const list of Object.values(ifaces)) {
    for (const addr of list || []) {
      if (addr.family === 'IPv4' && !addr.internal) return addr.address;
    }
  }
  return '127.0.0.1';
}
// The gate binds its OWN address; the upstream is dsh, wherever it lives:
// the same host (VM install) or a compose service name (Umbrel app).
const BIND_HOST = ownIPv4();
const UPSTREAM_HOST = process.env.GATE_UPSTREAM_HOST || BIND_HOST;

// The Host authority presented to dsh. dsh trusts the authority it bound,
// so present dsh's own bound authority, parsed from the current launch
// link — the gate then works at any address the app happens to land on.
// GATE_AUTHORITY pins a static value where that is wanted (the VM install
// passes its LAN authority explicitly).
const STATIC_AUTHORITY = process.env.GATE_AUTHORITY || '';
function authority() {
  if (STATIC_AUTHORITY) return STATIC_AUTHORITY;
  try {
    const text = fs.readFileSync(LINK_FILE, 'utf8').trim();
    return new URL(text.split(/\s+/).pop()).host;
  } catch {
    return `${UPSTREAM_HOST}:${UPSTREAM_PORT}`;
  }
}

// ---------- credential record ----------
function loadConfig() {
  const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
  const rec = JSON.parse(raw);
  if (!rec.salt || !rec.digest || !rec.signing) {
    throw new Error('gate config incomplete');
  }
  return rec;
}

function makeRecord(password, user) {
  const salt = crypto.randomBytes(16).toString('hex');
  const rec = {
    salt,
    digest: crypto.scryptSync(password, salt, 64).toString('hex'),
    signing: crypto.randomBytes(32).toString('hex'),
  };
  if (user) rec.user = user;
  return rec;
}

function writeRecord(rec) {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(rec, null, 2), { mode: 0o600 });
}

// Optional bootstrap: if GATE_SEED_PASSWORD is set and no record exists,
// seed the record from it. The Umbrel app does NOT use this (its first-run
// setup page replaced it); it remains for scripted installs.
function seedConfigIfNeeded() {
  if (fs.existsSync(CONFIG_FILE)) return;
  const seed = process.env.GATE_SEED_PASSWORD || '';
  if (!seed) return;
  const user = process.env.GATE_USER || 'admin';
  writeRecord(makeRecord(seed, PASSWORD_ONLY ? undefined : user));
  console.log('dsh-gate: seeded credential record from environment');
}
seedConfigIfNeeded();
// No record is a legal state ONLY in password-only mode: the gate then
// serves the one-time setup page until the first password is created.
// Any other mode fails loudly here, as it always has.
let config = null;
if (fs.existsSync(CONFIG_FILE)) {
  config = loadConfig();
} else if (!PASSWORD_ONLY) {
  config = loadConfig();
}

function passwordMatches(candidate) {
  const digest = crypto.scryptSync(String(candidate), config.salt, 64);
  const expected = Buffer.from(config.digest, 'hex');
  return digest.length === expected.length && crypto.timingSafeEqual(digest, expected);
}

// ---------- gate session cookie ----------
function sign(payloadB64) {
  return crypto.createHmac('sha256', Buffer.from(config.signing, 'hex'))
    .update(payloadB64).digest('base64url');
}
function sessionUser() {
  return (config && config.user) || '(password-only)';
}
function makeSessionCookie() {
  const payload = {};
  payload.u = sessionUser();
  payload.iat = Date.now();
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${COOKIE_NAME}=${b64}.${sign(b64)}; Max-Age=${COOKIE_MAX_AGE_S}; Path=/; HttpOnly; SameSite=Strict`;
}
function sessionPayload(req) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== COOKIE_NAME) continue;
    const value = part.slice(eq + 1).trim();
    const dot = value.lastIndexOf('.');
    if (dot < 0) return null;
    const b64 = value.slice(0, dot);
    const sig = value.slice(dot + 1);
    const expected = sign(b64);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
      return payload.u === sessionUser() ? payload : null;
    } catch {
      return null;
    }
  }
  return null;
}
function sessionValid(req) {
  return sessionPayload(req) !== null;
}
function sessionAgeMs(req) {
  const payload = sessionPayload(req);
  if (!payload || typeof payload.iat !== 'number') return Infinity;
  return Date.now() - payload.iat;
}

// ---------- dsh token exchange (server-side jar) ----------
let dshJar = '';          // "name=value; name=value" for upstream requests
let exchangeInFlight = null;

function currentToken() {
  try {
    const text = fs.readFileSync(LINK_FILE, 'utf8').trim();
    const url = new URL(text.split(/\s+/).pop());
    return url.searchParams.get('token') || '';
  } catch {
    return '';
  }
}

function exchange() {
  if (exchangeInFlight) return exchangeInFlight;
  exchangeInFlight = new Promise((resolve) => {
    const token = currentToken();
    if (!token) { resolve(false); return; }
    const req = http.request({
      host: UPSTREAM_HOST, port: UPSTREAM_PORT, method: 'GET',
      path: `/?token=${encodeURIComponent(token)}`,
      headers: { Host: authority() },
    }, (res) => {
      res.resume();
      res.on('end', () => {
        const setCookies = res.headers['set-cookie'] || [];
        if (setCookies.length > 0) {
          dshJar = setCookies.map((c) => c.split(';')[0].trim()).join('; ');
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });
    req.on('error', () => resolve(false));
    req.setTimeout(8000, () => { req.destroy(); resolve(false); });
    req.end();
  }).finally(() => { exchangeInFlight = null; });
  return exchangeInFlight;
}

// ---------- login rate limiting ----------
const failures = new Map(); // ip -> {count, firstAt}
function rateLimited(ip) {
  const rec = failures.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.firstAt > 5 * 60 * 1000) { failures.delete(ip); return false; }
  return rec.count >= 5;
}
function recordFailure(ip) {
  const rec = failures.get(ip);
  if (!rec || Date.now() - rec.firstAt > 5 * 60 * 1000) {
    failures.set(ip, { count: 1, firstAt: Date.now() });
  } else {
    rec.count += 1;
  }
}

// ---------- login & setup pages ----------
const PAGE_STYLE = `
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#0b0e14; color:#e6e9ee; font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  .card { width:min(92vw, 340px); background:#12161f; border:1px solid #232a38; border-radius:14px;
    padding:28px 26px 22px; box-shadow:0 12px 40px rgba(0,0,0,.45); }
  h1 { font-size:19px; margin:0 0 4px; font-weight:650; }
  .sub { color:#8b94a5; font-size:13px; margin:0 0 20px; }
  label { display:block; font-size:12.5px; color:#aab3c2; margin:14px 0 6px; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px; border:1px solid #2b3446;
    background:#0d1119; color:#e6e9ee; font-size:15px; outline:none; }
  input:focus { border-color:#4d7cff; }
  button { width:100%; margin-top:20px; padding:11px; border:0; border-radius:9px; cursor:pointer;
    background:#4d7cff; color:#fff; font-size:15px; font-weight:600; }
  button:hover { background:#3f6fe8; }
  .err { background:#3a1620; border:1px solid #6e2436; color:#ff9db0; border-radius:9px;
    padding:9px 12px; font-size:13px; margin:0 0 6px; }
  .foot { color:#5d6675; font-size:11.5px; text-align:center; margin:16px 0 0; }`;

function loginPage(error) {
  const errHtml = error ? `<p class="err">${error}</p>` : '';
  const userHtml = PASSWORD_ONLY ? '' : `
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" value="${config.user}" required>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSeek Harness — Sign in</title>
<style>${PAGE_STYLE}
</style></head>
<body><form class="card" method="post" action="/__gate/login">
  <h1>DeepSeek Harness</h1>
  <p class="sub">${SUBTITLE}</p>
  ${errHtml}${userHtml}
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" autofocus required>
  <button type="submit">Sign in</button>
  <p class="foot">Front door by Nell ✨ — dsh itself is untouched</p>
</form></body></html>`;
}

// One-time setup, served only in password-only mode while no credential
// record exists. The first visitor creates the password; the page then
// closes forever (the record existing is what closes it).
function setupPage(error) {
  const errHtml = error ? `<p class="err">${error}</p>` : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSeek Harness — Set up</title>
<style>${PAGE_STYLE}
</style></head>
<body><form class="card" method="post" action="/__gate/setup">
  <h1>DeepSeek Harness</h1>
  <p class="sub">Welcome — first sign-in. Create the password for this harness; you'll use it every time after this.</p>
  ${errHtml}
  <label for="p">New password (at least 10 characters)</label>
  <input id="p" name="password" type="password" autocomplete="new-password" autofocus required>
  <label for="p2">Confirm password</label>
  <input id="p2" name="confirm" type="password" autocomplete="new-password" required>
  <button type="submit">Create password &amp; sign in</button>
  <p class="foot">Front door by Nell ✨ — dsh itself is untouched</p>
</form></body></html>`;
}

// ---------- proxying ----------
function upstreamHeaders(req) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (k === 'host' || k === 'cookie' || k === 'connection') continue;
    headers[k] = v;
  }
  headers.host = authority();
  const cookies = [];
  if (dshJar) cookies.push(dshJar);
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const name = part.split('=')[0].trim();
    if (name && name !== COOKIE_NAME) cookies.push(part.trim());
  }
  if (cookies.length) headers.cookie = cookies.join('; ');
  return headers;
}

function proxy(req, res, retried) {
  const opts = {
    host: UPSTREAM_HOST, port: UPSTREAM_PORT,
    method: req.method, path: req.url, headers: upstreamHeaders(req),
  };
  const up = http.request(opts, (upRes) => {
    if (upRes.statusCode === 401 && !retried && (req.method === 'GET' || req.method === 'HEAD')) {
      upRes.resume();
      exchange().then(() => proxy(req, res, true));
      return;
    }
    if (upRes.statusCode === 401) exchange(); // refresh jar for next time
    const headers = { ...upRes.headers };
    if (sessionAgeMs(req) > RENEW_AFTER_MS) {
      // Sliding renewal: quietly extend the never-expiring session so the
      // browser's 400-day cookie cap never actually signs the user out.
      const existing = upRes.headers['set-cookie'];
      const merged = existing ? (Array.isArray(existing) ? existing : [existing]) : [];
      headers['set-cookie'] = [...merged, makeSessionCookie()];
    }
    res.writeHead(upRes.statusCode, headers);
    upRes.pipe(res);
  });
  up.on('error', () => {
    if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); }
    res.end('gate: dsh is not reachable right now');
  });
  req.pipe(up);
}

// ---------- server ----------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://gate.local');

  if (url.pathname === '/__gate/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }

  // ----- setup state: password-only mode with no credential record yet.
  // Everything funnels to the one-time setup page until a password exists.
  if (!config) {
    if (url.pathname === '/__gate/setup' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(setupPage(''));
      return;
    }
    if (url.pathname === '/__gate/setup' && req.method === 'POST') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (rateLimited(ip)) {
        res.writeHead(429, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        res.end(setupPage('Too many attempts — wait a few minutes and try again.'));
        return;
      }
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > 16384) req.destroy();
      });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        const pw = form.get('password') || '';
        const confirm = form.get('confirm') || '';
        if (pw.length < 10) {
          recordFailure(ip);
          res.writeHead(400, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(setupPage('Password needs at least 10 characters.'));
          return;
        }
        if (pw !== confirm) {
          recordFailure(ip);
          res.writeHead(400, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(setupPage('Those passwords do not match.'));
          return;
        }
        const rec = makeRecord(pw);
        writeRecord(rec);
        config = rec;
        console.log('dsh-gate: password created via first-run setup');
        res.writeHead(302, { Location: '/', 'Set-Cookie': makeSessionCookie() });
        res.end();
      });
      return;
    }
    if (url.pathname.startsWith('/api')) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"error":"gate setup required"}');
    } else {
      res.writeHead(302, { Location: '/__gate/setup' });
      res.end();
    }
    return;
  }

  // Setup closes forever once a credential record exists.
  if (url.pathname === '/__gate/setup') {
    res.writeHead(302, { Location: '/__gate/login' });
    res.end();
    return;
  }

  if (url.pathname === '/__gate/login' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(loginPage(''));
    return;
  }

  if (url.pathname === '/__gate/login' && req.method === 'POST') {
    const ip = req.socket.remoteAddress || 'unknown';
    if (rateLimited(ip)) {
      res.writeHead(429, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(loginPage('Too many attempts — wait a few minutes and try again.'));
      return;
    }
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 16384) req.destroy();
    });
    req.on('end', () => {
      const form = new URLSearchParams(body);
      const userOk = PASSWORD_ONLY || form.get('username') === config.user;
      let pwOk = false;
      try { pwOk = passwordMatches(form.get('password') || ''); } catch { pwOk = false; }
      if (userOk && pwOk) {
        failures.delete(ip);
        res.writeHead(302, { Location: '/', 'Set-Cookie': makeSessionCookie() });
        res.end();
      } else {
        recordFailure(ip);
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        res.end(loginPage(PASSWORD_ONLY ? 'Wrong password.' : 'Wrong username or password.'));
      }
    });
    return;
  }

  if (url.pathname === '/__gate/logout') {
    res.writeHead(302, {
      Location: '/__gate/login',
      'Set-Cookie': `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`,
    });
    res.end();
    return;
  }

  if (url.pathname.startsWith('/__gate/')) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
    return;
  }

  if (!sessionValid(req)) {
    if (url.pathname.startsWith('/api')) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"error":"gate authentication required"}');
    } else {
      res.writeHead(302, { Location: '/__gate/login' });
      res.end();
    }
    return;
  }

  proxy(req, res, false);
});

server.on('upgrade', (req, socket, head) => {
  if (!config) { socket.destroy(); return; }
  if (!sessionValid(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const upstream = net.connect(UPSTREAM_PORT, UPSTREAM_HOST, () => {
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    const headers = upstreamHeaders(req);
    headers.connection = 'Upgrade';
    if (req.headers.upgrade) headers.upgrade = req.headers.upgrade;
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
    upstream.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
});

server.listen(PORT, BIND_HOST, () => {
  console.log(`dsh-gate: listening on ${BIND_HOST}:${PORT}, upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}, authority ${authority()}, auth ${PASSWORD_ONLY ? 'password-only' : 'user+password'}${config ? '' : ' (setup pending)'}`);
});
