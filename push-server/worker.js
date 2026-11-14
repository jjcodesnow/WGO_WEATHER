// WGO 9 Weather alert notifications (Cloudflare Worker)
//
// Setup in the Cloudflare dashboard:
//   1. Paste this file into a new Worker and deploy it.
//   2. Create a KV namespace and bind it to the Worker with the name DB.
//   3. Add a Cron Trigger that runs every minute: * * * * *
//
// The app sends its drawn alerts here. Every minute this Worker checks
// for alerts that have started and sends a push notification to the
// phone that drew them. Keys for signing pushes are made on first use
// and kept in KV, so there are no secrets to set up.

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};
const SUBJECT = 'https://jjcodesnow.github.io/WGO_WEATHER/';
const MAX_DEVICES = 50;
const MAX_ALERTS = 100;
const enc = new TextEncoder();

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { ...CORS, 'content-type': 'application/json' } });
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};

async function load(env) {
  return (await env.DB.get('db', 'json')) || { devices: {} };
}
async function store(env, db) {
  await env.DB.put('db', JSON.stringify(db));
}
async function deviceId(endpoint) {
  return b64u(await crypto.subtle.digest('SHA-256', enc.encode(endpoint))).slice(0, 24);
}

async function vapidKeys(env, db) {
  if (!db.vapid) {
    const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    db.vapid = {
      pub: b64u(await crypto.subtle.exportKey('raw', k.publicKey)),
      jwk: await crypto.subtle.exportKey('jwk', k.privateKey),
    };
    await store(env, db);
  }
  return db.vapid;
}

async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8));
}

// Encrypts the message for the phone (RFC 8291, aes128gcm).
async function encrypt(sub, text) {
  const uaPublic = unb64u(sub.keys.p256dh);
  const authSecret = unb64u(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const body = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2])))
  );
  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  return concat(header, asPublic, body);
}

async function sendPush(sub, vapid, message) {
  const aud = new URL(sub.endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const key = await crypto.subtle.importKey('jwk', vapid.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + claims));
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      TTL: '3600',
      Urgency: 'high',
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      Authorization: `vapid t=${head}.${claims}.${b64u(sig)}, k=${vapid.pub}`,
    },
    body: await encrypt(sub, JSON.stringify(message)),
  });
  return res.status;
}

function cleanAlert(a) {
  return {
    id: String(a.id).slice(0, 40),
    title: String(a.title || 'Weather alert').slice(0, 80),
    body: String(a.body || '').slice(0, 200),
    start: Number(a.start) || Date.now(),
    end: Number(a.end) || Date.now() + 3600e3,
  };
}

async function handle(req, env) {
  const url = new URL(req.url);
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
  const db = await load(env);

  if (url.pathname === '/vapid') return json({ key: (await vapidKeys(env, db)).pub });
  if (req.method !== 'POST') return json({ ok: true, service: 'WGO 9 Weather alerts' });

  const data = await req.json().catch(() => ({}));
  const sub = data.sub || {};
  if (!sub.endpoint || !/^https:\/\//.test(sub.endpoint)) return json({ error: 'Missing subscription' }, 400);
  const id = await deviceId(sub.endpoint);

  if (url.pathname === '/sync') {
    if (!sub.keys || !sub.keys.p256dh || !sub.keys.auth) return json({ error: 'Missing subscription keys' }, 400);
    if (!db.devices[id] && Object.keys(db.devices).length >= MAX_DEVICES) return json({ error: 'Too many devices' }, 429);
    const old = Object.fromEntries(((db.devices[id] || {}).alerts || []).map((a) => [a.id, a]));
    const now = Date.now();
    const alerts = (Array.isArray(data.alerts) ? data.alerts : [])
      .slice(0, MAX_ALERTS)
      .map(cleanAlert)
      .filter((a) => a.end > now)
      .map((a) => ({ ...a, sent: !!(old[a.id] && old[a.id].sent && old[a.id].start === a.start) }));
    db.devices[id] = { sub: { endpoint: sub.endpoint, keys: sub.keys }, alerts, seen: now };
    await store(env, db);
    return json({ ok: true, alerts: alerts.length });
  }

  if (url.pathname === '/test') {
    const dev = db.devices[id];
    if (!dev) return json({ error: 'Turn on notifications first' }, 404);
    const status = await sendPush(dev.sub, await vapidKeys(env, db), {
      title: 'WGO 9 Weather',
      body: 'Notifications are working. You’ll get one when an alert you draw starts.',
      tag: 'test',
    });
    return json({ ok: status < 300, status });
  }

  if (url.pathname === '/unsub') {
    delete db.devices[id];
    await store(env, db);
    return json({ ok: true });
  }
  return json({ error: 'Not found' }, 404);
}

async function checkAlerts(env) {
  const db = await load(env);
  const now = Date.now();
  let changed = false;
  for (const [id, dev] of Object.entries(db.devices)) {
    const before = dev.alerts.length;
    dev.alerts = dev.alerts.filter((a) => a.end > now);
    if (dev.alerts.length !== before) changed = true;
    for (const a of dev.alerts) {
      if (a.sent || a.start > now) continue;
      const status = await sendPush(dev.sub, await vapidKeys(env, db), { title: a.title, body: a.body, tag: a.id });
      if (status === 404 || status === 410) { delete db.devices[id]; changed = true; break; }
      if (status < 300) { a.sent = true; changed = true; }
    }
  }
  if (changed) await store(env, db);
}

export default {
  fetch: (req, env) => handle(req, env).catch((e) => json({ error: String(e && e.message || e) }, 500)),
  scheduled: (event, env, ctx) => ctx.waitUntil(checkAlerts(env)),
};
