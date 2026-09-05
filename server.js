// EduBoard signaling / relay server
// -----------------------------------------------------------------------
// This process does four things and nothing else:
//   1. Groups WebSocket connections into rooms (?room=CODE in the URL).
//   2. Assigns each connection a random peerId and tells everyone in the
//      room who's there (join/leave presence), including their ROLE.
//   3. Relays opaque messages between peers — either to everyone in the
//      room ("broadcast") or to one specific peerId ("direct").
//   4. Enforces the teacher/student permission model described below.
//
// It NEVER looks inside `payload`. Chat text, board updates and WebRTC
// SDP/ICE data are all encrypted client-side (see client/crypto.js)
// before they ever reach this server — see README "Security model".
// This server could be fully compromised and an attacker would still only
// see ciphertext + routing metadata (who talked to whom, when, how much,
// and now also who's the teacher — that's metadata, same tier as peerId).
//
// --- Roles ---------------------------------------------------------------
// Whoever first connects to a room with a "?t=<teacherToken>" query param
// becomes that room's TEACHER; the server remembers that token for the
// lifetime of the room, so the same person reconnecting (refresh, second
// tab/device) with the same token is recognized as teacher again. Everyone
// else — including anyone who connects without a token, or with the wrong
// one — is a STUDENT. The token is generated client-side (index.html) and
// lives only in the room CREATOR's own address bar; the invite link built
// for students (app.js) never includes it.
//
// Because role is decided here, on the server, a student can't just flip a
// flag in devtools to become "teacher" — the enforcement below is real,
// not cosmetic:
//   - 'board-update' (a drawn stroke/shape) from a student is DROPPED
//     unless the teacher has granted that student board access.
//   - 'code-submit' (sandbox code) from a student is ALWAYS routed only to
//     the teacher, no matter what `to` the client puts on the message.
//   - 'grant-access' / 'revoke-access' are only honored from the teacher.
// One caveat, inherent to having no accounts: peerId (and therefore any
// granted board access) is per-connection, so it resets if a student's
// tab reloads or reconnects. The teacher just re-grants it — one click.
//
// Run: node server.js  (needs "ws", "pg", "bcryptjs" — see package.json)
// Env: PORT (default 8080), DATABASE_URL, SESSION_SECRET (see "Accounts" below)
// -----------------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 8080;
const MAX_ROOM_SIZE = 40; // sane cap for a classroom, tune as needed
const HEARTBEAT_MS = 30000;

// --- Accounts --------------------------------------------------------------
// Real name/surname/gender + password, so people are recognized by name
// instead of a random ID — separate from, and layered on top of, the
// teacher/student token system above (that still decides room permissions;
// accounts just decide what name is shown).
//
// Requires a PERMANENT Postgres database (not Render's free one — that
// auto-deletes after 30 days). Use Neon.tech's free tier instead — see
// README "Аккаунты". Two env vars, both set in Render's Environment tab:
//   DATABASE_URL    postgres connection string from Neon
//   SESSION_SECRET  any long random string you make up — signs login
//                   sessions so they can't be forged; never in code/git.
const DATABASE_URL = process.env.DATABASE_URL || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      gender TEXT,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);
}

// Password policy: 8+ chars, at least one uppercase letter, one digit, one
// underscore. Checked again here even though the browser checks it too —
// a client-side check alone can always be bypassed.
function isPasswordValid(pw) {
  return typeof pw === 'string'
    && pw.length >= 8
    && /[A-Z]/.test(pw)
    && /[0-9]/.test(pw)
    && /_/.test(pw);
}

function signSession(userId) {
  const payload = Buffer.from(JSON.stringify({ userId, exp: Date.now() + SESSION_TTL_SECONDS * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token || !SESSION_SECRET) return null;
  const [payload, sig] = String(token).split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return null; // tampered or wrong secret
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null; // expired
    return data.userId;
  } catch {
    return null;
  }
}

// firstname.lastname, de-duplicated with a trailing number if already taken
// (e.g. two students both named "Иван Иванов" -> ivan.ivanov, ivan.ivanov2).
async function makeUniqueLogin(firstName, lastName) {
  const base = `${firstName}.${lastName}`.toLowerCase().replace(/\s+/g, '');
  let candidate = base;
  let n = 1;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { rows } = await pool.query('SELECT 1 FROM users WHERE login = $1', [candidate]);
    if (rows.length === 0) return candidate;
    n += 1;
    candidate = `${base}${n}`;
  }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 10_000) req.destroy(); // guard against absurd bodies
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

async function handleRegister(req, res) {
  if (!pool || !SESSION_SECRET) {
    res.writeHead(501, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Accounts not configured (set DATABASE_URL and SESSION_SECRET)' }));
    return;
  }
  let body;
  try { body = await readJsonBody(req); } catch { res.writeHead(400); res.end(); return; }

  const firstName = String(body.firstName || '').trim().slice(0, 60);
  const lastName = String(body.lastName || '').trim().slice(0, 60);
  const gender = ['male', 'female', 'unspecified'].includes(body.gender) ? body.gender : 'unspecified';
  const password = String(body.password || '');
  const passwordConfirm = String(body.passwordConfirm || '');

  if (!firstName || !lastName) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Укажите имя и фамилию' }));
    return;
  }
  if (password !== passwordConfirm) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Пароли не совпадают' }));
    return;
  }
  if (!isPasswordValid(password)) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Пароль должен быть не короче 8 символов и содержать заглавную букву, цифру и "_"' }));
    return;
  }

  const login = await makeUniqueLogin(firstName, lastName);
  const passwordHash = await bcrypt.hash(password, 12);
  const { rows } = await pool.query(
    'INSERT INTO users (login, first_name, last_name, gender, password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [login, firstName, lastName, gender, passwordHash]
  );
  const token = signSession(rows[0].id);
  res.writeHead(201, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ token, login, firstName, lastName, gender }));
}

async function handleLogin(req, res) {
  if (!pool || !SESSION_SECRET) {
    res.writeHead(501, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Accounts not configured (set DATABASE_URL and SESSION_SECRET)' }));
    return;
  }
  let body;
  try { body = await readJsonBody(req); } catch { res.writeHead(400); res.end(); return; }

  const login = String(body.login || '').trim().toLowerCase().slice(0, 128);
  const password = String(body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
  const user = rows[0];
  // Same generic error whether the login doesn't exist or the password is
  // wrong — don't help an attacker enumerate which logins exist.
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Неверный логин или пароль' }));
    return;
  }
  const token = signSession(user.id);
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ token, login: user.login, firstName: user.first_name, lastName: user.last_name, gender: user.gender }));
}

async function handleMe(req, res, token) {
  const userId = verifySession(token);
  if (!userId || !pool) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid or expired session' }));
    return;
  }
  const { rows } = await pool.query('SELECT login, first_name, last_name, gender FROM users WHERE id = $1', [userId]);
  if (!rows[0]) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Account no longer exists' }));
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ login: rows[0].login, firstName: rows[0].first_name, lastName: rows[0].last_name, gender: rows[0].gender }));
}

// --- TURN credentials -----------------------------------------------------
// Two supported backends, tried in this order. Either way, the secret used
// to mint credentials NEVER reaches the browser — only a short-lived
// username/password (or ready-made iceServers array) does.
//
// A) Metered.ca hosted TURN (recommended — no server of your own to run).
//    Set these two env vars in Render's "Environment" tab (not in code):
//      METERED_DOMAIN      e.g. syncclasseduboard.metered.live
//      METERED_SECRET_KEY  from Metered dashboard -> Developers (SECRET KEY)
//
// B) Self-hosted coturn (see coturn/ folder), using a shared HMAC secret.
//    Set TURN_SECRET to the same value as `static-auth-secret` in
//    coturn/turnserver.conf.
const METERED_DOMAIN = process.env.METERED_DOMAIN || '';
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY || '';
const TURN_SECRET = process.env.TURN_SECRET || '';
const TURN_TTL_SECONDS = 3600;

// Option A: ask Metered to mint a fresh short-lived credential (server-side,
// using the secret key), then exchange it for the actual ready-to-use
// iceServers array (STUN + TURN URLs + username/password already filled in).
// Two calls, both server-to-server — the secret key never leaves this process.
async function mintMeteredIceServers() {
  const createRes = await fetch(
    `https://${METERED_DOMAIN}/api/v1/turn/credential?secretKey=${encodeURIComponent(METERED_SECRET_KEY)}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ expiryInSeconds: TURN_TTL_SECONDS, label: 'eduboard' }),
    }
  );
  if (!createRes.ok) throw new Error(`Metered credential create failed: ${createRes.status}`);
  const { apiKey } = await createRes.json();
  if (!apiKey) throw new Error('Metered response missing apiKey');

  const iceRes = await fetch(
    `https://${METERED_DOMAIN}/api/v1/turn/credentials?apiKey=${encodeURIComponent(apiKey)}`
  );
  if (!iceRes.ok) throw new Error(`Metered iceServers fetch failed: ${iceRes.status}`);
  return iceRes.json(); // already a ready-to-use iceServers array
}

// Option B: standard coturn "REST API" time-limited credential scheme —
// username is "<unix-expiry>:<label>", password is
// base64(HMAC-SHA1(secret, username)).
function mintCoturnCredentials() {
  if (!TURN_SECRET) return null;
  const expiry = Math.floor(Date.now() / 1000) + TURN_TTL_SECONDS;
  const username = `${expiry}:eduboard`;
  const credential = crypto.createHmac('sha1', TURN_SECRET).update(username).digest('base64');
  return { username, credential, ttl: TURN_TTL_SECONDS };
}

const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, rooms: rooms.size }));
    return;
  }

  if (req.method === 'OPTIONS') {
    // CORS preflight for the POST endpoints below
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type,authorization',
    });
    res.end();
    return;
  }
  res.setHeader('access-control-allow-origin', '*');

  if (req.method === 'POST' && req.url === '/register') {
    handleRegister(req, res).catch((err) => {
      console.error('register error:', err.message);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Server error' }));
    });
    return;
  }
  if (req.method === 'POST' && req.url === '/login') {
    handleLogin(req, res).catch((err) => {
      console.error('login error:', err.message);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Server error' }));
    });
    return;
  }
  if (req.method === 'GET' && req.url === '/me') {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    handleMe(req, res, token).catch((err) => {
      console.error('me error:', err.message);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Server error' }));
    });
    return;
  }

  if (req.url === '/turn-credentials') {
    res.setHeader('access-control-allow-origin', '*');
    if (METERED_DOMAIN && METERED_SECRET_KEY) {
      mintMeteredIceServers()
        .then((iceServers) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ iceServers }));
        })
        .catch((err) => {
          console.error('Metered TURN error:', err.message);
          res.writeHead(502, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Could not reach Metered TURN API' }));
        });
      return;
    }
    const creds = mintCoturnCredentials();
    res.writeHead(creds ? 200 : 501, { 'content-type': 'application/json' });
    res.end(JSON.stringify(creds || { error: 'No TURN backend configured (set METERED_DOMAIN+METERED_SECRET_KEY, or TURN_SECRET)' }));
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server: httpServer });

/** @type {Map<string, Set<import('ws').WebSocket>>} */
const rooms = new Map();
/** @type {Map<string, { teacherToken: string|null }>} */
const roomMeta = new Map();

function roomOf(roomId) {
  let set = rooms.get(roomId);
  if (!set) {
    set = new Set();
    rooms.set(roomId, set);
  }
  return set;
}

function metaOf(roomId) {
  let m = roomMeta.get(roomId);
  if (!m) {
    m = { teacherToken: null };
    roomMeta.set(roomId, m);
  }
  return m;
}

function teachersOf(roomId) {
  return [...roomOf(roomId)].filter((c) => c.role === 'teacher');
}

function peerInfo(c) {
  return {
    peerId: c.peerId,
    role: c.role,
    access: c.role === 'teacher' ? true : !!c.boardAccess,
    displayName: c.displayName || null, // null -> frontend falls back to showing peerId
  };
}

function peersIn(roomId, exceptWs) {
  return [...roomOf(roomId)].filter((c) => c !== exceptWs).map(peerInfo);
}

function send(ws, msg) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}

function broadcast(roomId, msg, exceptWs) {
  for (const client of roomOf(roomId)) {
    if (client !== exceptWs) send(client, msg);
  }
}

wss.on('connection', async (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const roomId = (url.searchParams.get('room') || '').trim();
  const token = (url.searchParams.get('t') || '').trim().slice(0, 128) || null;
  const sessionToken = (url.searchParams.get('session') || '').trim().slice(0, 512) || null;

  if (!roomId || roomId.length > 64) {
    ws.close(4000, 'invalid room');
    return;
  }

  const set = roomOf(roomId);
  if (set.size >= MAX_ROOM_SIZE) {
    ws.close(4001, 'room full');
    return;
  }

  // Optional: if this connection carries a valid session, show their real
  // name instead of a random ID. Failure here (expired/invalid/no DB) just
  // means displayName stays null — never blocks joining the room, since
  // accounts are for display only, not for the teacher/student permission
  // model below (that's still decided purely by the ?t= token).
  let displayName = null;
  if (sessionToken && pool) {
    const userId = verifySession(sessionToken);
    if (userId) {
      try {
        const { rows } = await pool.query('SELECT first_name, last_name FROM users WHERE id = $1', [userId]);
        if (rows[0]) displayName = `${rows[0].first_name} ${rows[0].last_name}`;
      } catch (err) {
        console.error('session lookup error:', err.message);
      }
    }
  }

  // --- Decide role ---------------------------------------------------
  const meta = metaOf(roomId);
  if (meta.teacherToken == null && token) {
    meta.teacherToken = token; // first token-bearing connection claims teacher
  }
  ws.role = (token && token === meta.teacherToken) ? 'teacher' : 'student';
  ws.boardAccess = false; // students start read-only on the board every connection
  ws.displayName = displayName;

  ws.roomId = roomId;
  ws.peerId = crypto.randomBytes(6).toString('hex');
  ws.isAlive = true;
  set.add(ws);

  send(ws, { type: 'welcome', peerId: ws.peerId, role: ws.role, peers: peersIn(roomId, ws) });
  broadcast(roomId, { type: 'peer-joined', ...peerInfo(ws) }, ws);

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;

    // --- Permission enforcement (metadata only — payload stays opaque) ---

    if (msg.type === 'grant-access' || msg.type === 'revoke-access') {
      if (ws.role !== 'teacher') return; // only the teacher may change access
      // Target peerId travels in plaintext `to` (like any direct message) —
      // the server has to read it to know which connection to flip.
      const target = [...roomOf(roomId)].find((c) => c.peerId === msg.to && c.role === 'student');
      if (!target) return;
      target.boardAccess = (msg.type === 'grant-access');
      broadcast(roomId, { type: 'access-changed', peerId: target.peerId, access: target.boardAccess }, null);
      return;
    }

    if (msg.type === 'board-update' && ws.role !== 'teacher' && !ws.boardAccess) {
      return; // student hasn't been granted board access — drop the stroke
    }

    if (msg.type === 'code-submit' && ws.role !== 'teacher') {
      // Hard rule: students can only ever send sandbox code to the teacher
      // (all of the teacher's connected tabs/devices), regardless of what
      // `to` the client tried to set.
      for (const teacher of teachersOf(roomId)) {
        send(teacher, { type: 'code-submit', from: ws.peerId, payload: msg.payload });
      }
      return;
    }

    // Envelope only — `payload` is opaque ciphertext to us.
    const envelope = { type: msg.type, from: ws.peerId, payload: msg.payload };

    if (msg.to) {
      // Direct message to one peer (WebRTC signaling, targeted sync response)
      const target = [...roomOf(roomId)].find((c) => c.peerId === msg.to);
      if (target) send(target, envelope);
    } else {
      // Room-wide broadcast (chat, board CRDT updates, presence-ish events)
      broadcast(roomId, envelope, ws);
    }
  });

  ws.on('close', () => {
    set.delete(ws);
    broadcast(roomId, { type: 'peer-left', peerId: ws.peerId }, ws);
    if (set.size === 0) {
      rooms.delete(roomId);
      roomMeta.delete(roomId); // room is gone — next use of this code starts fresh
    }
  });

  ws.on('error', () => {});
});

// Drop dead connections (phones sleeping, network drops, etc.)
const heartbeat = setInterval(() => {
  for (const client of wss.clients) {
    if (client.isAlive === false) {
      client.terminate();
      continue;
    }
    client.isAlive = false;
    client.ping();
  }
}, HEARTBEAT_MS);

wss.on('close', () => clearInterval(heartbeat));

httpServer.listen(PORT, () => {
  console.log(`EduBoard relay listening on :${PORT}`);
  if (pool) {
    initDb()
      .then(() => console.log('Accounts DB ready'))
      .catch((err) => console.error('Accounts DB init failed:', err.message));
  } else {
    console.log('DATABASE_URL not set — accounts (register/login) disabled, everything else works as before');
  }
});
