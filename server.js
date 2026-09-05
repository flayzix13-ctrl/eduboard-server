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
// Run: node server.js  (needs only the "ws" package — see package.json)
// Env: PORT (default 8080)
// -----------------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const MAX_ROOM_SIZE = 40; // sane cap for a classroom, tune as needed
const HEARTBEAT_MS = 30000;

// Must match `static-auth-secret` in coturn/turnserver.conf. Keep this in
// an env var / secrets manager on the real deploy — never commit it.
const TURN_SECRET = process.env.TURN_SECRET || '';
const TURN_TTL_SECONDS = 3600;

// Standard coturn "REST API" time-limited credential scheme: username is
// "<unix-expiry>:<label>", password is base64(HMAC-SHA1(secret, username)).
// This means client config.js never contains a long-lived TURN password —
// each browser fetches a fresh one that expires in an hour.
function mintTurnCredentials() {
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
  if (req.url === '/turn-credentials') {
    const creds = mintTurnCredentials();
    res.writeHead(creds ? 200 : 501, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(JSON.stringify(creds || { error: 'TURN_SECRET not configured on this relay' }));
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
  return { peerId: c.peerId, role: c.role, access: c.role === 'teacher' ? true : !!c.boardAccess };
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

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const roomId = (url.searchParams.get('room') || '').trim();
  const token = (url.searchParams.get('t') || '').trim().slice(0, 128) || null;

  if (!roomId || roomId.length > 64) {
    ws.close(4000, 'invalid room');
    return;
  }

  const set = roomOf(roomId);
  if (set.size >= MAX_ROOM_SIZE) {
    ws.close(4001, 'room full');
    return;
  }

  // --- Decide role ---------------------------------------------------
  const meta = metaOf(roomId);
  if (meta.teacherToken == null && token) {
    meta.teacherToken = token; // first token-bearing connection claims teacher
  }
  ws.role = (token && token === meta.teacherToken) ? 'teacher' : 'student';
  ws.boardAccess = false; // students start read-only on the board every connection

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
});
