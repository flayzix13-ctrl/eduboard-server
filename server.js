wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const roomId = (url.searchParams.get('room') || '').trim();
  const token = (url.searchParams.get('t')  '').trim().slice(0, 128)  null;

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
      // Target peerId travels in plaintext to (like any direct message) —
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
      // to the client tried to set.
      for (const teacher of teachersOf(roomId)) {
        send(teacher, { type: 'code-submit', from: ws.peerId, payload: msg.payload });
      }
      return;
    }

    // Envelope only — payload is opaque ciphertext to us.
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
  console.log(EduBoard relay listening on :${PORT});
});
