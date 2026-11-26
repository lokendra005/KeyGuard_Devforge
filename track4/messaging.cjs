"use strict";
const C = require("./crypto.cjs");
const SUITE = "ML-KEM-768/HKDF-SHA384/AES-256-GCM/ML-DSA-65";
const MAX_MESSAGE = 1048576;
const CHUNK = 16384;
function binding(h) {
  return {
    version: h.version,
    suite: h.suite,
    authority: h.authority,
    message_id: h.message_id,
    offer_id: h.offer_id,
    from: h.from,
    to: h.to,
    from_key: h.from_key,
    to_key: h.to_key,
    expires: h.expires,
    kem_ciphertext: h.kem_ciphertext,
  };
}
function derive(shared, offer, bound) {
  return Buffer.from(
    C.c.hkdfSync(
      "sha384",
      shared,
      Buffer.from(C.digest(offer), "hex"),
      Buffer.from(C.digest(["KIG/message-key/v1", bound]), "hex"),
      32,
    ),
  );
}
function verifyOffer(offer, peerKey, now) {
  C.object(offer);
  const { signature, ...body } = offer;
  C.check(
    body.version === 1 &&
      body.suite === SUITE &&
      body.to_key === C.keyID(peerKey),
    "WRONG_RECIPIENT",
  );
  for (const k of ["authority", "id", "from", "to", "from_key", "to_key"])
    C.text(body[k]);
  C.integer(body.expires, now, now + 300000);
  C.b64(body.public_key, 1184);
  C.check(
    C.verify(peerKey, "KIG/message-offer/v1", body, signature),
    "INVALID_OFFER",
  );
  return body;
}
function encrypt(
  identity,
  actor,
  trustedRecipient,
  offer,
  bytes,
  now = Date.now(),
) {
  C.check(
    Buffer.isBuffer(bytes) && bytes.length <= MAX_MESSAGE,
    "MESSAGE_TOO_LARGE",
  );
  const checked = verifyOffer(offer, trustedRecipient.public_key, now);
  C.check(
    checked.from === actor &&
      checked.from_key === C.keyID(identity.public_key) &&
      checked.to === trustedRecipient.actor,
    "WRONG_PEER",
  );
  const { ciphertext, sharedKey } = C.encapsulate(checked.public_key);
  const bound = {
    version: 1,
    suite: SUITE,
    authority: checked.authority,
    message_id: C.random(),
    offer_id: checked.id,
    from: actor,
    to: checked.to,
    from_key: checked.from_key,
    to_key: checked.to_key,
    expires: checked.expires,
    kem_ciphertext: ciphertext.toString("base64"),
  };
  const key = derive(sharedKey, offer, bound);
  let packet;
  try {
    packet = C.seal(key, bytes, bound);
  } finally {
    key.fill(0);
    sharedKey.fill(0);
  }
  const encrypted = C.b64(packet.body);
  const header = {
    ...bound,
    nonce: packet.nonce,
    tag: packet.tag,
    length: encrypted.length,
    chunks: Math.max(1, Math.ceil(encrypted.length / CHUNK)),
    digest: C.hash(encrypted),
  };
  const signature = C.sign(
    identity.private_key,
    "KIG/message-header/v1",
    header,
  );
  return Array.from({ length: header.chunks }, (_, index) => ({
    header,
    signature,
    index,
    chunk: encrypted
      .subarray(index * CHUNK, (index + 1) * CHUNK)
      .toString("base64"),
  }));
}
function validateFrame(frame, senderKey, now) {
  C.object(frame);
  const h = C.object(frame.header);
  C.check(
    Object.keys(h).sort().join(",") ===
      "authority,chunks,digest,expires,from,from_key,kem_ciphertext,length,message_id,nonce,offer_id,suite,tag,to,to_key,version",
    "INVALID_HEADER",
  );
  C.check(
    h.version === 1 && h.suite === SUITE && h.from_key === C.keyID(senderKey),
    "INVALID_HEADER",
  );
  for (const k of [
    "authority",
    "message_id",
    "offer_id",
    "from",
    "to",
    "to_key",
  ])
    C.text(h[k]);
  C.integer(h.expires, now, now + 300000);
  C.integer(h.length, 0, MAX_MESSAGE);
  C.check(
    h.chunks === Math.max(1, Math.ceil(h.length / CHUNK)),
    "INVALID_CHUNKS",
  );
  C.integer(frame.index, 0, h.chunks - 1);
  const bytes = C.b64(frame.chunk, undefined, CHUNK);
  C.check(
    bytes.length ===
      (frame.index === h.chunks - 1 ? h.length - frame.index * CHUNK : CHUNK),
    "INVALID_CHUNK_SIZE",
  );
  C.b64(h.kem_ciphertext, 1088);
  C.b64(h.nonce, 12);
  C.b64(h.tag, 16);
  C.check(
    /^[0-9a-f]{96}$/.test(h.digest) &&
      C.verify(senderKey, "KIG/message-header/v1", h, frame.signature),
    "INVALID_SIGNATURE",
  );
  return bytes;
}
class Receiver {
  constructor(identity, actor, trustedSender, authority, options = {}) {
    this.identity = identity;
    this.actor = actor;
    this.sender = trustedSender;
    this.authority = authority;
    this.clock = options.clock || Date.now;
    this.pending = new Map();
    this.completed = new Map();
  }
  offer(lifetime = 60000) {
    const now = this.clock();
    this.expire();
    C.check(this.pending.size < 8, "PENDING_CAPACITY");
    C.integer(lifetime, 1000, 300000);
    const pair = C.c.generateKeyPairSync("ml-kem-768");
    const spki = pair.publicKey.export({ format: "der", type: "spki" });
    const body = {
      version: 1,
      suite: SUITE,
      authority: this.authority,
      id: C.random(),
      from: this.sender.actor,
      to: this.actor,
      from_key: C.keyID(this.sender.public_key),
      to_key: C.keyID(this.identity.public_key),
      expires: now + lifetime,
      public_key: spki.subarray(C.KEM_SPKI.length).toString("base64"),
    };
    const offer = {
      ...body,
      signature: C.sign(
        this.identity.private_key,
        "KIG/message-offer/v1",
        body,
      ),
    };
    this.pending.set(body.id, {
      offer,
      privateKey: pair.privateKey,
      chunks: new Map(),
      header: null,
    });
    return offer;
  }
  expire() {
    const now = this.clock();
    const failed = [];
    for (const [id, entry] of this.pending)
      if (entry.offer.expires < now) {
        entry.privateKey = undefined;
        this.pending.delete(id);
        failed.push(id);
      }
    for (const [id, expires] of this.completed)
      if (expires < now) this.completed.delete(id);
    return failed;
  }
  receive(frame) {
    this.expire();
    const h = C.object(frame.header);
    C.check(!this.completed.has(h.offer_id), "REPLAY");
    const pending = this.pending.get(h.offer_id);
    C.check(pending, "UNKNOWN_OR_EXPIRED_OFFER");
    const bytes = validateFrame(frame, this.sender.public_key, this.clock());
    C.check(
      h.to === this.actor &&
        h.from === this.sender.actor &&
        h.to_key === pending.offer.to_key &&
        h.from_key === pending.offer.from_key &&
        h.authority === this.authority &&
        h.expires === pending.offer.expires,
      "WRONG_PEER",
    );
    if (pending.header)
      C.check(C.digest(pending.header) === C.digest(h), "CONFLICTING_MESSAGE");
    else pending.header = h;
    const old = pending.chunks.get(frame.index);
    C.check(!old || old.equals(bytes), "CONFLICTING_CHUNK");
    pending.chunks.set(frame.index, bytes);
    if (pending.chunks.size !== h.chunks)
      return {
        complete: false,
        received: pending.chunks.size,
        total: h.chunks,
      };
    const encrypted = Buffer.concat(
      Array.from({ length: h.chunks }, (_, i) => pending.chunks.get(i)),
    );
    try {
      C.check(
        C.hash(encrypted) === h.digest && encrypted.length === h.length,
        "INTEGRITY_FAILURE",
      );
      const shared = C.c.decapsulate(
        pending.privateKey,
        C.b64(h.kem_ciphertext, 1088),
      );
      const bound = binding(h);
      const key = derive(shared, pending.offer, bound);
      try {
        const body = C.open(
          key,
          { nonce: h.nonce, tag: h.tag, body: encrypted.toString("base64") },
          bound,
        );
        this.completed.set(h.offer_id, h.expires);
        return { complete: true, message_id: h.message_id, body };
      } finally {
        shared.fill(0);
        key.fill(0);
      }
    } finally {
      // Ephemeral private KeyObjects never enter persistent state; native/GC erasure is an explicit trust assumption.
      pending.privateKey = undefined;
      pending.chunks.clear();
      this.pending.delete(h.offer_id);
    }
  }
  close() {
    for (const entry of this.pending.values()) {
      entry.privateKey = undefined;
      entry.chunks.clear();
    }
    this.pending.clear();
  }
}
function relay(store, request, auth, now) {
  C.check(!auth.trusted, "SIGNED_PEER_REQUIRED");
  const db = store.db;
  db.prepare("DELETE FROM mail WHERE expires<?").run(now);
  db.prepare("DELETE FROM offers WHERE expires<?").run(now);
  if (request.op === "mail.offer") {
    const offer = request.offer;
    const key = db
      .prepare("SELECT public_key FROM keys WHERE id=?")
      .get(auth.key_id);
    verifyOffer(offer, key.public_key, now);
    C.check(
      offer.to === auth.actor &&
        offer.authority === store.get("authority") &&
        offer.expires <= now + store.policy().mailbox_lifetime_ms,
      "WRONG_PEER",
    );
    const sender = db
      .prepare("SELECT * FROM keys WHERE id=?")
      .get(offer.from_key);
    const actor = db.prepare("SELECT * FROM actors WHERE id=?").get(offer.from);
    C.check(
      sender &&
        sender.actor === offer.from &&
        !sender.revoked &&
        actor &&
        !actor.disabled &&
        (sender.not_after === null || now < sender.not_after),
      "UNAUTHORIZED_PEER",
    );
    C.check(
      db.prepare("SELECT count(*) AS n FROM offers").get().n <
        store.policy().max_mail,
      "MAILBOX_CAPACITY",
    );
    C.check(
      !db.prepare("SELECT id FROM offers WHERE id=?").get(offer.id),
      "OFFER_REUSED",
    );
    db.prepare("INSERT INTO offers(id,actor,body,expires) VALUES(?,?,?,?)").run(
      offer.id,
      auth.actor,
      C.canonical(offer),
      offer.expires,
    );
    store.record(now, request.op, auth.actor, {
      offer_id: offer.id,
      sender: offer.from,
    });
    return { published: true };
  }
  if (request.op === "mail.lookup") {
    C.text(request.recipient);
    const candidates = db
      .prepare(
        "SELECT body FROM offers WHERE actor=? AND used=0 AND expires>=? ORDER BY expires LIMIT 100",
      )
      .all(request.recipient, now)
      .map((r) => C.parse(r.body));
    return {
      offer:
        candidates.find(
          (o) => o.from === auth.actor && o.from_key === auth.key_id,
        ) || null,
    };
  }
  if (request.op === "mail.deliver") {
    C.check(
      Array.isArray(request.frames) &&
        request.frames.length >= 1 &&
        request.frames.length <= 64,
      "INVALID_FRAMES",
    );
    const h = request.frames[0].header;
    const entry = db.prepare("SELECT * FROM offers WHERE id=?").get(h.offer_id);
    C.check(entry && entry.used < 2, "UNKNOWN_OR_CONSUMED_OFFER");
    const offer = C.parse(entry.body);
    C.check(
      h.from === auth.actor &&
        h.from === offer.from &&
        h.from_key === auth.key_id &&
        h.from_key === offer.from_key &&
        h.to === offer.to &&
        h.to_key === offer.to_key &&
        h.authority === offer.authority &&
        h.expires === offer.expires,
      "WRONG_PEER",
    );
    const receiverKey = db
      .prepare("SELECT * FROM keys WHERE id=?")
      .get(h.to_key);
    const receiver = db.prepare("SELECT * FROM actors WHERE id=?").get(h.to);
    C.check(
      receiverKey &&
        !receiverKey.revoked &&
        (receiverKey.not_after === null || now < receiverKey.not_after) &&
        receiver &&
        !receiver.disabled,
      "UNAUTHORIZED_PEER",
    );
    const senderKey = db
      .prepare("SELECT public_key FROM keys WHERE id=?")
      .get(auth.key_id).public_key;
    const existing = db
      .prepare("SELECT body FROM mail WHERE id=?")
      .get(h.message_id);
    const all = existing ? C.parse(existing.body) : [];
    C.check(
      existing ||
        db.prepare("SELECT count(*) AS n FROM mail").get().n <
          store.policy().max_mail,
      "MAILBOX_CAPACITY",
    );
    C.check(
      !db
        .prepare("SELECT id FROM mail WHERE offer_id=? AND id<>?")
        .get(h.offer_id, h.message_id),
      "OFFER_ALREADY_USED",
    );
    for (const frame of request.frames) {
      validateFrame(frame, senderKey, now);
      C.check(C.digest(frame.header) === C.digest(h), "CONFLICTING_MESSAGE");
      if (all.length)
        C.check(C.digest(all[0].header) === C.digest(h), "CONFLICTING_MESSAGE");
      const old = all.find((f) => f.index === frame.index);
      C.check(!old || C.digest(old) === C.digest(frame), "CONFLICTING_CHUNK");
      if (!old) all.push(frame);
    }
    db.prepare(
      "INSERT INTO mail VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
    ).run(h.message_id, h.from, h.to, h.offer_id, C.canonical(all), h.expires);
    db.prepare("UPDATE offers SET used=1 WHERE id=?").run(h.offer_id);
    store.record(now, request.op, auth.actor, {
      recipient: h.to,
      message_id: h.message_id,
      chunks: all.length,
      total: h.chunks,
    });
    return { queued: all.length, total: h.chunks };
  }
  if (request.op === "mail.poll") {
    return {
      messages: db
        .prepare(
          "SELECT body FROM mail WHERE recipient=? ORDER BY expires LIMIT 8",
        )
        .all(auth.actor)
        .map((r) => C.parse(r.body)),
    };
  }
  if (request.op === "mail.ack") {
    C.text(request.message_id);
    const row = db
      .prepare("SELECT body FROM mail WHERE id=? AND recipient=?")
      .get(request.message_id, auth.actor);
    C.check(row, "NOT_FOUND");
    const frame = C.parse(row.body)[0];
    db.prepare("UPDATE offers SET used=2 WHERE id=?").run(
      frame.header.offer_id,
    );
    db.prepare("DELETE FROM mail WHERE id=?").run(request.message_id);
    store.record(now, request.op, auth.actor, {
      message_id: request.message_id,
    });
    return { acknowledged: true };
  }
  throw new C.Fault("UNSUPPORTED_OPERATION");
}
module.exports = {
  Receiver,
  encrypt,
  relay,
  validateFrame,
  verifyOffer,
  SUITE,
  MAX_MESSAGE,
};
