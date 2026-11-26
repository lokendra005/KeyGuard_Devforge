"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const C = require("../crypto.cjs");
const M = require("../messaging.cjs");
const { fixture } = require("./helpers.cjs");
function pair(t) {
  const f = fixture(t);
  const receiver = new M.Receiver(
    f.keys.peer,
    f.actors.peer,
    { actor: f.actors.owner, public_key: f.keys.owner.public_key },
    f.store.get("authority"),
    { clock: f.now },
  );
  t.after(() => receiver.close());
  const offer = receiver.offer();
  const prepare = (bytes) =>
    M.encrypt(
      f.keys.owner,
      f.actors.owner,
      { actor: f.actors.peer, public_key: f.keys.peer.public_key },
      offer,
      bytes,
      f.now(),
    );
  return { f, receiver, offer, prepare };
}
test("one-time KEM message decrypts only after complete authenticated reassembly; duplicates are rejected", (t) => {
  const p = pair(t);
  const bytes = C.c.randomBytes(80000);
  const frames = p.prepare(bytes);
  let result;
  A.equal(p.receiver.receive(frames[2]).complete, false);
  A.equal(p.receiver.receive(frames[2]).complete, false);
  for (const frame of frames.filter((f) => f.index !== 2).reverse())
    result = p.receiver.receive(frame);
  A.ok(result.complete);
  A.deepEqual(result.body, bytes);
  A.equal(p.receiver.pending.size, 0);
  A.throws(
    () => p.receiver.receive(frames[0]),
    (e) => e.code === "REPLAY",
  );
  // A newly created endpoint with the same long-term key lacks the erased ephemeral key.
  const compromised = new M.Receiver(
    p.f.keys.peer,
    p.f.actors.peer,
    { actor: p.f.actors.owner, public_key: p.f.keys.owner.public_key },
    p.f.store.get("authority"),
    { clock: p.f.now },
  );
  A.throws(
    () => compromised.receive(frames[0]),
    (e) => e.code === "UNKNOWN_OR_EXPIRED_OFFER",
  );
  compromised.close();
});
test("message recipient, sender, suite, authority, chunks and ciphertext are authenticated", async (t) => {
  for (const field of [
    "to",
    "from",
    "authority",
    "suite",
    "offer_id",
    "expires",
    "chunks",
    "nonce",
    "digest",
  ])
    await t.test(field, (sub) => {
      const p = pair(sub);
      const frames = p.prepare(Buffer.from("private"));
      const bad = structuredClone(frames[0]);
      bad.header[field] =
        typeof bad.header[field] === "number"
          ? bad.header[field] + 1
          : C.random();
      A.throws(() => p.receiver.receive(bad));
    });
  await t.test("ciphertext corruption", (sub) => {
    const p = pair(sub);
    const frame = p.prepare(Buffer.from("private"))[0];
    const chunk = C.b64(frame.chunk);
    chunk[0] ^= 1;
    frame.chunk = chunk.toString("base64");
    A.throws(
      () => p.receiver.receive(frame),
      (e) => e.code === "INTEGRITY_FAILURE",
    );
    A.equal(p.receiver.pending.size, 0);
  });
});
test("bounded loss recovery delivers exactly once; incomplete expired messages report failure", (t) => {
  const p = pair(t);
  const frames = p.prepare(C.c.randomBytes(50000));
  p.receiver.receive(frames[1]);
  p.receiver.receive(frames[3]);
  const pending = p.receiver.receive(frames[0]);
  A.equal(pending.complete, false);
  const delivered = p.receiver.receive(frames[2]);
  A.equal(delivered.complete, true);
  const other = p.receiver.offer(1000);
  const partial = M.encrypt(
    p.f.keys.owner,
    p.f.actors.owner,
    { actor: p.f.actors.peer, public_key: p.f.keys.peer.public_key },
    other,
    C.c.randomBytes(30000),
    p.f.now(),
  );
  A.equal(p.receiver.receive(partial[0]).complete, false);
  p.f.tick(1001);
  A.deepEqual(p.receiver.expire(), [other.id]);
  A.throws(() => p.receiver.receive(partial[1]));
});
test("relay stores ciphertext, supports partial retries and checks both peers at every operation", (t) => {
  const p = pair(t);
  const { f } = p;
  const secret = Buffer.from("unique-private-message-" + C.random());
  const frames = p.prepare(secret);
  A.equal(f.call("peer", { op: "mail.offer", offer: p.offer }).published, true);
  A.equal(
    f.call("owner", { op: "mail.lookup", recipient: f.actors.peer }).offer.id,
    p.offer.id,
  );
  A.equal(f.call("owner", { op: "mail.deliver", frames }).queued, 1);
  A.equal(f.call("owner", { op: "mail.deliver", frames }).queued, 1);
  A.equal(
    JSON.stringify(f.store.db.prepare("SELECT * FROM mail").all()).includes(
      secret.toString(),
    ),
    false,
  );
  const queued = f.call("peer", { op: "mail.poll" }).messages[0];
  const result = p.receiver.receive(queued[0]);
  A.deepEqual(result.body, secret);
  A.equal(
    f.call("peer", { op: "mail.ack", message_id: result.message_id })
      .acknowledged,
    true,
  );
  A.throws(
    () => f.call("owner", { op: "mail.deliver", frames }),
    (e) => e.code === "UNKNOWN_OR_CONSUMED_OFFER",
  );
  f.trusted({ op: "revoke", actor: f.actors.peer });
  A.throws(
    () => f.call("peer", { op: "mail.poll" }),
    (e) => e.code === "UNAUTHORIZED",
  );
});
test("random messages, empty bodies and chunk boundaries round-trip under shuffled delivery", (t) => {
  const f = fixture(t);
  for (const size of [0, 1, 16383, 16384, 16385, 1048576]) {
    const receiver = new M.Receiver(
      f.keys.peer,
      f.actors.peer,
      { actor: f.actors.owner, public_key: f.keys.owner.public_key },
      f.store.get("authority"),
      { clock: f.now },
    );
    const data = C.c.randomBytes(size);
    const offer = receiver.offer();
    const frames = M.encrypt(
      f.keys.owner,
      f.actors.owner,
      { actor: f.actors.peer, public_key: f.keys.peer.public_key },
      offer,
      data,
      f.now(),
    );
    let result;
    for (const frame of frames.reverse()) result = receiver.receive(frame);
    A.deepEqual(result.body, data);
    receiver.close();
  }
});
