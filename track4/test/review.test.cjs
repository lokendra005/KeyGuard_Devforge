"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const C = require("../crypto.cjs");
const S = require("../service.cjs");
const { Store, verifyEvidence } = require("../store.cjs");
const M = require("../messaging.cjs");
const { fixture } = require("./helpers.cjs");

test("worker scenarios reset atomically; expected errors use JSON exit zero and omit SQLite noise", (t) => {
  const f = fixture(t);
  const entry = path.resolve(__dirname, "../../track4_service.cjs");
  const call = (request) => {
    const p = spawnSync(process.execPath, [entry], {
      env: { ...process.env, TRACK4_STATE_DIR: f.directory },
      input: JSON.stringify(request),
      encoding: "utf8",
    });
    A.equal(p.status, 0, p.stderr);
    A.equal(p.stderr, "");
    return C.parse(p.stdout);
  };
  const actor = C.random(),
    asset = C.random(),
    body = C.random();
  A.equal(
    call({
      op: "setup",
      owners: { [asset]: actor },
      contents: { [asset]: body },
      key_material: C.random(),
    }).ready,
    true,
  );
  A.equal(
    call({ op: "read", actor, asset, request_id: C.random() }).body,
    body,
  );
  A.equal(
    call({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }).decision,
    "deny",
  );
  A.ok(
    call({
      op: "setup",
      owners: { broken: actor },
      contents: {},
      key_material: C.random(),
    }).error,
  );
  A.equal(
    call({ op: "read", actor, asset, request_id: C.random() }).body,
    body,
  );
  A.equal(call({ op: "revoke", actor: C.random() }).error, "NOT_FOUND");
  A.equal(call({ op: "audit", request_id: C.random() }).error, "NOT_FOUND");
  f.tick(Date.now() - f.now() + 100);
  A.throws(
    () => f.trusted({ op: "setup" }),
    (e) => e.code === "AUTHORITY_CHANGED",
  );
  const reopened = new Store({ directory: f.directory });
  try {
    A.throws(
      () => S.execute(reopened, { op: "setup" }, { trusted: true }),
      (e) => e.code === "ALREADY_INITIALIZED",
    );
  } finally {
    reopened.close();
  }
});

test("forged requests cannot consume audit capacity; revocation and raising budget work at the soft limit", (t) => {
  const f = fixture(t, { policy: { max_events: 2 } });
  for (let i = 0; i < 75; i++) {
    const request = f.envelope("owner", { op: "status" });
    request.signature = C.sign(f.keys.peer.private_key, "KIG/command/v1", {
      junk: i,
    });
    A.throws(() => S.execute(f.store, request));
  }
  A.equal(f.store.evidence().events.length, 1);
  A.equal(f.store.get("denial_counters")[0].count, 75);
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: C.random(),
  });
  A.equal(
    f.call("admin", { op: "revoke", actor: f.actors.owner }).revoked,
    true,
  );
  A.equal(f.store.evidence().events.at(-1).payload.action, "revoke");
  f.call("admin", { op: "policy.budget", max_events: 2000000 });
  A.equal(
    f.trusted({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }).decision,
    "deny",
  );
});

test("status verifies only the signed suffix after its cached checkpoint; full exported history still verifies", (t) => {
  const f = fixture(t);
  const first = f.trusted({ op: "status" }).checkpoint;
  f.trusted({ op: "revoke", actor: f.actors.peer });
  const suffix = f.store.evidence(first);
  A.equal(suffix.events.length, 1);
  A.throws(
    () => verifyEvidence(suffix, f.store.audit.public_key),
    (e) => e.code === "UNTRUSTED_PREFIX",
  );
  const last = f.trusted({ op: "status" }).checkpoint;
  A.deepEqual(
    last,
    verifyEvidence(f.store.evidence(), f.store.audit.public_key),
  );
  A.deepEqual(last, verifyEvidence(suffix, first.public_key, first));
});

test("temporary wall-clock jumps do not poison an already running authority's monotonic time", (t) => {
  const f = fixture(t);
  f.store.close();
  let wall = f.now() + 10,
    mono = 0;
  const store = new Store({
    directory: f.directory,
    wallClock: () => wall,
    monotonic: () => mono,
  });
  try {
    S.execute(store, { op: "status" }, { trusted: true });
    wall += 3600000;
    mono += 10;
    S.execute(store, { op: "status" }, { trusted: true });
    wall -= 3600000;
    mono += 10;
    S.execute(
      store,
      { op: "revoke", actor: f.actors.owner },
      { trusted: true },
    );
    A.ok(store.get("last_time") < wall + 100);
  } finally {
    store.close();
  }
});

test("protected-read replay storage expires at a documented finite window", (t) => {
  const f = fixture(t);
  const pair = C.c.generateKeyPairSync("ml-kem-768");
  const public_key = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(C.KEM_SPKI.length)
    .toString("base64");
  const request = {
    op: "protected_read",
    actor: f.actors.owner,
    asset: f.asset,
    public_key,
    challenge: C.random(),
  };
  f.trusted(request);
  A.throws(
    () => f.trusted(request),
    (e) => e.code === "REPLAY",
  );
  f.tick(120001);
  f.trusted({ ...request, challenge: C.random() });
  A.equal(f.store.db.prepare("SELECT count(*) AS n FROM nonces").get().n, 1);
});

test("per-recipient offer quotas leave capacity for other actors", (t) => {
  const f = fixture(t, { policy: { max_mail: 10, max_mail_per_actor: 2 } });
  const receiver = new M.Receiver(
    f.keys.peer,
    f.actors.peer,
    { actor: f.actors.owner, public_key: f.keys.owner.public_key },
    f.store.get("authority"),
    { clock: f.now },
  );
  t.after(() => receiver.close());
  for (let i = 0; i < 2; i++)
    f.call("peer", { op: "mail.offer", offer: receiver.offer() });
  A.throws(
    () => f.call("peer", { op: "mail.offer", offer: receiver.offer() }),
    (e) => e.code === "ACTOR_MAILBOX_CAPACITY",
  );
  const other = new M.Receiver(
    f.keys.admin,
    f.actors.admin,
    { actor: f.actors.owner, public_key: f.keys.owner.public_key },
    f.store.get("authority"),
    { clock: f.now },
  );
  t.after(() => other.close());
  A.equal(
    f.call("admin", { op: "mail.offer", offer: other.offer() }).published,
    true,
  );
});

test("partial transfers survive receiver rotation during grace and fail exactly at cutoff", (t) => {
  const f = fixture(t, { policy: { max_mail_per_actor: 1 } });
  const receiver = new M.Receiver(
    f.keys.peer,
    f.actors.peer,
    { actor: f.actors.owner, public_key: f.keys.owner.public_key },
    f.store.get("authority"),
    { clock: f.now },
  );
  t.after(() => receiver.close());
  const offer = receiver.offer();
  f.call("peer", { op: "mail.offer", offer });
  const bytes = C.c.randomBytes(20000);
  const frames = M.encrypt(
    f.keys.owner,
    f.actors.owner,
    { actor: f.actors.peer, public_key: f.keys.peer.public_key },
    offer,
    bytes,
    f.now(),
  );
  f.call("owner", { op: "mail.deliver", frames: frames.slice(0, 1) });
  const key = C.generate();
  const proposal = {
    authority: f.store.get("authority"),
    actor: f.actors.peer,
    epoch: 1,
    new_public_key: key.public_key,
    grace_ms: 1000,
  };
  f.call("peer", {
    op: "rotate",
    new_public_key: key.public_key,
    grace_ms: 1000,
    proof: C.sign(key.private_key, "KIG/rotate/v1", proposal),
  });
  f.tick(999);
  A.equal(
    f.call("owner", { op: "mail.deliver", frames: frames.slice(1) }).queued,
    2,
  );
  let result;
  for (const frame of f.call("peer", { op: "mail.poll" }).messages[0])
    result = receiver.receive(frame);
  A.deepEqual(result.body, bytes);
  f.tick(1);
  A.throws(
    () => f.call("owner", { op: "mail.deliver", frames }),
    (e) => e.code === "UNAUTHORIZED_PEER",
  );
  A.deepEqual(f.call("peer", { op: "mail.poll" }, key).messages, []);
  const replacement = new M.Receiver(
    key,
    f.actors.peer,
    { actor: f.actors.owner, public_key: f.keys.owner.public_key },
    f.store.get("authority"),
    { clock: f.now },
  );
  t.after(() => replacement.close());
  A.equal(
    f.call("peer", { op: "mail.offer", offer: replacement.offer() }, key)
      .published,
    true,
  );
});

test("signed ingestion persists and evaluates more than ten thousand real observations", (t) => {
  const f = fixture(t);
  const D = require("../detect.cjs"),
    data = require("./detector-benchmark.cjs").generate(7182921, 501);
  const report = f.call("admin", {
    op: "detector.ingest",
    events: data.events,
    approvals: data.approvals,
    config: { ...data.config, baseline: D.learn(data.reference) },
  });
  A.equal(report.counts.events, 10020);
  A.equal(f.trusted({ op: "status" }).detection.counts.events, 10020);
});

test("SQLite notice filtering preserves unrelated runtime warnings", () => {
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      'require("./track4/store.cjs"); process.emitWarning("preserve-this-diagnostic", "Warning");',
    ],
    { cwd: path.resolve(__dirname, "../.."), encoding: "utf8" },
  );
  A.equal(result.status, 0);
  A.match(result.stderr, /preserve-this-diagnostic/);
  A.doesNotMatch(result.stderr, /SQLite is an experimental feature/);
});
