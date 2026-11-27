"use strict";
const { test } = require("node:test"),
  A = require("node:assert/strict"),
  path = require("node:path");
const C = require("../crypto.cjs"),
  S = require("../service.cjs"),
  { Store, verifyEvidence } = require("../store.cjs"),
  { Replica } = require("../replica.cjs"),
  { fixture } = require("./helpers.cjs");
const fails = (fn, code) => A.throws(fn, (e) => e.code === code);
function node(f, t, id = "edge") {
  const r = new Replica({
    directory: path.join(f.directory, id),
    node: id,
    trust: {
      authority: f.store.get("authority"),
      public_key: f.store.audit.public_key,
    },
  });
  t.after(() => r.close());
  return r;
}
function read(f, r, id = C.random()) {
  return S.command(
    f.keys.owner,
    { ...S.info(f.store, f.actors.owner), audience: r.node },
    { op: "read", actor: f.actors.owner, asset: f.asset, request_id: id },
    f.now(),
  );
}
test("v2 signed audiences prevent authority/node and cross-node replay, including bootstrap", (t) => {
  const f = fixture(t),
    a = node(f, t, "a"),
    b = node(f, t, "b");
  a.install(f.sync(a.beginSync()));
  b.install(f.sync(b.beginSync()));
  const envelope = read(f, a);
  A.equal(a.execute(envelope).body, f.body);
  fails(() => b.execute(envelope), "WRONG_AUDIENCE");
  fails(() => S.execute(f.store, envelope), "WRONG_AUDIENCE");
  const forged = { ...envelope, audience: b.node };
  fails(() => b.execute(forged), "INVALID_SIGNATURE");
  const old = { ...envelope, version: 1 };
  fails(() => a.execute(old), "WRONG_AUTHORITY");
  const missing = { ...envelope };
  delete missing.audience;
  fails(() => a.execute(missing), "INVALID_ENVELOPE");
  const bootstrap = S.command(
    f.keys.owner,
    { ...S.info(f.store, f.actors.owner), epoch: 0, audience: a.node },
    { op: "info", actor: f.actors.owner },
    f.now(),
  );
  const { signature, ...body } = bootstrap;
  bootstrap.signature = C.sign(
    f.keys.owner.private_key,
    "KIG/identity-bootstrap/v2",
    body,
  );
  A.equal(a.execute(bootstrap, { bootstrap: true }).actor, f.actors.owner);
  fails(() => b.execute(bootstrap, { bootstrap: true }), "WRONG_AUDIENCE");
});
test("replication requires an enrolled node/key binding, caps leases and audits each plaintext export", (t) => {
  const f = fixture(t),
    a = node(f, t),
    req = a.beginSync();
  fails(() => f.call("admin", req), "FORBIDDEN");
  fails(() => f.trusted(req), "FORBIDDEN");
  const credential = f.registerReplica(req),
    call = (body) =>
      S.execute(
        f.store,
        S.command(
          credential.identity,
          S.info(f.store, credential.actor),
          body,
          f.now(),
        ),
      );
  fails(() => call({ ...req, node_id: "other" }), "REPLICA_BINDING_MISMATCH");
  fails(
    () => call({ ...req, node_public_key: C.generate().public_key }),
    "REPLICA_BINDING_MISMATCH",
  );
  a.leaseMS = 60000;
  const grant = call(a.beginSync());
  A.equal(grant.body.lease_ms, 5000);
  a.install(grant);
  const event = f.store.verifyEvent(grant.body.checkpoint.seq);
  A.equal(event.action, "replica.sync");
  A.equal(event.detail.files_exported, 2);
  A.equal(event.detail.node_id, a.node);
  A.equal(event.detail.lease_ms, 5000);
  A.equal(event.detail.checkpoint_seq, grant.body.checkpoint.seq);
  fails(
    () =>
      f.trusted({
        op: "replica.bind",
        actor: credential.actor,
        node_id: "different",
        node_public_key: a.audit.public_key,
      }),
    "REPLICA_ALREADY_BOUND",
  );
});
test("delta sync sends only changed records, imports signed read logs exactly once, and survives a lost response", (t) => {
  const f = fixture(t),
    a = node(f, t),
    b = node(f, t, "other");
  a.install(f.sync(a.beginSync()));
  b.install(f.sync(b.beginSync()));
  const id = C.random();
  A.equal(a.execute(read(f, a, id)).decision, "allow");
  const request = a.beginSync(),
    lost = f.sync(request);
  A.equal(lost.body.mode, "delta");
  A.equal(lost.body.files.length, 0);
  const grant = f.sync(a.beginSync());
  a.install(grant);
  A.equal(
    f.store.db.prepare("SELECT count(*) n FROM replica_events").get().n,
    1,
  );
  A.equal(
    f.trusted({ op: "audit", node_id: a.node, request_id: id }).decision,
    "allow",
  );
  const report = f.trusted({
    op: "detector.ingest",
    events: [],
    approvals: { changes: [] },
    config: { allowed_edges: [] },
  });
  A.equal(report.events.length, 1);
  A.equal(report.events[0].event.actor, f.actors.owner);
  const clean = f.sync(a.beginSync());
  A.equal(clean.body.read_log_ack.seq, 1);
  A.equal(clean.body.actors.length, 0);
  A.equal(clean.body.keys.length, 0);
  A.equal(clean.body.files.length, 0);
  a.install(clean);
  f.call("owner", {
    op: "put",
    actor: f.actors.owner,
    asset: f.asset,
    body: "updated",
    version: 1,
  });
  const update = f.sync(a.beginSync());
  A.equal(update.body.files.length, 1);
  A.equal(update.body.files[0].body, "updated");
  a.install(update);
  A.equal(a.execute(read(f, a)).body, "updated");
  f.trusted({ op: "revoke", actor: f.actors.owner });
  const rev = f.sync(a.beginSync());
  A.equal(rev.body.actors.length, 1);
  A.equal(rev.body.keys.length, 1);
  A.equal(rev.body.files.length, 0);
  a.install(rev);
  fails(() => a.execute(read(f, a)), "UNAUTHORIZED");
});
test("node log forgery, key substitution, gaps and conflicting replays cannot commit or renew a lease", (t) => {
  const f = fixture(t),
    a = node(f, t);
  // These cases model a holder of the node key, so each altered request is re-signed.
  const resign = (req) => {
    const { node_proof, ...body } = req;
    return { ...body, node_proof: C.sign(a.audit.private_key, "KIG/replica-sync/v1", body) };
  };
  a.install(f.sync(a.beginSync()));
  a.execute(read(f, a));
  let req = a.beginSync();
  req.read_log.events[0].payload.detail.decision = "deny";
  fails(() => f.sync(req), "REPLICA_PROOF_REQUIRED");
  fails(() => f.sync(resign(req)), "BROKEN_LOG");
  A.equal(
    f.store.db.prepare("SELECT count(*) n FROM replica_events").get().n,
    0,
  );
  const good = f.sync(a.beginSync());
  a.install(good);
  req = a.beginSync();
  req.read_log.prefix.seq = 999;
  fails(() => f.sync(resign(req)), "REPLICA_LOG_GAP");
  a.execute(read(f, a));
  req = a.beginSync();
  req.read_log.events[0].payload.node = "other";
  const e = req.read_log.events[0];
  e.hash = C.digest(["KIG/audit-chain/v1", e.previous, e.payload]);
  e.signature = C.sign(a.audit.private_key, "KIG/audit-event/v1", {
    seq: e.seq,
    hash: e.hash,
  });
  fails(() => f.sync(resign(req)), "INVALID_REPLICA_LOG");
  A.equal(
    f.store.db.prepare("SELECT count(*) n FROM replica_events").get().n,
    1,
  );
});
test("unowned UTF-8 assets deny all readers, and plaintext storage budgets are exact", (t) => {
  const f = fixture(t, {
    owners: { owned: "person" },
    contents: { owned: "ab", orphan: "🙂" },
    policy: { max_storage_bytes: 6 },
  });
  A.equal(f.store.get("plaintext_bytes"), 6);
  A.equal(
    f.store.db.prepare("SELECT owner FROM files WHERE id=?").get("orphan")
      .owner,
    null,
  );
  for (const actor of ["person", "", "null", f.actors.admin])
    A.equal(
      f.trusted({ op: "read", actor, asset: "orphan", request_id: C.random() })
        .decision,
      "deny",
    );
  fails(
    () =>
      f.trusted({
        op: "put",
        actor: "person",
        asset: "owned",
        version: 1,
        body: "abc",
      }),
    "STORAGE_CAPACITY",
  );
  A.equal(f.store.get("plaintext_bytes"), 6);
  f.trusted({
    op: "put",
    actor: "person",
    asset: "owned",
    version: 1,
    body: "",
  });
  A.equal(f.store.get("plaintext_bytes"), 4);
});
test("read index changes, replacement with a later event, and damaged signed payloads fail closed", (t) => {
  const f = fixture(t),
    id = C.random();
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: id,
  });
  const original = f.store.db.prepare("SELECT * FROM reads WHERE id=?").get(id);
  f.store.db.prepare("UPDATE reads SET decision=? WHERE id=?").run("deny", id);
  fails(
    () => f.trusted({ op: "audit", request_id: id }),
    "READ_AUDIT_MISMATCH",
  );
  f.store.db
    .prepare("UPDATE reads SET decision=? WHERE id=?")
    .run(original.decision, id);
  f.trusted({ op: "revoke", actor: f.actors.owner });
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: id,
  });
  const seq = f.store.db.prepare("SELECT max(seq) n FROM events").get().n;
  f.store.db
    .prepare("UPDATE reads SET decision=?,event_seq=? WHERE id=?")
    .run("deny", seq, id);
  fails(
    () => f.trusted({ op: "audit", request_id: id }),
    "READ_AUDIT_MISMATCH",
  );
  f.store.db
    .prepare("UPDATE reads SET decision=?,event_seq=? WHERE id=?")
    .run(original.decision, original.event_seq, id);
  f.store.db
    .prepare("UPDATE events SET payload=? WHERE seq=?")
    .run("{}", original.event_seq);
  fails(() => f.trusted({ op: "audit", request_id: id }), "BROKEN_LOG");
});
test("signed persisted checkpoints verify only the suffix on cold start and reject signature/truncation attacks", (t) => {
  const f = fixture(t);
  for (let i = 0; i < 30; i++)
    f.trusted({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    });
  const anchor = f.store.checkpoint();
  A.equal(f.store.get("verified_checkpoint").body.seq, anchor.seq);
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: C.random(),
  });
  const verify = C.verify;
  let calls = 0;
  C.verify = (...args) => {
    calls++;
    return verify(...args);
  };
  let cold;
  try {
    cold = new Store({ directory: f.directory, clock: f.now });
    A.equal(cold.checkpoint().seq, anchor.seq + 1);
    A.ok(calls < 10);
  } finally {
    C.verify = verify;
    cold?.close();
  }
  const saved = f.store.get("verified_checkpoint");
  saved.body.hash = "a".repeat(96);
  f.store.set("verified_checkpoint", saved);
  fails(
    () => new Store({ directory: f.directory, clock: f.now }),
    "INVALID_CHECKPOINT",
  );
});

test("replica restart retains the merged delta state and uploaded-log cursor but never restores a lease", (t) => {
  const f = fixture(t),
    config = {
      directory: path.join(f.directory, "restart"),
      node: "restart",
      trust: {
        authority: f.store.get("authority"),
        public_key: f.store.audit.public_key,
      },
    };
  let a = new Replica(config);
  a.install(f.sync(a.beginSync()));
  a.execute(read(f, a));
  a.install(f.sync(a.beginSync()));
  f.call("owner", {
    op: "put",
    actor: f.actors.owner,
    asset: f.asset,
    body: "delta survives restart",
    version: 1,
  });
  a.install(f.sync(a.beginSync()));
  a.close();
  a = new Replica(config);
  t.after(() => a.close());
  fails(() => a.execute(read(f, a)), "LEASE_EXPIRED");
  const request = a.beginSync();
  A.equal(request.read_log.prefix.seq, 1);
  A.equal(request.read_log.events.length, 0);
  const grant = f.sync(request);
  A.equal(grant.body.files.length, 0);
  a.install(grant);
  A.equal(a.execute(read(f, a)).body, "delta survives restart");
});
test("old authority tables upgrade without replacing keys, file ciphertext or signed history", (t) => {
  const f = fixture(t),
    id = C.random();
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: id,
  });
  const key = f.store.audit.public_key,
    events = C.digest(f.store.evidence()),
    packet = f.store.db
      .prepare("SELECT packet FROM files WHERE id=?")
      .get(f.asset).packet;
  // Recreate precisely the old read/file schema; snapshots are disposable fixtures.
  f.store.db.exec(
    "ALTER TABLE reads RENAME TO old_reads; CREATE TABLE reads (id TEXT PRIMARY KEY,actor TEXT NOT NULL,asset TEXT NOT NULL,decision TEXT NOT NULL); INSERT INTO reads SELECT id,actor,asset,decision FROM old_reads; DROP TABLE old_reads;",
  );
  f.store.set("schema", 1);
  const fresh = new Store({ directory: f.directory, clock: f.now });
  t.after(() => fresh.close());
  A.equal(fresh.audit.public_key, key);
  const preserved = fresh.evidence();
  A.equal(preserved.events.pop().payload.action, "protocol.upgrade");
  A.equal(C.digest(preserved), events);
  A.equal(fresh.get("schema"), 2);
  A.equal(
    fresh.db.prepare("SELECT packet FROM files WHERE id=?").get(f.asset).packet,
    packet,
  );
  A.equal(
    S.execute(fresh, { op: "audit", request_id: id }, { trusted: true })
      .decision,
    "allow",
  );
  A.equal(
    fresh.file(fresh.db.prepare("SELECT * FROM files WHERE id=?").get(f.asset)),
    f.body,
  );
});

test("independent millisecond clock anchors merge forward without weakening explicit rollback checks", (t) => {
  const f = fixture(t),
    last = f.store.get("last_time");
  const peer = new Store({
    directory: f.directory,
    wallClock: () => last - 1,
    monotonic: () => 0,
  });
  t.after(() => peer.close());
  A.equal(
    S.execute(
      peer,
      {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      },
      { trusted: true },
    ).decision,
    "allow",
  );
  A.equal(peer.get("last_time"), last);
  const old = new Store({
    directory: f.directory,
    wallClock: () => last - 10,
    monotonic: () => 0,
  });
  t.after(() => old.close());
  fails(
    () => S.execute(old, { op: "status" }, { trusted: true }),
    "CLOCK_REGRESSION",
  );
  const exact = new Store({ directory: f.directory, clock: () => last - 1 });
  t.after(() => exact.close());
  fails(
    () => S.execute(exact, { op: "status" }, { trusted: true }),
    "CLOCK_REGRESSION",
  );
});
test("a stolen replicator credential without the node private key cannot export, and captured sync requests cannot be replayed", (t) => {
  const f = fixture(t),
    a = node(f, t);
  const first = a.beginSync();
  a.install(f.sync(first));
  const { node_proof, ...unsigned } = a.beginSync();
  // Public values only: bound node id and public key, no node signature.
  fails(() => f.sync(unsigned), "REPLICA_PROOF_REQUIRED");
  fails(
    () => f.sync({ ...unsigned, node_proof: C.sign(C.generate().private_key, "KIG/replica-sync/v1", unsigned) }),
    "REPLICA_PROOF_REQUIRED",
  );
  // Re-wrapping a captured, validly signed request in a fresh replicator envelope is a replay.
  fails(() => f.sync(first), "REPLAY");
});
test("revoke reports when it holds on every replica, including outstanding leases", (t) => {
  const f = fixture(t),
    a = node(f, t);
  const solo = f.trusted({ op: "revoke", actor: f.actors.peer });
  A.equal(solo.replica_grace_ms, 0);
  A.equal(solo.effective_everywhere_at_ms, solo.effective_at_ms);
  const grant = f.sync(a.beginSync());
  a.install(grant);
  const result = f.trusted({ op: "revoke", actor: f.actors.owner });
  A.ok(result.replica_grace_ms >= grant.body.lease_ms);
  A.ok(result.replica_grace_ms <= Math.ceil(grant.body.lease_ms / 0.99));
  A.equal(result.effective_everywhere_at_ms, result.effective_at_ms + result.replica_grace_ms);
});
