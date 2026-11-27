"use strict";
const C = require("./crypto.cjs");
const { verifyEvidence } = require("./store.cjs");
function bind(store, actor, request) {
  const node = C.text(request.node_id, 256),
    key = request.node_public_key;
  C.check(node.length > 0 && node !== "authority", "INVALID_NODE");
  C.keyID(key);
  const prior = store.db
    .prepare(
      "SELECT * FROM replica_bindings WHERE actor=? OR node_id=? OR node_public_key=?",
    )
    .get(actor, node, key);
  C.check(!prior, "REPLICA_ALREADY_BOUND");
  store.db
    .prepare("INSERT INTO replica_bindings VALUES(?,?,?,NULL)")
    .run(actor, node, key);
}
function sync(store, request, auth, now) {
  C.check(auth.role === "replicator" && !auth.trusted, "FORBIDDEN");
  const db = store.db,
    binding = db
      .prepare("SELECT * FROM replica_bindings WHERE actor=?")
      .get(auth.actor);
  C.check(
    binding &&
      request.node_id === binding.node_id &&
      request.node_public_key === binding.node_public_key,
    "REPLICA_BINDING_MISMATCH",
  );
  // The replicator credential alone is not enough: the bound node key must sign this exact request,
  // with a counter above every counter already accepted for that key (replay of captured requests).
  const { node_proof: proof, ...signed } = request;
  C.check(
    typeof proof === "string" &&
      C.verify(binding.node_public_key, "KIG/replica-sync/v1", signed, proof),
    "REPLICA_PROOF_REQUIRED",
  );
  const counter = C.integer(request.sync_counter, 1, Number.MAX_SAFE_INTEGER),
    counterKey = "replica_sync_counter/" + C.digest(binding.node_public_key);
  C.check(counter > (store.get(counterKey) || 0), "REPLAY");
  store.set(counterKey, counter);
  C.text(request.nonce, 128);
  C.check(request.nonce.length >= 16, "INVALID_NONCE");
  const lease = Math.min(
    C.integer(request.lease_ms, 100, 60000),
    store.policy().max_lease_ms || 5000,
  );
  // Upper bound on when this grant stops authorizing, allowing 1% node clock-rate error (rho).
  store.set(
    "lease_horizon_ms",
    Math.max(store.get("lease_horizon_ms") || 0, now + Math.ceil(lease / 0.99)),
  );
  if (request.prefix) {
    const p = request.prefix,
      row = db
        .prepare("SELECT hash FROM events WHERE seq=?")
        .get(C.integer(p.seq, 1, Number.MAX_SAFE_INTEGER));
    C.check(
      p.authority === store.get("authority") &&
        p.public_key === store.audit.public_key &&
        row &&
        row.hash === p.hash,
      "REPLICA_FORK",
    );
  }
  const log = C.object(request.read_log);
  C.check(
    Array.isArray(log.events) &&
      log.events.length <= 256 &&
      log.authority === store.get("authority"),
    "INVALID_REPLICA_LOG",
  );
  const empty = {
    authority: store.get("authority"),
    public_key: binding.node_public_key,
    seq: 0,
    hash: "",
    time_ms: 0,
  };
  const accepted = binding.cursor ? C.parse(binding.cursor) : empty;
  const prefix = log.prefix || empty;
  C.check(prefix.seq <= accepted.seq, "REPLICA_LOG_GAP");
  if (prefix.seq) {
    const old = db
      .prepare("SELECT body FROM replica_events WHERE node_id=? AND seq=?")
      .get(binding.node_id, prefix.seq);
    C.check(
      old &&
        C.parse(old.body).hash === prefix.hash &&
        C.parse(old.body).payload.time_ms === prefix.time_ms,
      "REPLICA_LOG_FORK",
    );
  } else C.check(C.digest(prefix) === C.digest(empty), "REPLICA_LOG_FORK");
  const uploaded = verifyEvidence(log, binding.node_public_key, prefix);
  for (const event of log.events) {
    const p = event.payload;
    C.text(p.actor);
    if (p.action === "security.alert") {
      C.check(
        p.node === binding.node_id &&
          p.detail.service === binding.node_id &&
          ["revoked_key_use", "disabled_actor_use", "stale_epoch_use", "expired_key_use", "signed_replay"].includes(p.detail.rule),
        "INVALID_REPLICA_LOG",
      );
      C.text(p.detail.reason, 64);
    } else {
      C.check(
        p.node === binding.node_id &&
          ["read", "protected_read"].includes(p.action) &&
          ["allow", "deny"].includes(p.detail.decision),
        "INVALID_REPLICA_LOG",
      );
      C.text(p.detail.asset);
      if (p.action === "read") C.text(p.detail.request_id);
    }
    const old = db
      .prepare("SELECT body FROM replica_events WHERE node_id=? AND seq=?")
      .get(binding.node_id, event.seq);
    C.check(
      !old || C.digest(C.parse(old.body)) === C.digest(event),
      "REPLICA_LOG_FORK",
    );
    db.prepare("INSERT OR IGNORE INTO replica_events VALUES(?,?,?,?)").run(
      binding.node_id,
      event.seq,
      C.canonical(event),
      now,
    );
  }
  const ack = uploaded.seq > accepted.seq ? uploaded : accepted;
  db.prepare("UPDATE replica_bindings SET cursor=? WHERE actor=?").run(
    C.canonical(ack),
    auth.actor,
  );
  const full = !request.prefix;
  function changed(table) {
    return full
      ? db.prepare("SELECT * FROM " + table).all()
      : db
          .prepare(
            `SELECT t.* FROM ${table} t JOIN replication_versions v ON v.id=t.id AND v.kind=? WHERE v.seq>?`,
          )
          .all(table, request.prefix.seq);
  }
  const actors = changed("actors"),
    keys = changed("keys"),
    files = changed("files").map((row) => ({
      id: row.id,
      owner: row.owner,
      version: row.version,
      body: store.file(row),
    }));
  const seq =
    db.prepare("SELECT coalesce(max(seq),0) AS n FROM events").get().n + 1;
  store.record(now, "replica.sync", auth.actor, {
    node_id: binding.node_id,
    files_exported: files.length,
    checkpoint_seq: seq,
    lease_ms: lease,
    mode: full ? "full" : "delta",
    base_seq: request.prefix?.seq || 0,
    node_log: ack,
    received_events: log.events.length,
  });
  const body = {
    version: 2,
    authority: store.get("authority"),
    node_id: binding.node_id,
    node_public_key: binding.node_public_key,
    nonce: request.nonce,
    lease_ms: lease,
    issued_ms: now,
    checkpoint: store.checkpoint(),
    evidence: store.evidence(request.prefix),
    policy: store.policy(),
    mode: full ? "full" : "delta",
    base: request.prefix || null,
    actors,
    keys,
    files,
    read_log_ack: ack,
  };
  return {
    body,
    signature: C.sign(store.audit.private_key, "KIG/replica-grant/v2", body),
  };
}
function audit(store, node, id, auth) {
  const binding = store.db
    .prepare("SELECT * FROM replica_bindings WHERE node_id=?")
    .get(C.text(node, 256));
  C.check(binding, "NOT_FOUND");
  const rows = store.db
    .prepare("SELECT body FROM replica_events WHERE node_id=? ORDER BY seq")
    .all(node);
  const event = rows
    .map((r) => C.parse(r.body))
    .find(
      (e) => e.payload.action === "read" && e.payload.detail.request_id === id,
    );
  C.check(
    event &&
      (auth.trusted ||
        ["admin", "auditor"].includes(auth.role) ||
        event.payload.actor === auth.actor),
    "NOT_FOUND",
  );
  C.check(
    event.hash ===
      C.digest(["KIG/audit-chain/v1", event.previous, event.payload]) &&
      C.verify(
        binding.node_public_key,
        "KIG/audit-event/v1",
        { seq: event.seq, hash: event.hash },
        event.signature,
      ),
    "BROKEN_LOG",
  );
  return {
    request_id: id,
    decision: event.payload.detail.decision,
    node_id: node,
    event,
    public_key: binding.node_public_key,
  };
}
function observations(store) {
  return store.db
    .prepare("SELECT * FROM replica_events ORDER BY received_ms,node_id,seq")
    .all()
    .filter((row) => C.parse(row.body).payload.action !== "security.alert")
    .map((row) => {
      const e = C.parse(row.body),
        p = e.payload;
      return {
        event_id: "replica:" + C.digest([row.node_id, e.seq, e.hash]),
        actor: p.actor,
        source_service: row.node_id,
        target_service: p.detail.asset,
        action: p.action,
        outcome: p.detail.decision,
        event_time_utc: new Date(p.time_ms).toISOString(),
        received_time_utc: new Date(row.received_ms).toISOString(),
      };
    });
}
module.exports = { bind, sync, audit, observations };
