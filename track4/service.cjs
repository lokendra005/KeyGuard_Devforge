"use strict";
const C = require("./crypto.cjs");
const DEFAULT_POLICY = Object.freeze({
  max_files: 10000,
  max_body_bytes: 1048576,
  max_storage_bytes: 16777216,
  max_events: 1000000,
  max_grace_ms: 60000,
  max_lease_ms: 5000,
  request_lifetime_ms: 120000,
  mailbox_lifetime_ms: 300000,
  max_mail: 1000,
  max_mail_per_actor: 32,
  replay_window_ms: 120000,
});
const ROLES = new Set(["user", "auditor", "admin", "recovery", "replicator"]);
// Replicas holding a lease granted before an authorization change may apply the old policy until that
// lease expires. Every revoking change reports when it holds on every node (and when the old key's own
// cutoff ends, for rotation), so callers wait instead of trusting the authority acknowledgement.
function lineage(db, actor) {
  const seen = new Set();
  for (let at = actor, i = 0; i < 256; i++) {
    const row = db.prepare("SELECT enrolled_by FROM enrollments WHERE actor=?").get(at);
    if (!row || seen.has(row.enrolled_by)) break;
    seen.add((at = row.enrolled_by));
  }
  return seen;
}
function everywhere(store, now, floor = now) {
  const at = Math.max(floor, store.get("lease_horizon_ms") || 0, now);
  return { effective_everywhere_at_ms: at, replica_grace_ms: at - now };
}
function isAdmin(auth) {
  return auth.trusted || auth.role === "admin";
}
function requireAdmin(auth) {
  C.check(isAdmin(auth), "FORBIDDEN");
}
function authenticate(store, envelope, now, bootstrap = false) {
  C.object(envelope);
  const auth = require("./auth.cjs").verifyCommand(
    envelope,
    {
      authority: store.get("authority"),
      audience: "authority",
      policy: store.policy(),
      actor: store.db
        .prepare("SELECT * FROM actors WHERE id=?")
        .get(C.text(envelope.actor)),
      key: store.db
        .prepare("SELECT * FROM keys WHERE id=?")
        .get(C.text(envelope.key_id)),
    },
    now,
    bootstrap,
  );
  const request = envelope;
  store.db.prepare("DELETE FROM nonces WHERE expires<?").run(now);
  const nonceID = C.digest([
    bootstrap ? "bootstrap" : "command",
    auth.key_id,
    request.nonce,
  ]);
  if (store.db.prepare("SELECT id FROM nonces WHERE id=?").get(nonceID)) {
    // The signature verified, so the replayed envelope names a real identity worth alerting on.
    const error = new C.Fault("REPLAY");
    Object.assign(error, { verifiedActor: auth.actor, verifiedKey: auth.key_id, rule: "signed_replay" });
    throw error;
  }
  store.db
    .prepare("INSERT INTO nonces VALUES(?,?)")
    .run(nonceID, request.expires);
  return auth;
}
function installKey(store, actor, public_key, now) {
  const id = C.keyID(public_key);
  C.check(
    !store.db.prepare("SELECT id FROM keys WHERE id=?").get(id),
    "KEY_REUSE",
  );
  store.db
    .prepare("INSERT INTO keys VALUES(?,?,?,?,NULL,0)")
    .run(id, actor, public_key, now);
  return id;
}
function setup(store, request, now) {
  C.check(!store.get("authority"), "ALREADY_INITIALIZED");
  C.object(request.owners);
  C.object(request.contents);
  C.check(
    request.disabled === undefined || Array.isArray(request.disabled),
    "INVALID_INPUT",
  );
  C.text(request.key_material, 1048576);
  const policy = { ...DEFAULT_POLICY, ...C.object(request.policy || {}) };
  C.check(
    Object.keys(policy).sort().join(",") ===
      Object.keys(DEFAULT_POLICY).sort().join(","),
    "INVALID_POLICY",
  );
  for (const [key, value] of Object.entries(policy))
    C.integer(
      value,
      key === "max_grace_ms"
        ? 0
        : key === "max_lease_ms"
          ? 100
          : key.endsWith("lifetime_ms")
            ? 1000
            : 1,
      key === "max_events" ? 1000000000 : DEFAULT_POLICY[key],
    );
  const assets = Object.keys(request.contents);
  C.check(
    assets.length <= policy.max_files &&
      Object.keys(request.owners).every((id) =>
        Object.hasOwn(request.contents, id),
      ),
    "INVALID_INPUT",
  );
  const authority = C.random();
  store.set("schema", 2);
  store.set("authority", authority);
  store.loadedAuthority = authority;
  store.set("policy", policy);
  store.set("master_commitment", C.hash(store.master));
  store.audit = C.generate();
  store.set(
    "audit_secret",
    C.seal(store.master, Buffer.from(C.canonical(store.audit)), [
      "audit-key",
      authority,
    ]),
  );
  store.set(
    "synthetic_secret",
    C.seal(store.master, Buffer.from(request.key_material), [
      "setup-secret",
      authority,
    ]),
  );
  const identities = request.identities || [];
  C.check(
    Array.isArray(identities) && identities.length <= policy.max_files,
    "INVALID_INPUT",
  );
  for (const identity of identities) {
    C.text(identity.actor);
    C.check(ROLES.has(identity.role), "INVALID_ROLE");
    C.check(
      !store.db.prepare("SELECT id FROM actors WHERE id=?").get(identity.actor),
      "DUPLICATE_IDENTITY",
    );
    store.db
      .prepare("INSERT INTO actors VALUES(?,?,0,1)")
      .run(identity.actor, identity.role);
    installKey(store, identity.actor, identity.public_key, now);
    if (identity.role === "replicator")
      require("./replication.cjs").bind(store, identity.actor, identity);
  }
  let bytes = 0;
  for (const [asset, body] of Object.entries(request.contents)) {
    const actor = Object.hasOwn(request.owners, asset)
      ? C.text(request.owners[asset])
      : null;
    C.text(asset);
    C.text(body, policy.max_body_bytes);
    bytes += Buffer.byteLength(body);
    if (actor !== null)
      store.db
        .prepare("INSERT OR IGNORE INTO actors VALUES(?,?,0,1)")
        .run(actor, "user");
    store.putFile(asset, actor, body, 1);
  }
  C.check(bytes <= policy.max_storage_bytes, "STORAGE_CAPACITY");
  store.set("plaintext_bytes", bytes);
  for (const actor of request.disabled || []) {
    C.text(actor);
    store.db
      .prepare("INSERT OR IGNORE INTO actors VALUES(?,?,0,1)")
      .run(actor, "user");
    store.db.prepare("UPDATE actors SET disabled=1 WHERE id=?").run(actor);
  }
  store.record(now, "setup", "local-operator", {
    files: assets.length,
    identities: identities.length,
  });
  return { ready: true };
}
function info(store, actor) {
  C.text(actor);
  const row = store.db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
  C.check(row, "NOT_FOUND");
  return {
    version: 2,
    authority: store.get("authority"),
    audience: "authority",
    actor,
    epoch: row.epoch,
    disabled: !!row.disabled,
    role: row.role,
    request_lifetime_ms: store.policy().request_lifetime_ms,
    mailbox_lifetime_ms: store.policy().mailbox_lifetime_ms,
    keys: store.db
      .prepare(
        "SELECT id,public_key,not_before,not_after,revoked FROM keys WHERE actor=?",
      )
      .all(actor),
    audit_public_key: store.audit.public_key,
  };
}
function executeTransaction(store, input, options = {}) {
  C.object(input);
  return store.transaction((now) => {
    let auth;
    if (options.observer) {
      C.text(options.observer, 128);
      const viewer = store.db
        .prepare("SELECT * FROM viewers WHERE id=?")
        .get(C.hash(options.observer));
      const member =
        viewer &&
        store.db.prepare("SELECT * FROM actors WHERE id=?").get(viewer.actor);
      const key =
        viewer &&
        store.db.prepare("SELECT * FROM keys WHERE id=?").get(viewer.key_id);
      C.check(
        viewer &&
          viewer.expires >= now &&
          member &&
          !member.disabled &&
          member.epoch === viewer.epoch &&
          ["admin", "auditor"].includes(member.role) &&
          key &&
          !key.revoked &&
          (key.not_after === null || now < key.not_after),
        "UNAUTHORIZED",
      );
      C.check(["status", "evidence"].includes(input.op), "FORBIDDEN");
      auth = { actor: member.id, role: member.role, body: input };
    } else
      auth = options.trusted
        ? { trusted: true, actor: "local-operator", role: "admin" }
        : authenticate(store, input, now, options.bootstrap);
    const request = options.trusted ? input : auth.body;
    const op = C.text(request.op, 64);
    if (op === "setup") {
      C.check(auth.trusted, "FORBIDDEN");
      if (options.resetScenario) {
        for (const table of [...require("./store.cjs").TABLES].reverse())
          store.db.exec("DELETE FROM " + table);
        store.verifiedCheckpoint = undefined;
      }
      return setup(store, request, now);
    }
    C.check(store.get("authority"), "NOT_INITIALIZED");
    const db = store.db;
    if (op === "replica.sync") {
      return require("./replication.cjs").sync(store, request, auth, now);
    }
    if (op === "replica.bind") {
      requireAdmin(auth);
      const actor = C.text(request.actor),
        member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(
        member && member.role === "replicator" && !member.disabled,
        "FORBIDDEN",
      );
      require("./replication.cjs").bind(store, actor, request);
      store.record(now, op, auth.actor, {
        actor,
        node_id: request.node_id,
        node_public_key: request.node_public_key,
      });
      return { bound: true };
    }
    if (op === "read" || op === "protected_read") {
      const actor = C.text(request.actor);
      const asset = C.text(request.asset);
      C.check(auth.trusted || actor === auth.actor, "FORBIDDEN");
      const member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      const file = db.prepare("SELECT * FROM files WHERE id=?").get(asset);
      const allowed = !!(
        member &&
        !member.disabled &&
        file &&
        file.owner === actor
      );
      const decision = allowed ? "allow" : "deny";
      if (op === "read") {
        const id = C.text(request.request_id);
        const prior = db
          .prepare("SELECT actor,asset FROM reads WHERE id=?")
          .get(id);
        C.check(
          !prior || (prior.actor === actor && prior.asset === asset),
          "REQUEST_ID_CONFLICT",
        );
        const event = store.record(now, op, actor, {
          asset,
          request_id: id,
          decision,
        });
        db.prepare(
          "INSERT INTO reads VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
        ).run(
          id,
          actor,
          asset,
          decision,
          event.seq,
          store.signRead({ id, actor, asset, decision, event_seq: event.seq }),
        );
        return allowed ? { decision, body: store.file(file) } : { decision };
      }
      if (!allowed) {
        store.record(now, op, actor, { asset, decision });
        return { decision };
      }
      C.text(request.challenge);
      C.text(request.public_key, 4096);
      const id = C.digest([
        "protected-read",
        actor,
        asset,
        request.challenge,
        request.public_key,
      ]);
      db.prepare("DELETE FROM nonces WHERE expires<?").run(now);
      C.check(
        !db.prepare("SELECT id FROM nonces WHERE id=?").get(id),
        "REPLAY",
      );
      const result = C.protectedRead(
        request.public_key,
        request.challenge,
        store.file(file),
      );
      db.prepare("INSERT INTO nonces VALUES(?,?)").run(
        id,
        now + (store.policy().replay_window_ms || 120000),
      );
      store.record(now, op, actor, {
        asset,
        decision,
        challenge_commitment: C.digest(request.challenge),
        recipient_key_commitment: C.digest(request.public_key),
      });
      return result;
    }
    if (op === "audit") {
      const id = C.text(request.request_id);
      if (request.node_id !== undefined)
        return require("./replication.cjs").audit(
          store,
          request.node_id,
          id,
          auth,
        );
      const row = db.prepare("SELECT * FROM reads WHERE id=?").get(id);
      C.check(
        row &&
          (auth.trusted ||
            auth.role === "admin" ||
            auth.role === "auditor" ||
            row.actor === auth.actor),
        "NOT_FOUND",
      );
      const event = store.verifyRead(row);
      C.check(
        event.action === "read" &&
          event.actor === row.actor &&
          event.detail.asset === row.asset &&
          event.detail.request_id === row.id &&
          event.detail.decision === row.decision,
        "READ_AUDIT_MISMATCH",
      );
      return { request_id: row.id, decision: row.decision };
    }
    if (op === "revoke") {
      requireAdmin(auth);
      const actor = C.text(request.actor);
      const row = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(row, "NOT_FOUND");
      // A signed command cannot remove the last admin; the trusted local operator still can (lost admin device).
      if (!auth.trusted && row.role === "admin" && !row.disabled)
        C.check(
          db.prepare("SELECT count(*) AS n FROM actors WHERE role=? AND disabled=0").get("admin").n > 1,
          "LAST_ADMIN",
        );
      db.prepare(
        "UPDATE actors SET disabled=1,epoch=epoch+1 WHERE id=? AND disabled=0",
      ).run(actor);
      db.prepare("UPDATE keys SET revoked=1 WHERE actor=?").run(actor);
      db.prepare("DELETE FROM offers WHERE actor=?").run(actor);
      db.prepare("DELETE FROM mail WHERE sender=? OR recipient=?").run(
        actor,
        actor,
      );
      store.record(now, op, auth.actor, { target: actor });
      return { revoked: true, effective_at_ms: now, ...everywhere(store, now) };
    }
    if (op === "put") {
      const actor = C.text(request.actor);
      const asset = C.text(request.asset);
      C.text(request.body, store.policy().max_body_bytes);
      C.check(auth.trusted || actor === auth.actor, "FORBIDDEN");
      const member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(member && !member.disabled, "UNAUTHORIZED");
      const file = db.prepare("SELECT * FROM files WHERE id=?").get(asset);
      C.integer(request.version, 0, Number.MAX_SAFE_INTEGER - 1);
      C.check(
        file
          ? file.owner === actor && file.version === request.version
          : request.version === 0,
        "CONFLICT",
      );
      if (!file)
        C.check(
          db.prepare("SELECT count(*) AS n FROM files").get().n <
            store.policy().max_files,
          "CAPACITY",
        );
      const version = request.version + 1;
      const oldBytes = file ? Buffer.byteLength(store.file(file)) : 0;
      const total =
        (store.get("plaintext_bytes") ??
          db
            .prepare("SELECT * FROM files")
            .all()
            .reduce((n, r) => n + Buffer.byteLength(store.file(r)), 0)) -
        oldBytes +
        Buffer.byteLength(request.body);
      C.check(total <= store.policy().max_storage_bytes, "STORAGE_CAPACITY");
      store.putFile(asset, actor, request.body, version);
      store.set("plaintext_bytes", total);
      store.record(now, op, actor, { asset, version });
      return { version };
    }
    if (op === "enroll") {
      requireAdmin(auth);
      const actor = C.text(request.actor);
      C.check(ROLES.has(request.role), "INVALID_ROLE");
      C.check(
        !db.prepare("SELECT id FROM actors WHERE id=?").get(actor),
        "ALREADY_ENROLLED",
      );
      C.check(
        C.verify(
          request.public_key,
          "KIG/enroll/v1",
          {
            authority: store.get("authority"),
            actor,
            role: request.role,
            ...(request.role === "replicator"
              ? {
                  node_id: request.node_id,
                  node_public_key: request.node_public_key,
                }
              : {}),
          },
          request.proof,
        ),
        "INVALID_PROOF",
      );
      db.prepare("INSERT INTO actors VALUES(?,?,0,1)").run(actor, request.role);
      // Enrollment lineage lets recovery refuse two custodians created by one admin chain.
      if (!auth.trusted)
        db.prepare("INSERT INTO enrollments VALUES(?,?)").run(actor, auth.actor);
      const key_id = installKey(store, actor, request.public_key, now);
      if (request.role === "replicator")
        require("./replication.cjs").bind(store, actor, request);
      store.record(now, op, auth.actor, {
        target: actor,
        role: request.role,
        key_id,
      });
      return { key_id, epoch: 1 };
    }
    if (op === "role.set") {
      requireAdmin(auth);
      const actor = C.text(request.actor);
      C.check(ROLES.has(request.role), "INVALID_ROLE");
      const member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(member, "NOT_FOUND");
      if (
        member.role === "admin" &&
        request.role !== "admin" &&
        !member.disabled
      )
        C.check(
          db
            .prepare(
              "SELECT count(*) AS n FROM actors WHERE role=? AND disabled=0",
            )
            .get("admin").n > 1,
          "LAST_ADMIN",
        );
      if (request.role === "replicator" && member.role !== "replicator")
        require("./replication.cjs").bind(store, actor, request);
      db.prepare("UPDATE actors SET role=?,epoch=epoch+1 WHERE id=?").run(
        request.role,
        actor,
      );
      store.record(now, op, auth.actor, {
        target: actor,
        before: member.role,
        after: request.role,
        epoch: member.epoch + 1,
      });
      return { epoch: member.epoch + 1, ...everywhere(store, now) };
    }
    if (op === "file.transfer") {
      const asset = C.text(request.asset);
      const recipient = C.text(request.recipient);
      C.integer(request.version, 1, Number.MAX_SAFE_INTEGER - 1);
      const file = db.prepare("SELECT * FROM files WHERE id=?").get(asset);
      const target = db
        .prepare("SELECT * FROM actors WHERE id=?")
        .get(recipient);
      C.check(
        file && (isAdmin(auth) || file.owner === auth.actor),
        "FORBIDDEN",
      );
      C.check(
        file.version === request.version && target && !target.disabled,
        "CONFLICT",
      );
      store.putFile(asset, recipient, store.file(file), file.version + 1);
      store.record(now, op, auth.actor, {
        asset,
        previous_owner: file.owner,
        owner: recipient,
        version: file.version + 1,
      });
      return { version: file.version + 1, ...everywhere(store, now) };
    }
    if (op === "rotate") {
      const actor = auth.trusted ? C.text(request.actor) : auth.actor;
      const member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(member && !member.disabled, "UNAUTHORIZED");
      const grace = C.integer(request.grace_ms, 0, store.policy().max_grace_ms);
      const proof = {
        authority: store.get("authority"),
        actor,
        epoch: member.epoch,
        new_public_key: request.new_public_key,
        grace_ms: grace,
      };
      C.check(
        C.verify(request.new_public_key, "KIG/rotate/v1", proof, request.proof),
        "INVALID_PROOF",
      );
      const cutoff = now + grace;
      db.prepare(
        "UPDATE keys SET not_after=CASE WHEN not_after IS NULL OR not_after>? THEN ? ELSE not_after END WHERE actor=? AND revoked=0",
      ).run(cutoff, cutoff, actor);
      const key_id = installKey(store, actor, request.new_public_key, now);
      db.prepare("UPDATE actors SET epoch=epoch+1 WHERE id=?").run(actor);
      store.record(now, op, actor, {
        key_id,
        cutoff_ms: cutoff,
        epoch: member.epoch + 1,
      });
      return {
        key_id,
        cutoff_ms: cutoff,
        epoch: member.epoch + 1,
        ...everywhere(store, now, cutoff),
      };
    }
    if (op === "recover") {
      C.check(
        !auth.trusted && (auth.role === "recovery" || auth.role === "admin"),
        "FORBIDDEN",
      );
      const actor = C.text(request.actor);
      C.check(actor !== auth.actor, "SELF_RECOVERY");
      const member = db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
      C.check(member, "NOT_FOUND");
      C.text(request.recovery_id, 128);
      C.integer(request.expires, now, now + store.policy().request_lifetime_ms);
      const proposal = {
        authority: store.get("authority"),
        actor,
        epoch: C.integer(request.epoch, 1, Number.MAX_SAFE_INTEGER),
        recovery_id: request.recovery_id,
        expires: request.expires,
        new_public_key: request.new_public_key,
      };
      C.check(proposal.epoch === member.epoch, "STALE_EPOCH");
      C.check(
        C.verify(
          request.new_public_key,
          "KIG/recover/v1",
          proposal,
          request.proof,
        ),
        "INVALID_PROOF",
      );
      const old = db
        .prepare("SELECT body FROM recoveries WHERE id=?")
        .get(request.recovery_id);
      const rec = old
        ? C.parse(old.body)
        : { proposal, approvals: [], complete: false };
      C.check(
        !rec.complete && C.digest(rec.proposal) === C.digest(proposal),
        "RECOVERY_CONFLICT",
      );
      C.check(
        !rec.approvals.some((a) => a.actor === auth.actor),
        "DUPLICATE_APPROVER",
      );
      for (const approval of rec.approvals) {
        const a = db
          .prepare("SELECT * FROM actors WHERE id=?")
          .get(approval.actor);
        const k = db
          .prepare("SELECT * FROM keys WHERE id=?")
          .get(approval.key_id);
        C.check(
          a &&
            !a.disabled &&
            a.epoch === approval.epoch &&
            ["admin", "recovery"].includes(a.role) &&
            k &&
            !k.revoked &&
            (k.not_after === null || now < k.not_after),
          "STALE_APPROVER",
        );
      }
      rec.approvals.push({
        actor: auth.actor,
        key_id: auth.key_id,
        epoch: db.prepare("SELECT epoch FROM actors WHERE id=?").get(auth.actor)
          .epoch,
      });
      if (rec.approvals.length === 2) {
        // Two-person control: neither custodian may be enrolled (directly or through a chain) by the
        // other, nor share an enrolling ancestor, so one admin cannot mint a puppet second approver.
        const [x, y] = rec.approvals.map((a) => a.actor);
        const lineX = lineage(db, x),
          lineY = lineage(db, y);
        C.check(
          !lineX.has(y) && !lineY.has(x) && ![...lineX].some((a) => lineY.has(a)),
          "CUSTODIANS_NOT_INDEPENDENT",
        );
        db.prepare("UPDATE keys SET revoked=1 WHERE actor=?").run(actor);
        const key_id = installKey(store, actor, request.new_public_key, now);
        db.prepare("UPDATE actors SET disabled=0,epoch=epoch+1 WHERE id=?").run(
          actor,
        );
        db.prepare("DELETE FROM offers WHERE actor=?").run(actor);
        db.prepare("DELETE FROM mail WHERE sender=? OR recipient=?").run(
          actor,
          actor,
        );
        rec.complete = true;
        rec.key_id = key_id;
      }
      db.prepare(
        "INSERT INTO recoveries VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
      ).run(request.recovery_id, C.canonical(rec));
      store.record(now, op, auth.actor, {
        target: actor,
        recovery_id: request.recovery_id,
        complete: rec.complete,
        proposal_commitment: C.digest(proposal),
      });
      return {
        complete: rec.complete,
        approvals: rec.approvals.length,
        ...(rec.complete ? everywhere(store, now) : {}),
      };
    }
    if (op === "info") {
      C.check(
        auth.trusted ||
          request.actor === auth.actor ||
          auth.role === "admin" ||
          auth.role === "auditor" ||
          auth.role === "recovery",
        "FORBIDDEN",
      );
      return info(store, request.actor);
    }
    if (op === "dashboard.open") {
      C.check(
        !auth.trusted && ["admin", "auditor"].includes(auth.role),
        "FORBIDDEN",
      );
      db.prepare("DELETE FROM viewers WHERE expires<?").run(now);
      C.check(
        db.prepare("SELECT count(*) AS n FROM viewers").get().n < 1000,
        "SESSION_CAPACITY",
      );
      const token = C.random();
      const expires = now + 600000;
      const epoch = db
        .prepare("SELECT epoch FROM actors WHERE id=?")
        .get(auth.actor).epoch;
      db.prepare("INSERT INTO viewers VALUES(?,?,?,?,?)").run(
        C.hash(token),
        auth.actor,
        auth.key_id,
        epoch,
        expires,
      );
      store.record(now, op, auth.actor, { expires });
      return { token, expires };
    }
    if (op === "evidence") {
      C.check(
        auth.trusted || auth.role === "admin" || auth.role === "auditor",
        "FORBIDDEN",
      );
      return store.evidence(request.prefix);
    }
    if (op === "policy.budget") {
      requireAdmin(auth);
      const limit = C.integer(request.max_events, 1, 1000000000);
      C.check(limit >= store.policy().max_events, "BUDGET_DECREASE");
      store.set("policy", { ...store.policy(), max_events: limit });
      store.record(now, op, auth.actor, { max_events: limit });
      return { max_events: limit };
    }
    if (op === "status") {
      C.check(
        auth.trusted || auth.role === "admin" || auth.role === "auditor",
        "FORBIDDEN",
      );
      return {
        authority: store.get("authority"),
        node: store.node,
        policy: store.policy(),
        actors: db.prepare("SELECT * FROM actors ORDER BY id").all(),
        files: db
          .prepare("SELECT id,owner,version FROM files ORDER BY id")
          .all(),
        keys: db
          .prepare(
            "SELECT id,actor,not_before,not_after,revoked FROM keys ORDER BY actor",
          )
          .all(),
        events: db
          .prepare("SELECT payload FROM events ORDER BY seq DESC LIMIT 100")
          .all()
          .map((r) => C.parse(r.payload)),
        checkpoint: store.checkpoint(),
        denial_counters: store.get("denial_counters") || [],
        security_alerts: db
          .prepare(
            "SELECT payload FROM events WHERE json_extract(json_extract(payload,'$'),'$.action')='security.alert' ORDER BY seq DESC LIMIT 100",
          )
          .all()
          .map((r) => {
            const e = C.parse(r.payload);
            return { rule: e.detail.rule, identity: e.actor, key_id: e.detail.key_id, services: [e.detail.service], events: [e.seq], reason: e.detail.reason, op: e.detail.op, time_ms: e.time_ms };
          })
          .concat(
            // Alerts raised on replica nodes arrive via replica.sync uploads (their own signed chains).
            db
              .prepare(
                "SELECT node_id,body FROM replica_events WHERE json_extract(json_extract(body,'$'),'$.payload.action')='security.alert' ORDER BY received_ms DESC LIMIT 100",
              )
              .all()
              .map((r) => {
                const e = C.parse(r.body), p = e.payload;
                return { rule: p.detail.rule, identity: p.actor, key_id: p.detail.key_id, services: [r.node_id], events: [r.node_id + ":" + e.seq], reason: p.detail.reason, op: p.detail.op, time_ms: p.time_ms };
              }),
          )
          .sort((a, b) => b.time_ms - a.time_ms)
          .slice(0, 100),
        security_alert_counters: store.get("security_alert_counters") || {},
        detection: store.get("detection") || null,
      };
    }
    if (op === "detector.ingest") {
      requireAdmin(auth);
      C.check(Array.isArray(request.events), "INVALID_EVENTS");
      const prior = store.get("detector_events") || [];
      const config = request.config || store.get("detector_config");
      const replicaEvents =
        request.include_replica_reads === false
          ? []
          : require("./replication.cjs")
              .observations(store)
              .filter(
                (e) =>
                  !config?.baseline ||
                  Date.parse(e.event_time_utc) >
                    config.baseline.reference_end_ms,
              );
      const events = require("./detect.cjs").unique([
        ...prior,
        ...request.events,
        ...replicaEvents,
      ]);
      const approvals = request.approvals || store.get("detector_approvals");
      const report = require("./detect.cjs").detect(events, approvals, config);
      store.set("detector_events", events);
      store.set("detector_config", config);
      store.set("detector_approvals", approvals);
      store.set("detection", report);
      store.record(now, op, auth.actor, {
        events: events.length,
        alerts: report.alerts.length,
        config_commitment: C.digest(config),
        approvals_commitment: C.digest(approvals),
      });
      return report;
    }
    if (op.startsWith("mail."))
      return require("./messaging.cjs").relay(store, request, auth, now);
    throw new C.Fault("UNSUPPORTED_OPERATION");
  });
}
function execute(store, input, options = {}) {
  try {
    return executeTransaction(store, input, options);
  } catch (error) {
    if (!options.trusted && store.audit && error instanceof C.Fault) {
      try {
        store.denial(error.code);
      } catch {
        /* A failed authority never releases content; the original failure remains visible. */
      }
      if (error.verifiedActor && error.rule)
        try {
          securityAlert(store, input, error);
        } catch {
          /* Alerting is best effort; the original rejection stands. */
        }
    }
    throw error;
  }
}
const ALERTS_PER_ACTOR_MINUTE = 20;
// Self-detection: a command whose signature verified but was then rejected (revoked/expired key, disabled
// actor, stale epoch, replay) means a real key is in someone's hands. Record it in the signed audit chain
// in its own transaction (the command's transaction already rolled back). At most 20 alerts per actor per
// minute reach the chain; the rest only bump a per-actor counter, so a stolen key cannot flood the log.
// Response on revoked_key_use: drop that actor's dashboard viewer tokens and pending mail offers.
function securityAlert(store, input, error) {
  store.transaction((now) => {
    const minute = Math.floor(now / 60000),
      actor = error.verifiedActor;
    const counters = store.get("security_alert_counters") || {};
    const c = counters[actor]?.minute === minute ? counters[actor] : { minute, recorded: 0, suppressed: 0 };
    counters[actor] = c;
    if (c.recorded >= ALERTS_PER_ACTOR_MINUTE) c.suppressed++;
    else {
      c.recorded++;
      store.record(now, "security.alert", actor, {
        rule: error.rule,
        key_id: error.verifiedKey || null,
        service: "authority",
        op: typeof input?.body?.op === "string" ? input.body.op.slice(0, 64) : null,
        reason: error.code,
      });
    }
    store.set("security_alert_counters", counters);
    if (error.rule === "revoked_key_use") {
      store.db.prepare("DELETE FROM viewers WHERE actor=?").run(actor);
      store.db.prepare("DELETE FROM offers WHERE actor=?").run(actor);
    }
  });
}
function command(identity, details, body, now = Date.now()) {
  const request = {
    version: 2,
    authority: details.authority,
    audience: details.audience || "authority",
    actor: details.actor,
    key_id: C.keyID(identity.public_key),
    epoch: details.epoch,
    nonce: C.random(),
    expires: now + Math.min(60000, details.request_lifetime_ms),
    body,
  };
  return {
    ...request,
    signature: C.sign(identity.private_key, "KIG/command/v2", request),
  };
}
module.exports = { execute, info, command, DEFAULT_POLICY };
