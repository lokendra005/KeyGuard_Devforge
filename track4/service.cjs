"use strict";
const C = require("./crypto.cjs");
const DEFAULT_POLICY = Object.freeze({
  max_files: 10000,
  max_body_bytes: 1048576,
  max_storage_bytes: 16777216,
  max_events: 10000,
  max_grace_ms: 60000,
  request_lifetime_ms: 120000,
  mailbox_lifetime_ms: 300000,
  max_mail: 1000,
});
const ROLES = new Set(["user", "auditor", "admin", "recovery"]);
function isAdmin(auth) {
  return auth.trusted || auth.role === "admin";
}
function requireAdmin(auth) {
  C.check(isAdmin(auth), "FORBIDDEN");
}
function authenticate(store, envelope, now) {
  C.object(envelope);
  const { signature, ...request } = envelope;
  C.check(
    Object.keys(request).sort().join(",") ===
      "actor,authority,body,epoch,expires,key_id,nonce,version",
    "INVALID_ENVELOPE",
  );
  C.check(
    request.version === 1 && request.authority === store.get("authority"),
    "WRONG_AUTHORITY",
  );
  C.text(request.actor);
  C.text(request.key_id, 96);
  C.text(request.nonce, 128);
  C.check(request.nonce.length >= 16, "INVALID_NONCE");
  C.integer(request.expires, now, now + store.policy().request_lifetime_ms);
  const actor = store.db
    .prepare("SELECT * FROM actors WHERE id=?")
    .get(request.actor);
  const key = store.db
    .prepare("SELECT * FROM keys WHERE id=?")
    .get(request.key_id);
  C.check(actor && key && key.actor === actor.id, "UNAUTHORIZED");
  C.check(
    C.verify(key.public_key, "KIG/command/v1", request, signature),
    "INVALID_SIGNATURE",
  );
  if (
    actor.disabled ||
    key.revoked ||
    now < key.not_before ||
    (key.not_after !== null && now >= key.not_after) ||
    request.epoch !== actor.epoch
  ) {
    const error = new C.Fault("UNAUTHORIZED");
    error.verifiedActor = actor.id;
    throw error;
  }
  store.db.prepare("DELETE FROM nonces WHERE expires<?").run(now);
  const nonceID = C.digest(["command", key.id, request.nonce]);
  C.check(
    !store.db.prepare("SELECT id FROM nonces WHERE id=?").get(nonceID),
    "REPLAY",
  );
  store.db
    .prepare("INSERT INTO nonces VALUES(?,?)")
    .run(nonceID, request.expires);
  return {
    actor: actor.id,
    role: actor.role,
    key_id: key.id,
    body: C.object(request.body),
    trusted: false,
  };
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
  C.check(Array.isArray(request.disabled), "INVALID_INPUT");
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
      key === "max_grace_ms" ? 0 : key.endsWith("lifetime_ms") ? 1000 : 1,
      DEFAULT_POLICY[key],
    );
  const assets = Object.keys(request.owners);
  C.check(
    assets.length <= policy.max_files &&
      assets.length === Object.keys(request.contents).length &&
      assets.every((id) => Object.hasOwn(request.contents, id)),
    "INVALID_INPUT",
  );
  const authority = C.random();
  store.set("schema", 1);
  store.set("authority", authority);
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
  }
  for (const [asset, actor] of Object.entries(request.owners)) {
    C.text(asset);
    C.text(actor);
    C.text(request.contents[asset], policy.max_body_bytes);
    store.db
      .prepare("INSERT OR IGNORE INTO actors VALUES(?,?,0,1)")
      .run(actor, "user");
    store.putFile(asset, actor, request.contents[asset], 1);
  }
  C.check(
    store.db
      .prepare("SELECT coalesce(sum(length(packet)),0) AS bytes FROM files")
      .get().bytes <= policy.max_storage_bytes,
    "STORAGE_CAPACITY",
  );
  for (const actor of request.disabled) {
    C.text(actor);
    store.db
      .prepare("INSERT OR IGNORE INTO actors VALUES(?,?,0,1)")
      .run(actor, "user");
    store.db.prepare("UPDATE actors SET disabled=1 WHERE id=?").run(actor);
  }
  store.record(now, "setup", "local-operator", {
    files: Object.keys(request.owners).length,
    identities: identities.length,
  });
  return { ready: true };
}
function info(store, actor) {
  C.text(actor);
  const row = store.db.prepare("SELECT * FROM actors WHERE id=?").get(actor);
  C.check(row, "NOT_FOUND");
  return {
    version: 1,
    authority: store.get("authority"),
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
        : authenticate(store, input, now);
    const request = options.trusted ? input : auth.body;
    const op = C.text(request.op, 64);
    if (op === "setup") {
      C.check(auth.trusted, "FORBIDDEN");
      return setup(store, request, now);
    }
    C.check(store.get("authority"), "NOT_INITIALIZED");
    const db = store.db;
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
        db.prepare(
          "INSERT INTO reads VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET decision=excluded.decision",
        ).run(id, actor, asset, decision);
        store.record(now, op, actor, { asset, request_id: id, decision });
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
        Number.MAX_SAFE_INTEGER,
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
      const row = db.prepare("SELECT * FROM reads WHERE id=?").get(id);
      C.check(
        row &&
          (auth.trusted ||
            auth.role === "admin" ||
            auth.role === "auditor" ||
            row.actor === auth.actor),
        "NOT_FOUND",
      );
      return { request_id: row.id, decision: row.decision };
    }
    if (op === "revoke") {
      requireAdmin(auth);
      const actor = C.text(request.actor);
      const row = db.prepare("SELECT id FROM actors WHERE id=?").get(actor);
      C.check(row, "NOT_FOUND");
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
      return { revoked: true, effective_at_ms: now };
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
      store.putFile(asset, actor, request.body, version);
      C.check(
        db
          .prepare("SELECT coalesce(sum(length(packet)),0) AS bytes FROM files")
          .get().bytes <= store.policy().max_storage_bytes,
        "STORAGE_CAPACITY",
      );
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
          { authority: store.get("authority"), actor, role: request.role },
          request.proof,
        ),
        "INVALID_PROOF",
      );
      db.prepare("INSERT INTO actors VALUES(?,?,0,1)").run(actor, request.role);
      const key_id = installKey(store, actor, request.public_key, now);
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
      return { epoch: member.epoch + 1 };
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
      return { version: file.version + 1 };
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
      db.prepare("DELETE FROM offers WHERE actor=?").run(actor);
      store.record(now, op, actor, {
        key_id,
        cutoff_ms: cutoff,
        epoch: member.epoch + 1,
      });
      return { key_id, cutoff_ms: cutoff, epoch: member.epoch + 1 };
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
      return { complete: rec.complete, approvals: rec.approvals.length };
    }
    if (op === "info") {
      C.check(
        auth.trusted ||
          request.actor === auth.actor ||
          auth.role === "admin" ||
          auth.role === "auditor",
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
      return store.evidence();
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
        checkpoint: require("./store.cjs").verifyEvidence(
          store.evidence(),
          store.audit.public_key,
        ),
        detection: store.get("detection") || null,
      };
    }
    if (op === "detector.ingest") {
      requireAdmin(auth);
      C.check(Array.isArray(request.events), "INVALID_EVENTS");
      const prior = store.get("detector_events") || [];
      const byID = new Map(prior.map((e) => [e.event_id, e]));
      for (const event of request.events) {
        const previous = byID.get(event.event_id);
        C.check(
          !previous || C.digest(previous) === C.digest(event),
          "EVENT_ID_CONFLICT",
        );
        byID.set(event.event_id, event);
      }
      const events = [...byID.values()];
      const config = request.config || store.get("detector_config");
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
        store.transaction((now) =>
          store.record(
            now,
            "request.denied",
            error.verifiedActor || "unauthenticated",
            { reason: error.code },
          ),
        );
      } catch {
        /* A failed authority never releases content; the original failure remains visible. */
      }
    }
    throw error;
  }
}
function command(identity, details, body, now = Date.now()) {
  const request = {
    version: 1,
    authority: details.authority,
    actor: details.actor,
    key_id: C.keyID(identity.public_key),
    epoch: details.epoch,
    nonce: C.random(),
    expires: now + Math.min(60000, details.request_lifetime_ms),
    body,
  };
  return {
    ...request,
    signature: C.sign(identity.private_key, "KIG/command/v1", request),
  };
}
module.exports = { execute, info, command, DEFAULT_POLICY };
