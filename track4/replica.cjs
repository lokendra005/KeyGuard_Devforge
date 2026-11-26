"use strict";
const fs = require("node:fs");
const path = require("node:path");
const C = require("./crypto.cjs");
const {
  DatabaseSync,
  directory,
  writeExclusive,
  verifyEvidence,
} = require("./store.cjs");
const { verifyCommand } = require("./auth.cjs");

class Replica {
  constructor(options) {
    this.trust = C.object(options.trust);
    C.text(this.trust.authority);
    C.keyID(this.trust.public_key);
    this.node = C.text(options.node, 256);
    this.monotonic = options.monotonic || (() => performance.now());
    this.leaseMS = C.integer(options.lease_ms ?? 5000, 100, 60000);
    this.deadline = -Infinity;
    this.lastMono = this.monotonic();
    this.dir = directory(path.join(options.directory, "replica-cache"));
    const keyfile = path.join(this.dir, "master.key"),
      dbfile = path.join(this.dir, "replica.sqlite");
    if (!fs.existsSync(keyfile)) {
      C.check(!fs.existsSync(dbfile), "MISSING_MASTER_KEY");
      writeExclusive(keyfile, C.c.randomBytes(32));
    }
    for (const file of [keyfile, dbfile, dbfile + "-wal", dbfile + "-shm"])
      if (fs.existsSync(file)) {
        const stat = fs.lstatSync(file);
        C.check(
          stat.isFile() &&
            !stat.isSymbolicLink() &&
            stat.nlink === 1 &&
            (stat.mode & 0o077) === 0,
          "UNSAFE_STATE_FILE",
        );
      }
    this.master = fs.readFileSync(keyfile);
    C.check(this.master.length === 32, "INVALID_MASTER_KEY");
    const mask = process.umask(0o077);
    try {
      this.db = new DatabaseSync(dbfile);
    } finally {
      process.umask(mask);
    }
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state(id TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS nonces(id TEXT PRIMARY KEY, expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS policy_events(seq INTEGER PRIMARY KEY, body TEXT NOT NULL);",
    );
    const load = (id) => {
      const row = this.db.prepare("SELECT value FROM state WHERE id=?").get(id);
      return (
        row &&
        C.parse(
          C.open(
            this.master,
            JSON.parse(row.value),
            ["replica", this.node, this.trust.authority, id],
            64 * 1024 * 1024,
          ),
          64 * 1024 * 1024,
        )
      );
    };
    this.audit = load("audit") || C.generate();
    this.authTime = load("time") || 0;
    this.persist("audit", this.audit);
    this.ack = load("ack");
    const snapshot = load("snapshot");
    const grant = load("grant");
    if (grant) {
      C.check(
        C.verify(
          this.trust.public_key,
          grant.body.version === 1
            ? "KIG/replica-grant/v1"
            : "KIG/replica-grant/v2",
          grant.body,
          grant.signature,
        ),
        "INVALID_GRANT",
      );
      C.check(
        grant.body.authority === this.trust.authority &&
          grant.body.node_id === this.node &&
          grant.body.node_public_key === this.audit.public_key,
        "WRONG_REPLICA",
      );
      if (grant.body.version === 2) {
        C.check(
          snapshot &&
            C.digest(snapshot.checkpoint) === C.digest(grant.body.checkpoint),
          "INVALID_SNAPSHOT",
        );
        this.grant = grant;
        this.anchor = grant.body.checkpoint;
        for (const name of ["actors", "keys", "files"])
          this[name] = new Map(snapshot[name].map((r) => [r.id, r]));
      } else {
        // v1 caches need a full audience-bound snapshot; local read evidence and keys are retained.
        this.db.exec("DELETE FROM policy_events");
        this.ack = undefined;
      }
    }
    // Persisted snapshots never restore a lease; every process start needs a fresh signed challenge.
  }
  persist(id, value) {
    const packet = C.seal(this.master, Buffer.from(C.canonical(value)), [
      "replica",
      this.node,
      this.trust.authority,
      id,
    ]);
    this.db
      .prepare(
        "INSERT INTO state VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      )
      .run(id, JSON.stringify(packet));
  }
  mono() {
    const now = this.monotonic();
    C.check(
      Number.isFinite(now) && now >= this.lastMono,
      "MONOTONIC_CLOCK_FAILURE",
    );
    this.lastMono = now;
    return now;
  }
  beginSync() {
    C.check(!this.closed, "CLOSED");
    const prefix = this.ack
      ? structuredClone(this.ack)
      : {
          authority: this.trust.authority,
          public_key: this.audit.public_key,
          seq: 0,
          hash: "",
          time_ms: 0,
        };
    const events = this.db
      .prepare("SELECT body FROM events WHERE seq>? ORDER BY seq LIMIT 256")
      .all(prefix.seq)
      .map((r) => JSON.parse(r.body));
    const log = {
      version: 1,
      authority: this.trust.authority,
      public_key: this.audit.public_key,
      prefix,
      events,
    };
    const uploaded = verifyEvidence(log, this.audit.public_key, prefix);
    this.pending = { nonce: C.random(), start: this.mono(), uploaded };
    return {
      op: "replica.sync",
      node_id: this.node,
      nonce: this.pending.nonce,
      node_public_key: this.audit.public_key,
      lease_ms: this.leaseMS,
      read_log: log,
      ...(this.anchor ? { prefix: structuredClone(this.anchor) } : {}),
    };
  }
  install(grant) {
    C.check(!this.closed, "CLOSED");
    grant = structuredClone(grant);
    const body = C.object(grant.body),
      now = this.mono();
    C.check(
      this.pending &&
        body.nonce === this.pending.nonce &&
        body.node_id === this.node &&
        body.authority === this.trust.authority &&
        body.node_public_key === this.audit.public_key &&
        body.version === 2 &&
        Number.isSafeInteger(body.lease_ms) &&
        body.lease_ms >= 100 &&
        body.lease_ms <= this.leaseMS &&
        body.lease_ms <= (body.policy?.max_lease_ms || 5000),
      "WRONG_REPLICA",
    );
    C.check(now < this.pending.start + body.lease_ms, "LEASE_EXPIRED");
    C.check(
      C.verify(
        this.trust.public_key,
        "KIG/replica-grant/v2",
        body,
        grant.signature,
      ),
      "INVALID_GRANT",
    );
    const anchor = verifyEvidence(
      body.evidence,
      this.trust.public_key,
      this.anchor,
    );
    C.check(
      C.digest(anchor) === C.digest(body.checkpoint),
      "INVALID_CHECKPOINT",
    );
    C.integer(body.issued_ms, 0, Number.MAX_SAFE_INTEGER);
    C.check(
      C.digest(body.read_log_ack) === C.digest(this.pending.uploaded),
      "INVALID_LOG_ACK",
    );
    C.check(
      this.anchor
        ? body.mode === "delta" && C.digest(body.base) === C.digest(this.anchor)
        : body.mode === "full" && body.base === null,
      "INVALID_DELTA_BASE",
    );
    const next = {};
    for (const name of ["actors", "keys", "files"]) {
      C.check(Array.isArray(body[name]), "INVALID_SNAPSHOT");
      next[name] = new Map(body.mode === "full" ? [] : this[name]);
      const ids = new Set();
      for (const row of body[name]) {
        C.text(row.id);
        C.check(!ids.has(row.id), "INVALID_SNAPSHOT");
        ids.add(row.id);
        next[name].set(row.id, row);
      }
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const event of body.evidence.events)
        this.db
          .prepare("INSERT INTO policy_events VALUES(?,?)")
          .run(event.seq, JSON.stringify(event));
      this.persist("grant", grant);
      this.persist("snapshot", {
        checkpoint: anchor,
        ...Object.fromEntries(
          Object.entries(next).map(([k, v]) => [k, [...v.values()]]),
        ),
      });
      this.persist("ack", body.read_log_ack);
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
    this.grant = grant;
    this.anchor = anchor;
    this.start = this.pending.start;
    this.deadline = this.start + body.lease_ms;
    this.ack = body.read_log_ack;
    this.pending = undefined;
    Object.assign(this, next);
    C.check(this.mono() < this.deadline, "LEASE_EXPIRED");
    return {
      checkpoint: this.anchor,
      lease_remaining_ms: Math.floor(this.deadline - this.lastMono),
    };
  }
  ready() {
    return !this.closed && this.mono() < this.deadline;
  }
  get(id) {
    return id === "authority" ? this.trust.authority : undefined;
  }
  policy() {
    return this.grant?.body.policy || { request_lifetime_ms: 120000 };
  }
  record(now, actor, action, detail) {
    const row = this.db
      .prepare("SELECT seq,body FROM events ORDER BY seq DESC LIMIT 1")
      .get();
    const seq = row ? row.seq + 1 : 1,
      previous = row ? JSON.parse(row.body).hash : "";
    const payload = {
      authority: this.trust.authority,
      seq,
      time_ms: Math.max(now, row ? JSON.parse(row.body).payload.time_ms : 0),
      node: this.node,
      actor,
      action,
      detail,
    };
    const hash = C.digest(["KIG/audit-chain/v1", previous, payload]);
    this.db.prepare("INSERT INTO events VALUES(?,?)").run(
      seq,
      JSON.stringify({
        seq,
        payload,
        previous,
        hash,
        signature: C.sign(this.audit.private_key, "KIG/audit-event/v1", {
          seq,
          hash,
        }),
      }),
    );
  }
  execute(envelope, options = {}) {
    C.check(this.ready(), "LEASE_EXPIRED");
    const now = Math.max(
      this.authTime,
      Math.floor(this.grant.body.issued_ms + this.lastMono - this.start),
    );
    const auth = verifyCommand(
      envelope,
      {
        authority: this.trust.authority,
        audience: this.node,
        policy: this.policy(),
        actor: this.actors.get(envelope.actor),
        key: this.keys.get(envelope.key_id),
      },
      now,
      options.bootstrap,
    );
    const body = auth.body;
    this.db.exec("BEGIN IMMEDIATE");
    let committed = false;
    try {
      this.db.prepare("DELETE FROM nonces WHERE expires<?").run(now);
      const nonce = C.digest([
        options.bootstrap ? "bootstrap" : "command",
        auth.key_id,
        envelope.nonce,
      ]);
      C.check(
        !this.db.prepare("SELECT id FROM nonces WHERE id=?").get(nonce),
        "REPLAY",
      );
      this.db
        .prepare("INSERT INTO nonces VALUES(?,?)")
        .run(nonce, envelope.expires);
      let result;
      if (body.op === "info") {
        C.check(body.actor === auth.actor, "FORBIDDEN");
        const member = this.actors.get(auth.actor);
        result = {
          version: 2,
          authority: this.trust.authority,
          audience: this.node,
          actor: auth.actor,
          epoch: member.epoch,
          disabled: !!member.disabled,
          role: member.role,
          keys: [...this.keys.values()].filter((k) => k.actor === auth.actor),
          request_lifetime_ms: this.policy().request_lifetime_ms,
          mailbox_lifetime_ms: this.policy().mailbox_lifetime_ms,
          audit_public_key: this.audit.public_key,
        };
      } else if (["read", "protected_read"].includes(body.op)) {
        C.check(body.actor === auth.actor, "FORBIDDEN");
        C.text(body.asset);
        if (body.op === "read") C.text(body.request_id);
        const file = this.files.get(body.asset),
          allow = file && file.owner === auth.actor;
        result = allow
          ? { decision: "allow", body: file.body }
          : { decision: "deny" };
        if (allow && body.op === "protected_read") {
          C.text(body.challenge);
          C.text(body.public_key, 4096);
          const replay = C.digest([
            "protected-read",
            auth.actor,
            body.asset,
            body.challenge,
            body.public_key,
          ]);
          C.check(
            !this.db.prepare("SELECT id FROM nonces WHERE id=?").get(replay),
            "REPLAY",
          );
          this.db
            .prepare("INSERT INTO nonces VALUES(?,?)")
            .run(replay, now + (this.policy().replay_window_ms || 120000));
          result = C.protectedRead(body.public_key, body.challenge, file.body);
        }
        this.record(now, auth.actor, body.op, {
          asset: body.asset,
          decision: allow ? "allow" : "deny",
          policy_checkpoint: this.anchor.seq,
          ...(body.op === "read" ? { request_id: body.request_id } : {}),
        });
      } else if (
        body.op === "evidence" &&
        ["admin", "auditor"].includes(auth.role)
      ) {
        result = {
          version: 1,
          authority: this.trust.authority,
          public_key: this.audit.public_key,
          events: this.db
            .prepare("SELECT body FROM events ORDER BY seq")
            .all()
            .map((r) => JSON.parse(r.body)),
        };
      } else throw new C.Fault("REPLICA_READ_ONLY");
      C.check(this.ready(), "LEASE_EXPIRED");
      this.persist("time", now);
      this.db.exec("COMMIT");
      committed = true;
      this.authTime = now;
      C.check(this.ready(), "LEASE_EXPIRED");
      return result;
    } catch (e) {
      if (!committed) this.db.exec("ROLLBACK");
      throw e;
    }
  }
  close() {
    this.closed = true;
    this.deadline = -Infinity;
    this.db.close();
    this.master.fill(0);
    this.files?.clear();
  }
}
async function replicate(replica, remote, interval = 1000) {
  C.integer(interval, 10, replica.leaseMS);
  let stopped = false,
    timer;
  const sync = async () => {
    try {
      const request = replica.beginSync();
      const grant = await remote.call(request);
      if (!stopped) replica.install(grant);
      replica.lastError = undefined;
    } catch (e) {
      replica.lastError = e.code || "SYNC_FAILED";
    }
    if (!stopped) timer = setTimeout(sync, interval);
  };
  await sync();
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}
module.exports = { Replica, replicate };
