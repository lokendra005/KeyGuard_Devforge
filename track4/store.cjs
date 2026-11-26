"use strict";
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
// Silence only the documented SQLite notice; preserve every other diagnostic.
const emitWarning = process.emitWarning;
let DatabaseSync;
try {
  process.emitWarning = function (message, type, ...args) {
    if (
      type === "ExperimentalWarning" &&
      message ===
        "SQLite is an experimental feature and might change at any time"
    )
      return;
    return emitWarning.call(process, message, type, ...args);
  };
  ({ DatabaseSync } = require("node:sqlite"));
} finally {
  process.emitWarning = emitWarning;
}
const C = require("./crypto.cjs");

const TABLES = [
  "meta",
  "actors",
  "keys",
  "files",
  "events",
  "reads",
  "nonces",
  "recoveries",
  "offers",
  "mail",
  "viewers",
];
const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (id TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actors (id TEXT PRIMARY KEY, role TEXT NOT NULL, disabled INTEGER NOT NULL, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, actor TEXT NOT NULL REFERENCES actors(id), public_key TEXT NOT NULL, not_before INTEGER NOT NULL, not_after INTEGER, revoked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES actors(id), version INTEGER NOT NULL, packet TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reads (id TEXT PRIMARY KEY, actor TEXT NOT NULL, asset TEXT NOT NULL, decision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS recoveries (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS offers (id TEXT PRIMARY KEY, actor TEXT NOT NULL, body TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mail (id TEXT PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL, offer_id TEXT NOT NULL, body TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS viewers (id TEXT PRIMARY KEY, actor TEXT NOT NULL, key_id TEXT NOT NULL, epoch INTEGER NOT NULL, expires INTEGER NOT NULL);
`;
function directory(given) {
  const base = given || process.env.TRACK4_STATE_DIR || os.tmpdir();
  const dir = path.join(path.resolve(base), "keyguard-track4");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  C.check(
    st.isDirectory() &&
      !st.isSymbolicLink() &&
      (st.mode & 0o077) === 0 &&
      (process.getuid === undefined || st.uid === process.getuid()),
    "UNSAFE_STATE_DIRECTORY",
  );
  return dir;
}
function writeExclusive(file, bytes) {
  const fd = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const parent = fs.openSync(path.dirname(file), "r");
  try {
    fs.fsyncSync(parent);
  } finally {
    fs.closeSync(parent);
  }
}
class Store {
  constructor(options = {}) {
    this.dir = directory(options.directory);
    const monotonic = options.monotonic || (() => performance.now());
    this.wallClock = options.wallClock || Date.now;
    const wall = this.wallClock(),
      mono = monotonic();
    this.clock = options.clock || (() => Math.floor(wall + monotonic() - mono));
    this.node = options.node || process.env.KIG_NODE_ID || os.hostname();
    C.text(this.node, 256);
    const dbfile = path.join(this.dir, "authority.sqlite");
    const keyfile = path.join(this.dir, "master.key");
    if (!fs.existsSync(keyfile)) {
      C.check(!fs.existsSync(dbfile), "MISSING_MASTER_KEY");
      const pending = path.join(this.dir, "master-pending-" + C.random());
      writeExclusive(pending, C.c.randomBytes(32));
      try {
        fs.linkSync(pending, keyfile);
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
      } finally {
        fs.unlinkSync(pending);
      }
      const parent = fs.openSync(this.dir, "r");
      try {
        fs.fsyncSync(parent);
      } finally {
        fs.closeSync(parent);
      }
    }
    for (const file of [keyfile, dbfile, dbfile + "-wal", dbfile + "-shm"]) {
      if (!fs.existsSync(file)) continue;
      const s = fs.lstatSync(file);
      C.check(
        s.isFile() &&
          !s.isSymbolicLink() &&
          s.nlink === 1 &&
          (s.mode & 0o077) === 0,
        "UNSAFE_STATE_FILE",
      );
    }
    this.master = fs.readFileSync(keyfile);
    C.check(this.master.length === 32, "INVALID_MASTER_KEY");
    const previousMask = process.umask(0o077);
    try {
      this.db = new DatabaseSync(dbfile);
    } finally {
      process.umask(previousMask);
    }
    // SQLite's Node string boundary can truncate embedded NULs. Encode every bound string losslessly.
    const prepare = this.db.prepare.bind(this.db);
    this.db.prepare = (sql) => {
      const statement = prepare(sql);
      const encode = (value) =>
        typeof value === "string" ? JSON.stringify(value) : value;
      const decode = (row) =>
        row &&
        Object.fromEntries(
          Object.entries(row).map(([key, value]) => [
            key,
            typeof value === "string" && value.startsWith('"')
              ? JSON.parse(value)
              : value,
          ]),
        );
      return {
        run: (...args) => statement.run(...args.map(encode)),
        get: (...args) => decode(statement.get(...args.map(encode))),
        all: (...args) => statement.all(...args.map(encode)).map(decode),
      };
    };
    this.db.exec(
      "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
    );
    this.db.exec(SCHEMA);
    C.check(
      this.get("authority") ||
        this.db.prepare("SELECT count(*) AS n FROM meta").get().n === 0,
      "UNSUPPORTED_STORAGE",
    );
    if (this.get("authority")) {
      C.check(this.get("schema") === 1, "UNSUPPORTED_STORAGE");
      C.check(
        this.get("master_commitment") === C.hash(this.master),
        "WRONG_MASTER_KEY",
      );
      this.audit = C.parse(
        C.open(this.master, this.get("audit_secret"), [
          "audit-key",
          this.get("authority"),
        ]),
      );
      this.loadedAuthority = this.get("authority");
      C.check(
        C.verify(
          this.audit.public_key,
          "KIG/audit-key-check/v1",
          this.get("authority"),
          C.sign(
            this.audit.private_key,
            "KIG/audit-key-check/v1",
            this.get("authority"),
          ),
        ),
        "INVALID_AUDIT_KEY",
      );
      if (options.anchor)
        verifyEvidence(
          this.evidence(),
          options.anchor.public_key,
          options.anchor,
        );
    }
  }
  get(id) {
    const row = this.db.prepare("SELECT value FROM meta WHERE id=?").get(id);
    return row ? C.parse(row.value) : undefined;
  }
  set(id, value) {
    const encoded = C.canonical(value);
    C.check(Buffer.byteLength(encoded) <= 16 * 1024 * 1024, "STATE_CAPACITY");
    this.db
      .prepare(
        "INSERT INTO meta VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      )
      .run(id, encoded);
  }
  transaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    const previous = {
      audit: this.audit,
      authority: this.loadedAuthority,
      checkpoint: this.verifiedCheckpoint,
    };
    try {
      if (this.audit)
        C.check(
          this.loadedAuthority === this.get("authority"),
          "AUTHORITY_CHANGED",
        );
      const now = C.integer(this.clock(), 0, Number.MAX_SAFE_INTEGER);
      C.check(now >= (this.get("last_time") || 0), "CLOCK_REGRESSION");
      const result = fn(now);
      this.set("last_time", now);
      this.db.exec("COMMIT");
      return result;
    } catch (e) {
      this.db.exec("ROLLBACK");
      this.audit = previous.audit;
      this.loadedAuthority = previous.authority;
      this.verifiedCheckpoint = previous.checkpoint;
      throw e;
    }
  }
  record(now, action, actor, detail) {
    const last = this.db
      .prepare("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")
      .get();
    const seq = last ? last.seq + 1 : 1;
    const previous = last ? last.hash : "";
    // The soft budget stops data operations, never revocation/recovery or evidence preservation.
    C.check(
      seq <= this.policy().max_events ||
        [
          "revoke",
          "rotate",
          "recover",
          "role.set",
          "backup",
          "policy.budget",
        ].includes(action),
      "AUDIT_CAPACITY",
    );
    const payload = {
      authority: this.get("authority"),
      seq,
      time_ms: now,
      node: this.node,
      actor,
      action,
      detail,
    };
    const hash = C.digest(["KIG/audit-chain/v1", previous, payload]);
    const signature = C.sign(this.audit.private_key, "KIG/audit-event/v1", {
      seq,
      hash,
    });
    this.db
      .prepare("INSERT INTO events VALUES(?,?,?,?,?)")
      .run(seq, C.canonical(payload), previous, hash, signature);
    return { seq, hash };
  }
  policy() {
    return this.get("policy");
  }
  denial(reason) {
    this.transaction((now) => {
      const minute = Math.floor(now / 60000);
      const buckets = (this.get("denial_counters") || []).filter(
        (b) => b.minute > minute - 60,
      );
      let bucket = buckets.find((b) => b.minute === minute);
      if (!bucket) {
        bucket = { minute, count: 0 };
        buckets.push(bucket);
      }
      bucket.count++;
      this.set("denial_counters", buckets);
    });
  }
  checkpoint() {
    const cached = this.verifiedCheckpoint;
    if (cached) {
      const row = this.db
        .prepare("SELECT hash FROM events WHERE seq=?")
        .get(cached.seq);
      C.check(row && row.hash === cached.hash, "BROKEN_LOG");
    }
    const bundle = this.evidence(cached);
    this.verifiedCheckpoint = verifyEvidence(
      bundle,
      this.audit.public_key,
      cached,
    );
    return this.verifiedCheckpoint;
  }
  file(row) {
    return C.open(this.master, C.parse(row.packet), [
      "file",
      this.get("authority"),
      row.id,
      row.owner,
      row.version,
    ]).toString("utf8");
  }
  putFile(id, owner, body, version) {
    const packet = C.seal(this.master, Buffer.from(body), [
      "file",
      this.get("authority"),
      id,
      owner,
      version,
    ]);
    this.db
      .prepare(
        "INSERT INTO files VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,version=excluded.version,packet=excluded.packet",
      )
      .run(id, owner, version, C.canonical(packet));
  }
  evidence(prefix) {
    return {
      version: 1,
      authority: this.get("authority"),
      public_key: this.audit.public_key,
      ...(prefix ? { prefix } : {}),
      events: this.db
        .prepare("SELECT * FROM events WHERE seq>? ORDER BY seq")
        .all(prefix ? prefix.seq : 0)
        .map((r) => ({ ...r, payload: C.parse(r.payload) })),
    };
  }
  close() {
    this.db.close();
    this.master.fill(0);
    this.audit = undefined;
  }
}
function verifyEvidence(bundle, trustedKey, anchor) {
  C.check(
    bundle.version === 1 &&
      bundle.public_key === trustedKey &&
      Array.isArray(bundle.events),
    "UNTRUSTED_LOG",
  );
  if (bundle.prefix)
    C.check(
      anchor &&
        C.digest(bundle.prefix) === C.digest(anchor) &&
        anchor.public_key === trustedKey &&
        anchor.authority === bundle.authority,
      "UNTRUSTED_PREFIX",
    );
  let previous = bundle.prefix ? anchor.hash : "";
  let seq = bundle.prefix ? anchor.seq : 0;
  let time = bundle.prefix ? anchor.time_ms || 0 : 0;
  for (const event of bundle.events) {
    seq++;
    C.check(
      event.seq === seq &&
        event.payload.seq === seq &&
        event.payload.authority === bundle.authority &&
        event.payload.time_ms >= time &&
        event.previous === previous,
      "BROKEN_LOG",
    );
    const hash = C.digest(["KIG/audit-chain/v1", previous, event.payload]);
    C.check(
      hash === event.hash &&
        C.verify(
          trustedKey,
          "KIG/audit-event/v1",
          { seq, hash },
          event.signature,
        ),
      "BROKEN_LOG",
    );
    if (anchor && seq === anchor.seq)
      C.check(hash === anchor.hash, "FORKED_LOG");
    previous = hash;
    time = event.payload.time_ms;
  }
  if (anchor)
    C.check(
      anchor.authority === bundle.authority &&
        seq >= anchor.seq &&
        anchor.public_key === trustedKey,
      "STALE_LOG",
    );
  return {
    authority: bundle.authority,
    public_key: trustedKey,
    seq,
    hash: previous,
    time_ms: time,
  };
}
module.exports = {
  Store,
  verifyEvidence,
  TABLES,
  writeExclusive,
  directory,
  DatabaseSync,
};
