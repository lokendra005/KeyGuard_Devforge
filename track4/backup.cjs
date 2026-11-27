"use strict";
const fs = require("node:fs");
const path = require("node:path");
const C = require("./crypto.cjs");
const {
  Store,
  TABLES,
  verifyEvidence,
  writeExclusive,
} = require("./store.cjs");

function wrap(value, password, kind) {
  C.text(password, 4096);
  C.check(Buffer.byteLength(password) >= 16, "WEAK_BACKUP_PASSWORD");
  const salt = C.c.randomBytes(32);
  const key = C.c.scryptSync(password, salt, 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  const plain = Buffer.from(C.canonical(value));
  C.check(plain.length <= 128 * 1024 * 1024, "BACKUP_CAPACITY");
  try {
    return {
      version: 1,
      kind,
      kdf: "scrypt-N32768-r8-p1",
      salt: salt.toString("base64"),
      packet: C.seal(key, plain, ["KIG/backup/v1", kind]),
    };
  } finally {
    key.fill(0);
    plain.fill(0);
  }
}
function unwrap(bundle, password, kind) {
  C.check(
    bundle.version === 1 &&
      bundle.kind === kind &&
      bundle.kdf === "scrypt-N32768-r8-p1",
    "INVALID_BACKUP",
  );
  C.text(password, 4096);
  const key = C.c.scryptSync(password, C.b64(bundle.salt, 32), 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  let plain;
  try {
    plain = C.open(
      key,
      bundle.packet,
      ["KIG/backup/v1", kind],
      128 * 1024 * 1024,
    );
    return C.parse(plain, 128 * 1024 * 1024);
  } finally {
    key.fill(0);
    if (plain) plain.fill(0);
  }
}
function validateIdentity(identity) {
  C.check(
    C.verify(
      identity.public_key,
      "KIG/backup-key-check/v1",
      identity.public_key,
      C.sign(
        identity.private_key,
        "KIG/backup-key-check/v1",
        identity.public_key,
      ),
    ),
    "INVALID_KEY_BACKUP",
  );
  return identity;
}
function backupKey(identity, password) {
  return wrap(validateIdentity(identity), password, "identity");
}
function restoreKey(bundle, password) {
  return validateIdentity(unwrap(bundle, password, "identity"));
}
function backupAuthority(store, password) {
  return store.transaction((now) => {
    store.record(now, "backup", "local-operator", { kind: "authority" });
    const checkpoint = verifyEvidence(store.evidence(), store.audit.public_key);
    const tables = Object.fromEntries(
      TABLES.map((name) => [
        name,
        store.db.prepare("SELECT * FROM " + name).all(),
      ]),
    );
    const bundle = wrap(
      { version: 1, master_key: store.master.toString("base64"), tables },
      password,
      "authority",
    );
    return { bundle, checkpoint };
  });
}
function restoreAuthority(bundle, password, target, anchor) {
  C.check(
    anchor && anchor.public_key && anchor.seq >= 1,
    "EXTERNAL_ANCHOR_REQUIRED",
  );
  const snapshot = unwrap(bundle, password, "authority");
  C.check(snapshot.version === 1, "INVALID_BACKUP");
  // Backups taken before enrollment lineage existed restore with no recorded lineage (setup trust root).
  if (snapshot.tables && typeof snapshot.tables === "object") snapshot.tables.enrollments ??= [];
  const legacyTables = TABLES.filter(
    (t) =>
      !["replication_versions", "replica_bindings", "replica_events"].includes(
        t,
      ),
  );
  if (
    Object.keys(snapshot.tables).sort().join(",") ===
    legacyTables.sort().join(",")
  ) {
    for (const name of [
      "replication_versions",
      "replica_bindings",
      "replica_events",
    ])
      snapshot.tables[name] = [];
    for (const row of snapshot.tables.reads) {
      row.event_seq ??= null;
      row.signature ??= null;
    }
  }
  C.check(
    Object.keys(snapshot.tables).sort().join(",") ===
      [...TABLES].sort().join(","),
    "INVALID_BACKUP",
  );
  const meta = new Map(
    snapshot.tables.meta.map((row) => [row.id, C.parse(row.value)]),
  );
  C.check(meta.get("last_time") <= Date.now(), "CLOCK_REGRESSION");
  const master = C.b64(snapshot.master_key, 32);
  C.check(C.hash(master) === meta.get("master_commitment"), "INVALID_BACKUP");
  const audit = C.parse(
    C.open(master, meta.get("audit_secret"), [
      "audit-key",
      meta.get("authority"),
    ]),
  );
  validateIdentity(audit);
  const evidence = {
    version: 1,
    authority: meta.get("authority"),
    public_key: audit.public_key,
    events: snapshot.tables.events
      .map((r) => ({ ...r, payload: C.parse(r.payload) }))
      .sort((a, b) => a.seq - b.seq),
  };
  verifyEvidence(evidence, anchor.public_key, anchor);
  for (const row of snapshot.tables.files)
    C.open(master, C.parse(row.packet), [
      "file",
      meta.get("authority"),
      row.id,
      row.owner,
      row.version,
    ]);
  for (const row of snapshot.tables.keys)
    C.check(row.id === C.keyID(row.public_key), "INVALID_BACKUP");
  // Restore into a new directory only; an authenticated old snapshot cannot overwrite a live authority.
  fs.mkdirSync(target, { recursive: false, mode: 0o700 });
  const store = new Store({ directory: target });
  try {
    const temp = path.join(store.dir, "restore-master-" + C.random());
    writeExclusive(temp, master);
    fs.renameSync(temp, path.join(store.dir, "master.key"));
    const dir = fs.openSync(store.dir, "r");
    try {
      fs.fsyncSync(dir);
    } finally {
      fs.closeSync(dir);
    }
    store.master.fill(0);
    store.master = Buffer.from(master);
    store.transaction(() => {
      for (const table of TABLES) {
        const columns = store.db
          .prepare("PRAGMA table_info(" + table + ")")
          .all()
          .map((c) => c.name);
        const insert = store.db.prepare(
          (table === "replication_versions"
            ? "INSERT OR REPLACE INTO "
            : "INSERT INTO ") +
            table +
            " (" +
            columns.join(",") +
            ") VALUES(" +
            columns.map(() => "?").join(",") +
            ")",
        );
        for (const row of snapshot.tables[table]) {
          C.check(
            Object.keys(row).sort().join(",") === [...columns].sort().join(","),
            "INVALID_BACKUP",
          );
          insert.run(...columns.map((col) => row[col]));
        }
      }
    });
    return {
      restored: true,
      authority: evidence.authority,
      checkpoint: verifyEvidence(evidence, anchor.public_key, anchor),
    };
  } finally {
    store.close();
    master.fill(0);
  }
}
module.exports = { backupKey, restoreKey, backupAuthority, restoreAuthority };
