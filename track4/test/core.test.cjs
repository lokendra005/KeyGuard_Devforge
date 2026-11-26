"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync, spawn } = require("node:child_process");
const C = require("../crypto.cjs");
const S = require("../service.cjs");
const { Store, verifyEvidence } = require("../store.cjs");
const B = require("../backup.cjs");
const { fixture } = require("./helpers.cjs");
const fails = (fn, code) => A.throws(fn, (e) => e.code === code);

test("owner policy, opaque IDs, denial audit and at-rest secrecy share real storage", (t) => {
  const f = fixture(t);
  const id = "constructor\0🙂";
  A.equal(
    f.call("owner", {
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: id,
    }).body,
    f.body,
  );
  A.equal(f.call("owner", { op: "audit", request_id: id }).request_id, id);
  A.deepEqual(
    f.call("peer", {
      op: "read",
      actor: f.actors.peer,
      asset: f.asset,
      request_id: "deny",
    }),
    { decision: "deny" },
  );
  A.equal(f.call("peer", { op: "audit", request_id: "deny" }).decision, "deny");
  fails(
    () => f.call("owner", { op: "audit", request_id: "deny" }),
    "NOT_FOUND",
  );
  fails(
    () =>
      f.call("peer", {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: "impersonate",
      }),
    "FORBIDDEN",
  );
  fails(
    () =>
      f.trusted({
        op: "read",
        actor: f.actors.owner,
        asset: f.other,
        request_id: id,
      }),
    "REQUEST_ID_CONFLICT",
  );
  f.store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  for (const name of fs.readdirSync(f.store.dir)) {
    const bytes = fs.readFileSync(path.join(f.store.dir, name));
    A.equal(bytes.includes(Buffer.from(f.body)), false);
    A.equal(bytes.includes(Buffer.from(f.secret)), false);
  }
});

test("retrying a read correlation ID rechecks policy and preserves both historical decisions", (t) => {
  const f = fixture(t);
  const request = {
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: C.random(),
  };
  A.equal(f.trusted(request).body, f.body);
  f.trusted({ op: "revoke", actor: f.actors.owner });
  A.deepEqual(f.trusted(request), { decision: "deny" });
  A.equal(
    f.trusted({ op: "audit", request_id: request.request_id }).decision,
    "deny",
  );
  const events = f.store
    .evidence()
    .events.filter((e) => e.payload.detail.request_id === request.request_id);
  A.deepEqual(
    events.map((e) => e.payload.detail.decision),
    ["allow", "deny"],
  );
});

test("ML-KEM protected read binds exact challenge/body; invalid keys and replays fail closed", (t) => {
  const f = fixture(t);
  const pair = C.c.generateKeyPairSync("ml-kem-768");
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(C.KEM_SPKI.length)
    .toString("base64");
  const request = {
    op: "protected_read",
    actor: f.actors.owner,
    asset: f.asset,
    challenge: "挑战-" + C.random(),
    public_key: raw,
  };
  const result = f.trusted(request);
  const shared = C.c.decapsulate(
    pair.privateKey,
    C.b64(result.ciphertext, 1088),
  );
  A.equal(
    result.proof,
    C.c
      .createHmac("sha256", shared)
      .update(request.challenge + f.body)
      .digest("hex"),
  );
  A.notEqual(
    result.proof,
    C.c
      .createHmac("sha256", shared)
      .update(request.challenge + "\0" + f.body)
      .digest("hex"),
  );
  shared.fill(0);
  fails(() => f.trusted(request), "REPLAY");
  fails(
    () =>
      f.trusted({ ...request, challenge: C.random(), public_key: raw + "\n" }),
    "INVALID_KEY",
  );
  fails(
    () =>
      f.trusted({
        ...request,
        challenge: C.random(),
        public_key: Buffer.alloc(1184, 255).toString("base64"),
      }),
    "INVALID_KEY",
  );
  f.trusted({ op: "revoke", actor: f.actors.owner });
  A.deepEqual(f.trusted({ ...request, public_key: "not-a-key" }), {
    decision: "deny",
  });
});

test("signed commands reject substitution, replay, wrong authority, stale epochs and expired requests", (t) => {
  const f = fixture(t);
  const body = {
    op: "put",
    actor: f.actors.owner,
    asset: f.asset,
    version: 1,
    body: "next",
  };
  const request = f.envelope("owner", body);
  const altered = structuredClone(request);
  altered.body.body = "attacker";
  fails(() => S.execute(f.store, altered), "INVALID_SIGNATURE");
  const wrong = structuredClone(request);
  wrong.authority = C.random();
  fails(() => S.execute(f.store, wrong), "WRONG_AUTHORITY");
  A.equal(S.execute(f.store, request).version, 2);
  fails(() => S.execute(f.store, request), "REPLAY");
  fails(
    () => f.call("owner", { op: "revoke", actor: f.actors.peer }),
    "FORBIDDEN",
  );
  const expires = f.envelope("owner", { op: "info", actor: f.actors.owner });
  f.tick(60001);
  A.throws(() => S.execute(f.store, expires));
  const token = f.call("admin", { op: "dashboard.open" }).token;
  f.trusted({ op: "revoke", actor: f.actors.admin });
  fails(
    () => S.execute(f.store, { op: "status" }, { observer: token }),
    "UNAUTHORIZED",
  );
});

test("rotation has a precise cutoff, preserves content and rejects prior-epoch authorization", (t) => {
  const f = fixture(t);
  const next = C.generate();
  const before = f.envelope("owner", { op: "info", actor: f.actors.owner });
  const proposal = {
    authority: f.store.get("authority"),
    actor: f.actors.owner,
    epoch: 1,
    new_public_key: next.public_key,
    grace_ms: 1000,
  };
  const rotated = f.call("owner", {
    op: "rotate",
    new_public_key: next.public_key,
    grace_ms: 1000,
    proof: C.sign(next.private_key, "KIG/rotate/v1", proposal),
  });
  A.equal(rotated.epoch, 2);
  fails(() => S.execute(f.store, before), "UNAUTHORIZED");
  A.equal(
    f.call(
      "owner",
      {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      },
      next,
    ).body,
    f.body,
  );
  f.tick(999);
  A.equal(f.call("owner", { op: "info", actor: f.actors.owner }).epoch, 2);
  f.tick(1);
  fails(
    () => f.call("owner", { op: "info", actor: f.actors.owner }),
    "UNAUTHORIZED",
  );
  A.equal(
    f.call("owner", { op: "info", actor: f.actors.owner }, next).epoch,
    2,
  );
  const restart = new Store({ directory: f.directory, clock: f.now });
  t.after(() => restart.close());
  A.equal(S.info(restart, f.actors.owner).epoch, 2);
});

test("two-person recovery fences competing proposals and permanently retires old keys", (t) => {
  const f = fixture(t);
  f.trusted({ op: "revoke", actor: f.actors.owner });
  const keyA = C.generate(),
    keyB = C.generate();
  const proposal = (key) => ({
    authority: f.store.get("authority"),
    actor: f.actors.owner,
    epoch: 2,
    new_public_key: key.public_key,
    recovery_id: C.random(),
    expires: f.now() + 60000,
  });
  const pA = proposal(keyA),
    pB = proposal(keyB);
  const rA = {
      op: "recover",
      ...pA,
      proof: C.sign(keyA.private_key, "KIG/recover/v1", pA),
    },
    rB = {
      op: "recover",
      ...pB,
      proof: C.sign(keyB.private_key, "KIG/recover/v1", pB),
    };
  A.equal(f.call("recoveryA", rA).complete, false);
  fails(() => f.call("recoveryA", rA), "DUPLICATE_APPROVER");
  A.equal(f.call("recoveryA", rB).complete, false);
  A.equal(f.call("recoveryB", rB).complete, true);
  fails(() => f.call("recoveryB", rA), "STALE_EPOCH");
  fails(
    () => f.call("owner", { op: "info", actor: f.actors.owner }),
    "UNAUTHORIZED",
  );
  A.equal(
    f.call(
      "owner",
      {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      },
      keyB,
    ).body,
    f.body,
  );
  A.equal(
    f.call("peer", {
      op: "read",
      actor: f.actors.peer,
      asset: f.other,
      request_id: C.random(),
    }).decision,
    "allow",
  );
});

test("failed persistence rolls back rotation and data, and clocks cannot silently regress", (t) => {
  const f = fixture(t);
  const key = C.generate();
  const proposal = {
    authority: f.store.get("authority"),
    actor: f.actors.owner,
    epoch: 1,
    new_public_key: key.public_key,
    grace_ms: 0,
  };
  f.store.db.exec(
    "CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'injected-disk-failure'); END;",
  );
  A.throws(() =>
    f.call("owner", {
      op: "rotate",
      new_public_key: key.public_key,
      grace_ms: 0,
      proof: C.sign(key.private_key, "KIG/rotate/v1", proposal),
    }),
  );
  A.equal(S.info(f.store, f.actors.owner).epoch, 1);
  A.equal(
    f.store.db
      .prepare("SELECT count(*) AS n FROM keys WHERE actor=?")
      .get(f.actors.owner).n,
    1,
  );
  f.store.db.exec("DROP TRIGGER fail_event");
  f.tick(-1);
  fails(() => f.trusted({ op: "status" }), "CLOCK_REGRESSION");
});

test("signed audit rejects edits, truncation and text injection without conflating records", (t) => {
  const f = fixture(t);
  const hostile = 'x\n{"actor":"admin","action":"allow"}';
  f.trusted({
    op: "read",
    actor: hostile,
    asset: f.asset,
    request_id: hostile,
  });
  const evidence = f.store.evidence();
  const anchor = verifyEvidence(evidence, evidence.public_key);
  A.equal(anchor.seq, 2);
  A.equal(evidence.events[1].payload.actor, hostile);
  const bad = structuredClone(evidence);
  bad.events[1].payload.actor = "admin";
  fails(() => verifyEvidence(bad, evidence.public_key), "BROKEN_LOG");
  const short = structuredClone(evidence);
  short.events.pop();
  fails(() => verifyEvidence(short, evidence.public_key, anchor), "STALE_LOG");
  fails(
    () => verifyEvidence(evidence, C.generate().public_key),
    "UNTRUSTED_LOG",
  );
});

test("encrypted key and authority backups verify corruption, wrong passwords and stale anchors", (t) => {
  const f = fixture(t);
  const password = C.random();
  const identityBackup = B.backupKey(f.keys.owner, password);
  A.equal(
    B.restoreKey(identityBackup, password).public_key,
    f.keys.owner.public_key,
  );
  fails(() => B.restoreKey(identityBackup, C.random()), "INTEGRITY_FAILURE");
  const corrupt = structuredClone(identityBackup);
  const bytes = C.b64(corrupt.packet.body);
  bytes[10] ^= 1;
  corrupt.packet.body = bytes.toString("base64");
  fails(() => B.restoreKey(corrupt, password), "INTEGRITY_FAILURE");
  f.trusted({ op: "revoke", actor: f.actors.owner });
  const saved = B.backupAuthority(f.store, password);
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "kig-restore-test-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const restoredDir = path.join(parent, "restored");
  A.equal(
    B.restoreAuthority(saved.bundle, password, restoredDir, saved.checkpoint)
      .restored,
    true,
  );
  const restored = new Store({ directory: restoredDir });
  t.after(() => restored.close());
  A.deepEqual(
    S.execute(
      restored,
      {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      },
      { trusted: true },
    ),
    { decision: "deny" },
  );
  A.equal(
    S.execute(
      restored,
      {
        op: "read",
        actor: f.actors.peer,
        asset: f.other,
        request_id: C.random(),
      },
      { trusted: true },
    ).decision,
    "allow",
  );
  f.trusted({ op: "revoke", actor: f.actors.peer });
  const latest = verifyEvidence(f.store.evidence(), f.store.audit.public_key);
  fails(
    () =>
      B.restoreAuthority(
        saved.bundle,
        password,
        path.join(parent, "stale"),
        latest,
      ),
    "STALE_LOG",
  );
  A.equal(fs.existsSync(path.join(parent, "stale")), false);
  fails(
    () =>
      B.restoreAuthority(
        saved.bundle,
        password,
        path.join(parent, "unanchored"),
      ),
    "EXTERNAL_ANCHOR_REQUIRED",
  );
});

test("strict JSON rejects duplicate fields, malformed UTF-8, unsafe numbers and deep nesting", () => {
  for (const raw of [
    '{"op":"read","op":"setup"}',
    '{"a":1,"\\u0061":2}',
    '{"a":NaN}',
    '{"a":9007199254740992}',
    '{"a":"\\ud800"}',
    "[1,]",
    '{"a":1,}',
    "{} trailing",
    "[".repeat(40) + "0" + "]".repeat(40),
  ])
    A.throws(() => C.parse(raw));
  A.throws(() => C.parse(Buffer.from([0xff])));
  A.equal(C.parse('{"__proto__":"x"}').__proto__, "x");
  for (let i = 0; i < 1000; i++) {
    const raw = C.c.randomBytes(i % 128);
    try {
      const parsed = C.parse(raw);
      C.canonical(parsed);
    } catch (e) {
      A.ok(e instanceof Error);
    }
  }
});

test("permission changes fence prepared actions and transfer file ownership atomically", (t) => {
  const f = fixture(t);
  const before = f.envelope("recoveryA", {
    op: "info",
    actor: f.actors.recoveryA,
  });
  f.call("admin", { op: "role.set", actor: f.actors.recoveryA, role: "user" });
  fails(() => S.execute(f.store, before), "UNAUTHORIZED");
  fails(
    () =>
      f.call("admin", { op: "role.set", actor: f.actors.admin, role: "user" }),
    "LAST_ADMIN",
  );
  A.equal(
    f.call("owner", {
      op: "file.transfer",
      asset: f.asset,
      recipient: f.actors.peer,
      version: 1,
    }).version,
    2,
  );
  A.equal(
    f.call("owner", {
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }).decision,
    "deny",
  );
  A.equal(
    f.call("peer", {
      op: "read",
      actor: f.actors.peer,
      asset: f.asset,
      request_id: C.random(),
    }).body,
    f.body,
  );
  fails(
    () =>
      f.call("owner", {
        op: "put",
        actor: f.actors.owner,
        asset: f.asset,
        version: 1,
        body: "replace",
      }),
    "CONFLICT",
  );
});

test("noncanonical public-key encodings and missing master keys cannot create new identities silently", (t) => {
  const f = fixture(t);
  const alias = Buffer.concat([
    C.b64(f.keys.owner.public_key),
    Buffer.from([0]),
  ]).toString("base64");
  fails(() => C.keyID(alias), "INVALID_KEY");
  const file = path.join(f.store.dir, "master.key");
  fs.unlinkSync(file);
  fails(() => new Store({ directory: f.directory }), "MISSING_MASTER_KEY");
  A.equal(fs.existsSync(file), false);
});

test("audit and file capacity failures preserve previously acknowledged state", (t) => {
  const f = fixture(t, { policy: { max_events: 2, max_storage_bytes: 1000 } });
  f.trusted({
    op: "read",
    actor: f.actors.owner,
    asset: f.asset,
    request_id: C.random(),
  });
  fails(
    () => f.trusted({ op: "revoke", actor: f.actors.owner }),
    "AUDIT_CAPACITY",
  );
  A.equal(S.info(f.store, f.actors.owner).disabled, false);
  fails(
    () =>
      f.call("owner", {
        op: "put",
        actor: f.actors.owner,
        asset: f.asset,
        version: 1,
        body: "X".repeat(900),
      }),
    "STORAGE_CAPACITY",
  );
  A.equal(
    f.store.file(
      f.store.db.prepare("SELECT * FROM files WHERE id=?").get(f.asset),
    ),
    f.body,
  );
});

test("actual process-per-request adapter persists policy and rejects oversized or malformed input", (t) => {
  const f = fixture(t);
  const entry = path.resolve(__dirname, "../../track4_service.cjs");
  const run = (request) =>
    C.parse(
      execFileSync(process.execPath, [entry], {
        env: { ...process.env, TRACK4_STATE_DIR: f.directory },
        input: JSON.stringify(request),
        stdio: ["pipe", "pipe", "pipe"],
      }),
    );
  A.equal(
    run({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }).body,
    f.body,
  );
  run({ op: "revoke", actor: f.actors.owner });
  A.equal(
    run({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }).decision,
    "deny",
  );
  try {
    execFileSync(process.execPath, [entry], {
      input: '{"op":"read","op":"setup"}',
      stdio: ["pipe", "pipe", "pipe"],
    });
    A.fail("duplicate field accepted");
  } catch (e) {
    A.match(String(e.stdout), /DUPLICATE_FIELD/);
  }
  try {
    execFileSync(process.execPath, [entry], {
      input: Buffer.alloc(16 * 1024 * 1024 + 1, 32),
      stdio: ["pipe", "pipe", "pipe"],
    });
    A.fail("oversized input accepted");
  } catch (e) {
    A.match(String(e.stdout), /INPUT_TOO_LARGE/);
  }
});

test(
  "SIGKILL during rotation recovers the prior committed key and preserved revocation",
  { timeout: 10000 },
  async (t) => {
    const f = fixture(t);
    f.trusted({ op: "revoke", actor: f.actors.peer });
    const replacement = C.generate();
    const proposal = {
      authority: f.store.get("authority"),
      actor: f.actors.owner,
      epoch: 1,
      new_public_key: replacement.public_key,
      grace_ms: 0,
    };
    const request = f.envelope("owner", {
      op: "rotate",
      new_public_key: replacement.public_key,
      grace_ms: 0,
      proof: C.sign(replacement.private_key, "KIG/rotate/v1", proposal),
    });
    const input = path.join(f.directory, "request.json");
    fs.writeFileSync(input, JSON.stringify(request));
    const script = `const fs=require('node:fs'); const {Store}=require(${JSON.stringify(path.resolve(__dirname, "../store.cjs"))}); const {execute}=require(${JSON.stringify(path.resolve(__dirname, "../service.cjs"))}); const s=new Store({directory:process.argv[1]}); s.db.function('pause_for_test',()=>{fs.writeSync(1,'transaction-open'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,30000); return 0;}); s.db.exec('CREATE TEMP TRIGGER interrupt_rotation BEFORE INSERT ON events BEGIN SELECT pause_for_test(); END;'); execute(s,JSON.parse(fs.readFileSync(process.argv[2])));`;
    const child = spawn(process.execPath, ["-e", script, f.directory, input], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    t.after(() => child.kill("SIGKILL"));
    await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) =>
        reject(new Error("child exited before interruption " + code)),
      );
      child.stdout.once("data", () => resolve());
    });
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("close", resolve));
    const restarted = new Store({ directory: f.directory });
    try {
      A.equal(S.info(restarted, f.actors.owner).epoch, 1);
      A.equal(S.info(restarted, f.actors.peer).disabled, true);
      A.equal(
        restarted.file(
          restarted.db.prepare("SELECT * FROM files WHERE id=?").get(f.asset),
        ),
        f.body,
      );
    } finally {
      restarted.close();
    }
  },
);

test("three fresh worker nodes enforce completed revocation with measured observer latency", async (t) => {
  const f = fixture(t);
  const entry = path.resolve(__dirname, "../../track4_service.cjs");
  function invoke(node, request) {
    return new Promise((resolve, reject) => {
      const start = performance.now();
      const child = spawn(process.execPath, [entry], {
        env: {
          ...process.env,
          TRACK4_STATE_DIR: f.directory,
          KIG_NODE_ID: node,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let data = "";
      child.stdout.on("data", (b) => (data += b));
      child.on("error", reject);
      child.on("close", (status) =>
        status === 0
          ? resolve({ result: C.parse(data), start, end: performance.now() })
          : reject(new Error("child failed")),
      );
      child.stdin.end(JSON.stringify(request));
    });
  }
  const nodes = Array.from({ length: 3 }, () => C.random());
  const before = await Promise.all(
    nodes.map((node) =>
      invoke(node, {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      }),
    ),
  );
  A.ok(before.every((r) => r.result.decision === "allow"));
  const revoke = await invoke(nodes[0], {
    op: "revoke",
    actor: f.actors.owner,
  });
  const after = await Promise.all(
    nodes.map((node) =>
      invoke(node, {
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      }),
    ),
  );
  A.ok(after.every((r) => r.result.decision === "deny"));
  t.diagnostic(
    JSON.stringify({
      nodes: nodes.length,
      topology: "fresh local worker processes, one SQLite authority",
      observed_after_ack_ms: Math.ceil(
        Math.max(...after.map((r) => r.end)) - revoke.end,
      ),
      timing:
        "same observer monotonic clock; includes process startup, not geographically distributed propagation",
    }),
  );
});

test("worker temp fallback, empty opaque names and startup schema fences are explicit", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "kig-fallback-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const env = {
    ...process.env,
    TMPDIR: directory,
    TMP: directory,
    TEMP: directory,
  };
  delete env.TRACK4_STATE_DIR;
  const entry = path.resolve(__dirname, "../../track4_service.cjs");
  const run = (request) =>
    JSON.parse(
      execFileSync(process.execPath, [entry], {
        input: JSON.stringify(request),
        env,
        stdio: ["pipe", "pipe", "pipe"],
      }),
    );
  A.equal(
    run({
      op: "setup",
      owners: { "": "" },
      contents: { "": "exact" },
      disabled: [],
      key_material: C.random(),
    }).ready,
    true,
  );
  A.equal(
    run({ op: "read", actor: "", asset: "", request_id: "" }).body,
    "exact",
  );
  A.equal(run({ op: "audit", request_id: "" }).request_id, "");
  const store = new Store({ directory });
  store.set("schema", 99);
  store.close();
  fails(() => new Store({ directory }), "UNSUPPORTED_STORAGE");
});
