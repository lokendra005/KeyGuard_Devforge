"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { fork } = require("node:child_process");
const C = require("../crypto.cjs");
const S = require("../service.cjs");
const { Replica } = require("../replica.cjs");
const { fixture } = require("./helpers.cjs");
function options(f, name, extra = {}) {
  return {
    directory: path.join(f.directory, name),
    node: name,
    trust: {
      authority: f.store.get("authority"),
      public_key: f.store.audit.public_key,
    },
    lease_ms: 1000,
    ...extra,
  };
}
function read(f, node = "node-a") {
  f.replicaDetails ||= S.info(f.store, f.actors.owner);
  return S.command(
    f.keys.owner,
    { ...f.replicaDetails, audience: node },
    {
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    },
    f.now(),
  );
}

test("independent replica cache verifies signature, node binding, fresh challenge and chain continuity", (t) => {
  const f = fixture(t);
  let mono = 0;
  const node = new Replica(options(f, "node-a", { monotonic: () => mono }));
  t.after(() => node.close());
  A.throws(
    () => node.execute(read(f, node.node)),
    (e) => e.code === "LEASE_EXPIRED",
  );
  const sync = node.beginSync(),
    grant = f.sync(sync);
  const altered = structuredClone(grant);
  altered.body.files[0].body = "forged";
  A.throws(
    () => node.install(altered),
    (e) => e.code === "INVALID_GRANT",
  );
  node.install(grant);
  const readRequest = read(f, node.node);
  A.equal(node.execute(readRequest).body, f.body);
  A.equal(
    JSON.parse(
      node.db.prepare("SELECT body FROM events ORDER BY seq DESC LIMIT 1").get()
        .body,
    ).payload.detail.request_id,
    readRequest.body.request_id,
  );
  A.throws(
    () => node.install(grant),
    (e) => e.code === "WRONG_REPLICA",
  );
  node.beginSync();
  A.throws(
    () => node.install(grant),
    (e) => e.code === "WRONG_REPLICA",
  );
  const changedNode = new Replica(options(f, "node-b"));
  t.after(() => changedNode.close());
  changedNode.beginSync();
  A.throws(
    () => changedNode.install(grant),
    (e) => e.code === "WRONG_REPLICA",
  );
  const next = f.sync(node.beginSync());
  next.body.evidence.prefix.hash = "0".repeat(96);
  next.signature = C.sign(
    f.store.audit.private_key,
    "KIG/replica-grant/v2",
    next.body,
  );
  A.throws(
    () => node.install(next),
    (e) => e.code === "UNTRUSTED_PREFIX",
  );
});

test("delayed grants cannot extend leases; partitions, monotonic rollback and restart fail closed", (t) => {
  const f = fixture(t);
  let mono = 0;
  const config = options(f, "partitioned", { monotonic: () => mono });
  let node = new Replica(config);
  const grant = f.sync(node.beginSync());
  mono = 1000;
  A.throws(
    () => node.install(grant),
    (e) => e.code === "LEASE_EXPIRED",
  );
  const fresh = f.sync(node.beginSync());
  node.install(fresh);
  const envelope = read(f, node.node);
  A.equal(node.execute(envelope).body, f.body);
  A.throws(
    () => node.execute(envelope),
    (e) => e.code === "REPLAY",
  );
  f.trusted({ op: "revoke", actor: f.actors.owner });
  mono = 1999;
  A.equal(node.execute(read(f, node.node)).body, f.body);
  mono = 2000;
  A.throws(
    () => node.execute(read(f, node.node)),
    (e) => e.code === "LEASE_EXPIRED",
  );
  node.close();
  const bytes = fs.readFileSync(path.join(node.dir, "replica.sqlite"));
  A.equal(bytes.includes(Buffer.from(f.body)), false);
  node = new Replica(config);
  t.after(() => node.close());
  A.throws(
    () => node.execute(read(f, node.node)),
    (e) => e.code === "LEASE_EXPIRED",
  );
  node.install(f.sync(node.beginSync()));
  A.throws(
    () => node.execute(read(f, node.node)),
    (e) => e.code === "UNAUTHORIZED",
  );
  mono--;
  A.throws(
    () => node.beginSync(),
    (e) => e.code === "MONOTONIC_CLOCK_FAILURE",
  );
});

test("replica-role credentials cannot perform administrative mutations", (t) => {
  const f = fixture(t);
  const node = new Replica(options(f, "limited"));
  t.after(() => node.close());
  f.trusted({
    op: "role.set",
    actor: f.actors.peer,
    role: "replicator",
    node_id: node.node,
    node_public_key: node.audit.public_key,
  });
  node.install(f.call("peer", node.beginSync()));
  A.throws(
    () => f.call("peer", { op: "revoke", actor: f.actors.owner }),
    (e) => e.code === "FORBIDDEN",
  );
  A.throws(
    () =>
      node.execute(
        S.command(
          f.keys.admin,
          { ...S.info(f.store, f.actors.admin), audience: node.node },
          { op: "revoke", actor: f.actors.owner },
          f.now(),
        ),
      ),
    (e) => e.code === "REPLICA_READ_ONLY",
  );
});

async function fiveNodeMeasurement(f, t) {
  const lease = 3000,
    workers = [];
  for (let i = 0; i < 5; i++) {
    const child = fork(path.join(__dirname, "replica-worker.cjs"), [], {
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    const pending = new Map();
    let id = 0;
    child.on("message", (m) => {
      const waiter = pending.get(m.id);
      if (waiter) {
        pending.delete(m.id);
        clearTimeout(waiter.timeout);
        waiter.resolve(m);
      }
    });
    const call = (op, value) =>
      new Promise((resolve, reject) => {
        const n = ++id;
        const timeout = setTimeout(() => {
          pending.delete(n);
          reject(new Error("worker timeout"));
        }, 8000);
        pending.set(n, { resolve, timeout });
        child.send({ id: n, op, value });
      });
    const config = options(f, "independent-" + i, { lease_ms: lease });
    A.equal((await call("open", config)).result.ready, true);
    workers.push({ child, call, config });
  }
  t.after(() => {
    for (const w of workers) w.child.kill();
  });
  for (const w of workers) {
    const request = (await w.call("begin")).result;
    A.ok((await w.call("install", f.sync(request))).result);
    A.equal(
      (await w.call("execute", read(f, w.config.node))).result.body,
      f.body,
    );
  }
  f.trusted({ op: "revoke", actor: f.actors.owner });
  const acknowledged = performance.now(),
    latencies = [],
    timers = [];
  const updates = [50, 150, 300].map(
    (delay, i) =>
      new Promise((resolve, reject) => {
        timers.push(
          setTimeout(async () => {
            try {
              const request = (await workers[i].call("begin")).result;
              const response = await workers[i].call(
                "install",
                f.sync(request),
              );
              A.ok(response.result);
              resolve();
            } catch (e) {
              reject(e);
            }
          }, delay),
        );
      }),
  );
  t.after(() => timers.forEach(clearTimeout));
  const observed = new Set();
  while (observed.size < 5) {
    for (let i = 0; i < workers.length; i++) {
      if (observed.has(i)) continue;
      const response = await workers[i].call(
        "execute",
        read(f, workers[i].config.node),
      );
      const elapsed = performance.now() - acknowledged;
      if (response.error) {
        A.ok(
          ["UNAUTHORIZED", "LEASE_EXPIRED"].includes(response.error),
          response.error,
        );
        observed.add(i);
        latencies.push({
          node: i,
          partitioned: i >= 3,
          observed_ms: Math.ceil(elapsed),
          reason: response.error,
        });
      } else {
        A.equal(response.result.body, f.body);
        A.ok(elapsed < lease + 150, "content released after lease bound");
      }
    }
    A.ok(
      performance.now() - acknowledged < lease + 5000,
      "nodes did not fail closed",
    );
    if (observed.size < 5)
      await new Promise((resolve) => setTimeout(resolve, 20));
  }
  await Promise.all(updates);
  const sorted = latencies.map((r) => r.observed_ms).sort((a, b) => a - b);
  return {
    nodes: 5,
    independent_databases: 5,
    lease_ms: lease,
    injected_sync_delays_ms: [50, 150, 300],
    partitions: 2,
    p50_ms: sorted[2],
    max_ms: sorted[4],
    observations: latencies,
    measurement:
      "Single-observer monotonic elapsed time after revocation acknowledgement, 20ms polling; separate OS processes and encrypted caches; sync transport delayed/withheld by harness, not a physical WAN benchmark. Five samples only.",
  };
}
test(
  "five independent processes enforce revocation with delayed sync and two partitions",
  { timeout: 20000 },
  async (t) => {
    const f = fixture(t),
      result = await fiveNodeMeasurement(f, t);
    console.log("REPLICA_MEASUREMENT " + JSON.stringify(result));
  },
);
module.exports = { fiveNodeMeasurement };
