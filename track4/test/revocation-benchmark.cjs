"use strict";
// Revocation propagation across five replicas: N independent revocations, each observed on every node.
// Observation = monotonic ms from the authority's revoke ack until the node first rejects a request
// signed by the revoked key with its pre-revocation epoch (the lost-device attacker), 2 ms polling.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const C = require("../crypto.cjs");
const { Store } = require("../store.cjs");
const S = require("../service.cjs");
const { Replica, replicate } = require("../replica.cjs");
const samples = Number(process.argv[2] || 100),
  nodesCount = 5,
  interval = 1000,
  lease = 3000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
(async () => {
  const admin = C.generate();
  const users = Array.from({ length: samples }, (_, i) => ({ actor: "u" + i, key: C.generate() }));
  const store = new Store({ directory: tmp("kig-revbench-") });
  S.execute(
    store,
    {
      op: "setup",
      owners: Object.fromEntries(users.map((u) => ["f-" + u.actor, u.actor])),
      contents: Object.fromEntries(users.map((u) => ["f-" + u.actor, "secret-" + u.actor])),
      disabled: [],
      key_material: C.random(),
      identities: [
        { actor: "root", role: "admin", public_key: admin.public_key },
        ...users.map((u) => ({ actor: u.actor, role: "user", public_key: u.key.public_key })),
      ],
    },
    { trusted: true },
  );
  const trust = { authority: store.get("authority"), public_key: store.audit.public_key };
  const nodes = [],
    stops = [];
  for (let i = 0; i < nodesCount; i++) {
    const node = new Replica({ directory: tmp("kig-revnode-"), node: "node-" + i, trust, lease_ms: lease });
    const id = C.generate(),
      actor = "replicator-" + i,
      binding = { node_id: node.node, node_public_key: node.audit.public_key };
    S.execute(
      store,
      S.command(admin, S.info(store, "root"), {
        op: "enroll",
        actor,
        role: "replicator",
        public_key: id.public_key,
        ...binding,
        proof: C.sign(id.private_key, "KIG/enroll/v1", { authority: trust.authority, actor, role: "replicator", ...binding }),
      }),
    );
    nodes.push(node);
    // Injected transport delay 0-50 ms per sync; real wall-clock timers.
    stops.push(
      await replicate(
        node,
        {
          call: async (r) => {
            await sleep(Math.random() * 50);
            return S.execute(store, S.command(id, S.info(store, actor), r));
          },
        },
        interval,
      ),
    );
  }
  await sleep(interval + 500);
  const observed = [];
  let grace = 0;
  for (const u of users) {
    const old = S.info(store, u.actor);
    const read = (node) =>
      S.command(u.key, { ...old, audience: node.node }, { op: "read", actor: u.actor, asset: "f-" + u.actor, request_id: C.random() });
    for (const node of nodes) C.check(node.execute(read(node)).body === "secret-" + u.actor, "BENCH_PRECONDITION");
    const t0 = performance.now();
    const ack = S.execute(store, { op: "revoke", actor: u.actor }, { trusted: true });
    grace = Math.max(grace, ack.replica_grace_ms);
    const pending = new Set(nodes);
    while (pending.size) {
      for (const node of [...pending]) {
        let served = false;
        try {
          served = node.execute(read(node)).body !== undefined;
        } catch {}
        if (!served) {
          observed.push(performance.now() - t0);
          pending.delete(node);
        }
      }
      await sleep(2);
    }
    await sleep(Math.random() * interval);
  }
  stops.forEach((s) => s());
  nodes.forEach((n) => n.close());
  store.close();
  observed.sort((a, b) => a - b);
  const q = (p) => Math.round(observed[Math.min(observed.length - 1, Math.ceil(p * observed.length) - 1)]);
  process.stdout.write(
    JSON.stringify(
      {
        revocations: samples,
        nodes: nodesCount,
        observations: observed.length,
        sync_interval_ms: interval,
        lease_ms: lease,
        p50_ms: q(0.5),
        p95_ms: q(0.95),
        p99_ms: q(0.99),
        max_ms: Math.round(observed.at(-1)),
        max_reported_replica_grace_ms: grace,
        method:
          "Monotonic ms from authority revoke ack to first rejection, per node, of a request signed with the revoked key and its pre-revocation epoch; 2 ms polling; in-process transport with 0-50 ms injected delay; no partitions (partitioned nodes fail closed at lease expiry, measured separately).",
      },
      null,
      2,
    ) + "\n",
  );
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
