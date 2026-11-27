"use strict";
const { test } = require("node:test"),
  A = require("node:assert/strict"),
  path = require("node:path");
const C = require("../crypto.cjs"),
  S = require("../service.cjs"),
  { Replica } = require("../replica.cjs"),
  { fixture } = require("./helpers.cjs");
const fails = (fn, code) => A.throws(fn, (e) => e.code === code);
const alerts = (f) => f.call("admin", { op: "status" }).security_alerts;
const read = (f) => ({ op: "read", actor: f.actors.owner, asset: f.asset, request_id: C.random() });

test("revoked key use is rejected, alerted with identity + key, and bounded per actor", (t) => {
  const f = fixture(t);
  f.trusted({ op: "revoke", actor: f.actors.owner });
  fails(() => f.call("owner", read(f)), "UNAUTHORIZED");
  const [a] = alerts(f);
  A.equal(a.rule, "revoked_key_use");
  A.equal(a.identity, f.actors.owner);
  A.equal(a.key_id, C.keyID(f.keys.owner.public_key));
  A.deepEqual(a.services, ["authority"]);
  A.equal(a.reason, "UNAUTHORIZED");
  A.equal(typeof a.events[0], "number");
  for (let i = 0; i < 100; i++) fails(() => f.call("owner", read(f)), "UNAUTHORIZED");
  const status = f.call("admin", { op: "status" });
  const mine = status.security_alerts.filter((x) => x.identity === f.actors.owner);
  A.ok(mine.length <= 20, "alerts bounded: " + mine.length);
  A.equal(status.security_alert_counters[f.actors.owner].suppressed, 101 - mine.length);
});

test("signed replay is alerted; forged signatures record nothing identity-bearing", (t) => {
  const f = fixture(t);
  const env = f.envelope("owner", read(f));
  S.execute(f.store, env);
  fails(() => S.execute(f.store, env), "REPLAY");
  A.equal(alerts(f)[0].rule, "signed_replay");
  const before = alerts(f).length;
  const forged = f.envelope("peer", read(f), C.generate());
  forged.key_id = C.keyID(f.keys.peer.public_key);
  fails(() => S.execute(f.store, forged), "INVALID_SIGNATURE");
  A.equal(alerts(f).length, before);
  A.ok(!alerts(f).some((x) => x.identity === f.actors.peer));
});

test("replica records post-signature failures locally and uploads them as alerts", (t) => {
  const f = fixture(t);
  const r = new Replica({
    directory: path.join(f.directory, "edge"),
    node: "edge",
    trust: { authority: f.store.get("authority"), public_key: f.store.audit.public_key },
  });
  t.after(() => r.close());
  r.install(f.sync(r.beginSync()));
  const env = S.command(f.keys.owner, { ...S.info(f.store, f.actors.owner), audience: "edge" }, read(f), f.now());
  r.execute(env);
  fails(() => r.execute(env), "REPLAY");
  r.install(f.sync(r.beginSync()));
  const a = alerts(f).find((x) => x.services[0] === "edge");
  A.equal(a.rule, "signed_replay");
  A.equal(a.identity, f.actors.owner);
});
