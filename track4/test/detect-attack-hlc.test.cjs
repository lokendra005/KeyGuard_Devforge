"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const D = require("../detect.cjs");
const H = require("../hlc.cjs");
const dir = path.join(__dirname, "fixtures", "practice");
const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");
const config = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "examples", "practice-policy.json"), "utf8"));
const approvals = JSON.parse(read("approvals.json"));
const events = D.csv(read("events.csv"));
const summary = (r) => r.alerts.map((a) => `${a.rule}|${a.events.join(",")}`).sort();

test("every alert carries a non-empty ATT&CK mapping with valid technique ids", () => {
  const report = D.detect([...events, { ...events[0], event_id: "bad", event_time_utc: "nope" }], approvals, config);
  A.ok(report.alerts.some((a) => a.rule === "input_integrity"));
  for (const a of report.alerts) {
    A.ok(a.attack?.length, a.rule);
    for (const t of a.attack) {
      A.match(t.technique, /^T\d{4}(\.\d{3})?$/);
      A.match(t.tactic, /^TA\d{4} /);
      A.ok(t.name);
    }
  }
  A.ok(Object.isFrozen(D.ATTACK));
});

test("hlc-stamped events delivered shuffled produce the same alerts as ordered delivery", () => {
  let s = { l: 0, c: 0 };
  const stamped = events.map((e) => {
    s = H.send(s, D.time(e.event_time_utc) - Number(e.source_clock_offset_ms || 0));
    return { ...e, hlc: H.encode(s) };
  });
  const base = summary(D.detect(events, approvals, config));
  A.ok(base.length);
  A.deepEqual(summary(D.detect(stamped, approvals, config)), base);
  for (let seed = 1; seed <= 5; seed++) {
    let x = seed;
    const shuffled = [...stamped].sort(() => ((x = (x * 16807) % 2147483647) % 3) - 1);
    A.deepEqual(summary(D.detect(shuffled, approvals, config)), base);
  }
  const bad = D.detect([{ ...stamped[0], hlc: "12:x" }, ...stamped.slice(1)], approvals, config);
  A.deepEqual(bad.rejected.map((r) => r.reason), ["INVALID_HLC"]);
});

test("HLC is monotonic when the physical clock goes backwards and receive merges max", () => {
  let s = H.send({ l: 0, c: 0 }, 1000);
  A.deepEqual(s, { l: 1000, c: 0 });
  const back = H.send(s, 900);
  A.deepEqual(back, { l: 1000, c: 1 });
  A.ok(H.compare(back, s) > 0);
  A.deepEqual(H.receive(back, { l: 1000, c: 7 }, 950), { l: 1000, c: 8 });
  A.deepEqual(H.receive(back, { l: 2000, c: 3 }, 950), { l: 2000, c: 4 });
  A.deepEqual(H.receive(back, { l: 500, c: 9 }, 950), { l: 1000, c: 2 });
  A.deepEqual(H.receive(back, { l: 500, c: 9 }, 3000), { l: 3000, c: 0 });
  A.deepEqual(H.parse(H.encode({ l: 42, c: 3 })), { l: 42, c: 3 });
  A.equal(H.parse("1:-1"), null);
});
