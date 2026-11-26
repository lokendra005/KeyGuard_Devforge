"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const D = require("../detect.cjs");
const { generate, benchmark } = require("./detector-benchmark.cjs");
test("RFC3339 offsets/microseconds parse without accepting ambiguous or impossible dates", () => {
  A.equal(
    D.time("2026-01-01T01:30:00.123456+01:30"),
    D.time("2026-01-01T00:00:00.123Z"),
  );
  for (const bad of [
    "2026-02-30T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-01-01T00:00:60Z",
    "2026-01-01T00:00:00",
    "2026-01-01T00:00:00+24:00",
  ])
    A.throws(() => D.time(bad));
});
test("frozen reference baseline handles renamed actions, self-approval, revocation, 70s paths, absent correlation and harmless novelty", () => {
  const data = generate(134775813, 10),
    baseline = D.learn(data.reference);
  const report = D.detect(data.events, data.approvals, {
    ...data.config,
    baseline,
  });
  for (const rule of [
    "unexpected_role_change",
    "self_approval",
    "access_after_revocation",
    "lateral_movement_candidate",
  ])
    A.ok(
      report.alerts.some((a) => a.rule === rule),
      rule,
    );
  const score = D.score(report, data.labels, ["attack"]);
  A.equal(score.fp, 0);
  A.ok(score.fn > 0);
  A.ok(score.tp > 0);
  A.throws(
    () => D.detect(data.reference, { changes: [] }, { baseline }),
    (e) => e.code === "BASELINE_HOLDOUT_OVERLAP",
  );
  const copied = structuredClone(data.events);
  for (const event of copied) event.label = "arbitrary-poisoned-label";
  A.deepEqual(
    D.detect(copied, data.approvals, { ...data.config, baseline }).alerts,
    report.alerts,
  );
});
test("12,000 held-out observations are evaluated without the old 10k cap", () => {
  const result = benchmark(987654321);
  A.equal(result.heldout_events, 12000);
  A.equal(result.metrics.fp, 0);
  A.ok(result.metrics.f1 > 0.8 && result.metrics.f1 < 1);
  A.ok(result.timing.corrected_out_of_order_events > 0);
});

test("role regrant supersedes an earlier revocation but not a later one", () => {
  const t = Date.UTC(2026, 0, 1),
    iso = (ms) => new Date(t + ms).toISOString();
  const base = {
    actor: "subject",
    source_service: "portal",
    target_service: "records",
    action: "renamed-read",
    outcome: "allow",
    role_before: "reader",
    role_after: "reader",
  };
  const make = (id, ms, changes = {}) => ({
    ...base,
    event_id: id,
    event_time_utc: iso(ms),
    received_time_utc: iso(ms + 10),
    ...changes,
  });
  const approvals = {
    changes: [
      {
        approval_id: "old-revocation",
        operation: "revoke_role",
        subject: "subject",
        role: "reader",
        effective_at_utc: iso(100),
      },
      {
        approval_id: "new-grant",
        operation: "grant_role",
        subject: "subject",
        role: "reader",
        approved_by: "independent-admin",
        scope: ["records"],
        valid_from_utc: iso(200),
        valid_until_utc: iso(10000),
      },
      {
        approval_id: "new-revocation",
        operation: "revoke_role",
        subject: "subject",
        role: "reader",
        effective_at_utc: iso(500),
      },
    ],
  };
  const events = [
    make("bad-before", 150),
    make("grant", 210, {
      role_before: "none",
      approval_id: "new-grant",
      action: "unknown-grant",
      outcome: "success",
    }),
    make("good-after", 300),
    make("bad-later", 600),
  ];
  const result = D.detect(events, approvals, {
    allowed_edges: [["*", "portal", "records", "*"]],
  });
  A.equal(
    result.events.find((r) => r.event.event_id === "good-after").alerts.length,
    0,
  );
  for (const id of ["bad-before", "bad-later"])
    A.ok(
      result.events
        .find((r) => r.event.event_id === id)
        .labels.includes("access_after_role_revocation"),
    );
});
