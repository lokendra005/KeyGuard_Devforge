"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const D = require("../detect.cjs");
const dir = path.join(__dirname, "fixtures", "practice");
const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");

test("organizer practice set: every alerted event is a labelled finding, every finding is alerted", () => {
  const config = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "examples", "practice-policy.json"), "utf8"),
  );
  const report = D.detect(D.csv(read("events.csv")), JSON.parse(read("approvals.json")), config);
  const positive = new Set(["unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"]);
  const labels = D.csv(read("labels.csv"));
  const expected = labels.filter((l) => positive.has(l.label)).map((l) => l.event_id).sort();
  const alerted = report.events.filter((r) => r.alerts.length).map((r) => r.event.event_id).sort();
  A.deepEqual(alerted, expected);
  // Operator approve/revoke administration events are not beneficiary scope violations.
  for (const id of ["evt-003", "evt-016"])
    A.ok(report.events.find((r) => r.event.event_id === id).labels.includes("approval_administration"));
  const m = D.score(report, labels, [...positive]);
  A.equal(m.f1, 1);
  A.equal(report.counts.rejected, 0);
});

test("unknown outcomes, revocation subjects, reinstatement and bad records fail safely", () => {
  const iso = (ms) => new Date(Date.UTC(2026, 0, 1) + ms).toISOString();
  let n = 0;
  const ev = (actor, from, to, ms, extra = {}) => ({
    event_id: "e" + ++n, actor, source_service: from, target_service: to, action: "read",
    outcome: "allow", event_time_utc: iso(ms), received_time_utc: iso(ms + 5), ...extra,
  });
  const run = (events, approvals = { changes: [] }) =>
    D.detect(events, approvals, { allowed_edges: [["*", "portal", "catalog", "*"]] });
  // Unrecognized outcome on an unapproved role change fails closed and is counted.
  const esc = run([ev("u", "admin", "identity", 0, { outcome: "SUCCESS_MFA", role_before: "viewer", role_after: "operator" })]);
  A.equal(esc.alerts[0].rule, "unexpected_role_change");
  A.equal(esc.counts.unknown_outcome, 1);
  // Revocation without a subject never revokes the operator; reinstatement clears revocation.
  A.equal(run([ev("admin", "admin", "identity", 0, { action: "revoke_key" }), ev("admin", "portal", "catalog", 1000)]).alerts.length, 0);
  A.equal(run([
    ev("admin", "admin", "identity", 0, { action: "disable_user", subject: "u5" }),
    ev("u5", "portal", "catalog", 1000),
  ]).alerts[0].rule, "access_after_revocation");
  A.equal(run([
    ev("admin", "admin", "identity", 0, { action: "disable_user", subject: "u5" }),
    ev("admin", "admin", "identity", 500, { action: "enable_user", subject: "u5" }),
    ev("u5", "portal", "catalog", 1000),
  ]).alerts.length, 0);
  // One malformed record or approval is quarantined; the rest is still analysed.
  const mixed = run(
    [
      { ...ev("x", "portal", "catalog", 0), event_time_utc: "2026-01-01 00:00:00Z" },
      ev("u", "admin", "identity", 1000, { role_before: "viewer", role_after: "operator", approval_id: "bad" }),
    ],
    { changes: [{ approval_id: "bad", operation: "grant_role", subject: "u", role: "operator", approved_by: "admin" }] },
  );
  A.deepEqual(mixed.rejected.map((r) => r.reason), ["INVALID_TIME"]);
  A.equal(mixed.rejected_approvals.length, 1);
  A.equal(mixed.alerts[0].rule, "unexpected_role_change");
});
