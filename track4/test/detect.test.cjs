"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const C = require("../crypto.cjs");
const D = require("../detect.cjs");
function event(id, ms, overrides = {}) {
  return {
    event_id: id,
    event_time_utc: new Date(ms).toISOString(),
    received_time_utc: new Date(ms + 100).toISOString(),
    source_clock_offset_ms: 0,
    actor: "actor-" + id.split(":")[0],
    source_service: "portal",
    target_service: "files",
    action: "read",
    role_before: "reader",
    role_after: "reader",
    outcome: "allow",
    approval_id: "",
    session_id: "session",
    correlation_id: "flow",
    ...overrides,
  };
}
test("detector uses approval identity, role and interval, never labels or fixed event IDs", () => {
  const actor = C.random();
  const now = Date.now();
  const id = C.random();
  const grant = event(C.random(), now, {
    actor,
    action: "role_change",
    outcome: "success",
    role_after: "writer",
    approval_id: id,
  });
  const approval = {
    changes: [
      {
        approval_id: id,
        subject: actor,
        approved_by: "independent-custodian",
        operation: "grant_role",
        role: "writer",
        valid_from_utc: new Date(now - 10).toISOString(),
        valid_until_utc: new Date(now + 1000).toISOString(),
      },
    ],
  };
  const config = { allowed_edges: [["*", "portal", "files", "*"]] };
  A.equal(D.detect([grant], approval, config).alerts.length, 0);
  const stolen = { ...grant, event_id: C.random(), actor: "another-" + actor };
  A.equal(
    D.detect([stolen], approval, config).alerts[0].rule,
    "unexpected_role_change",
  );
  const expired = {
    ...grant,
    event_id: C.random(),
    event_time_utc: new Date(now + 1000).toISOString(),
    received_time_utc: new Date(now + 1100).toISOString(),
  };
  A.equal(D.detect([expired], approval, config).alerts.length, 1);
});
test("connected unexpected paths flag valid credential use; isolated and unrelated denials do not", () => {
  const actor = C.random();
  const now = Date.now();
  const base = ["alpha", "beta", "gamma", "delta"].map((x) => x + C.random());
  const path = Array.from({ length: 3 }, (_, i) =>
    event(C.random(), now + i * 100, {
      actor,
      source_service: base[i],
      target_service: base[i + 1],
      outcome: i % 2 ? "allow" : "deny",
    }),
  );
  const config = { allowed_edges: [], lateral_min_edges: 3 };
  const report = D.detect(path, { changes: [] }, config);
  A.equal(
    report.alerts.filter((a) => a.rule === "lateral_movement_candidate").length,
    1,
  );
  A.equal(
    report.alerts.find((a) => a.rule === "lateral_movement_candidate").events
      .length,
    3,
  );
  A.equal(D.detect(path.slice(0, 1), { changes: [] }, config).alerts.length, 0);
  const separate = path.map((e, i) => ({
    ...e,
    source_service: "separate-" + i,
  }));
  A.equal(
    D.detect(separate, { changes: [] }, config).alerts.filter(
      (a) => a.rule === "lateral_movement_candidate",
    ).length,
    0,
  );
});
test("clock normalization preserves raw evidence, flags uncertain order and handles late prerequisites", () => {
  const now = Date.now();
  const actor = C.random();
  const role = event("change", now, {
    actor,
    action: "role_change",
    role_after: "writer",
    outcome: "success",
    received_time_utc: new Date(now + 10000).toISOString(),
  });
  const read = event("later", now + 1000, { actor });
  const clock = event("offset", now + 5000, {
    actor,
    source_clock_offset_ms: 2000,
    received_time_utc: new Date(now + 3100).toISOString(),
  });
  const report = D.detect(
    [read, clock, role],
    { changes: [] },
    { allowed_edges: [["*", "portal", "files", "*"]] },
  );
  A.equal(
    report.events.find((e) => e.event.event_id === "offset").corrected_ms,
    now + 3000,
  );
  A.equal(
    report.events.find((e) => e.event.event_id === "offset").event
      .event_time_utc,
    clock.event_time_utc,
  );
  A.ok(report.events.find((e) => e.event.event_id === "change").out_of_order);
  A.equal(
    report.alerts.find((a) => a.rule === "access_after_role_change")
      .detected_at_ms,
    now + 10000,
  );
  const bad = D.detect(
    [{ ...clock, source_clock_offset_ms: 400000 }],
    { changes: [] },
    { allowed_edges: [] },
  );
  A.equal(bad.counts.uncertain, 1);
  A.deepEqual(D.estimateClock(1000, 3010, 3012, 1022), {
    offset_ms: 2000,
    uncertainty_ms: 11,
    round_trip_ms: 20,
  });
});
test("CSV record boundaries and event identity cannot be injected or silently overwritten", () => {
  A.deepEqual(D.csv('a,b\r\n"line\n1","x""y"\r\n'), [
    { a: "line\n1", b: 'x"y' },
  ]);
  for (const raw of ["a,a\n1,2", "a,b\n1", 'a\n"unclosed', 'a\n"x"suffix'])
    A.throws(() => D.csv(raw));
  const e = event(C.random(), Date.now());
  A.equal(
    D.detect([e, e], { changes: [] }, { allowed_edges: [] }).events.length,
    1,
  );
  A.throws(
    () =>
      D.detect(
        [e, { ...e, outcome: "denied" }],
        { changes: [] },
        { allowed_edges: [] },
      ),
    (e) => e.code === "DUPLICATE_EVENT" && e.label === "conflicting_duplicate",
  );
});
