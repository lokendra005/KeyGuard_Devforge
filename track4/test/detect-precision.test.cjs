"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const D = require("../detect.cjs");
const { pivots } = require("../lateral.cjs");
const epoch = Date.UTC(2026, 3, 2),
  iso = (ms) => new Date(epoch + ms).toISOString();
function event(id, from, to, ms, extra = {}) {
  return {
    event_id: id,
    actor: "person",
    source_service: from,
    target_service: to,
    action: "invoke",
    outcome: "ok",
    role_before: "reader",
    role_after: "reader",
    event_time_utc: iso(ms),
    received_time_utc: iso(ms + 100),
    session_id: "session/" + id,
    ...extra,
  };
}
function detect(events, config = {}) {
  return D.detect(events, { changes: [] }, { allowed_edges: [], ...config });
}
const lateral = (report) =>
  report.alerts.filter((a) => a.rule === "lateral_movement_candidate");

test("two-hop witnesses require an ordered pivot; three-edge fan-out and failed probes remain detectable", () => {
  for (const edges of [
    [
      ["a", "b"],
      ["a", "c"],
    ],
    [
      ["a", "b"],
      ["c", "b"],
    ],
    [
      ["b", "c"],
      ["a", "b"],
    ],
    [
      ["a", "b"],
      ["b", "a"],
    ],
  ]) {
    A.equal(
      lateral(
        detect(edges.map(([a, b], i) => event(String(i), a, b, i * 1000))),
      ).length,
      0,
    );
  }
  for (const gap of [1, 480000, 1800000]) {
    const pair = [event("first", "a", "b", 0), event("second", "b", "c", gap)];
    A.equal(lateral(detect(pair)).length, 1);
    A.equal(lateral(detect([...pair].reverse())).length, 1);
    A.equal(lateral(detect(pair)).at(0).sessions.length, 2);
  }
  A.equal(
    lateral(
      detect([event("first", "a", "b", 0), event("second", "b", "c", 1800001)]),
    ).length,
    0,
  );
  for (const outcomes of [
    ["ok", "ok", "ok"],
    ["denied", "error", "blocked"],
    ["ok", "denied", "ok"],
  ]) {
    const star = outcomes.map((outcome, i) =>
      event(String(i), "hub", "leaf/" + i, i * 1000, { outcome }),
    );
    A.equal(new Set(lateral(detect(star)).flatMap((a) => a.events)).size, 3);
  }
  const slow = Array.from({ length: 4 }, (_, i) =>
    event(String(i), "v" + i, "v" + (i + 1), i * 300000, {
      outcome: i ? "ok" : "denied",
    }),
  );
  A.equal(new Set(lateral(detect(slow)).flatMap((a) => a.events)).size, 4);
});

test("pivot evidence excludes unrelated spokes, respects uncertainty, and retains older valid repeated-edge witnesses", () => {
  const rows = [
    event("spoke", "b", "x", 0),
    event("first", "a", "b", 1000),
    event("second", "b", "c", 2000),
  ];
  const report = detect(rows, { lateral_score_milli: 100000 });
  A.deepEqual(
    lateral(report).map((a) => a.events),
    [["first", "second"]],
  );
  A.equal(
    report.events.find((r) => r.event.event_id === "spoke").alerts.length,
    0,
  );
  const first = event("first", "a", "b", 0, {
    source_clock_uncertainty_ms: 50,
  });
  for (const ms of [0, 50, 100])
    A.equal(
      lateral(
        detect([
          first,
          event("second", "b", "c", ms, { source_clock_uncertainty_ms: 50 }),
        ]),
      ).length,
      0,
    );
  A.equal(
    lateral(
      detect([
        first,
        event("second", "b", "c", 101, { source_clock_uncertainty_ms: 50 }),
      ]),
    ).length,
    1,
  );
  const repeated = [
    event("early", "a", "b", 0),
    event("overlap", "a", "b", 1000, { source_clock_uncertainty_ms: 100 }),
    event("next", "b", "c", 1001),
  ];
  A.deepEqual(lateral(detect(repeated)).at(-1).events, ["early", "next"]);
  A.equal(
    lateral(
      detect([
        first,
        event("next", "b", "c", 1000, { received_time_utc: iso(500) }),
      ]),
    ).length,
    0,
  );
});

test("trusted route familiarity is actor-scoped, window-bounded, and cannot suppress role or revocation findings", () => {
  const known = event("known", "hub", "files", 0),
    change = event("change", "hub", "control", 3000, { role_after: "writer" }),
    read = event("read", "hub", "files", 4000, {
      role_before: "writer",
      role_after: "writer",
    });
  const baseline = D.learn([
    event("ref1", "hub", "files", -2000),
    event("ref2", "hub", "files", -1000),
  ]);
  // Role reference is shared; actor paths must not authorize the new actor after a role change.
  for (const edge of baseline.actor_edges) edge[0] = "reference-person";
  const config = { baseline };
  const decoys = [
    event("novel", "hub", "new", 1000),
    event("denial", "hub", "other", 2000, { outcome: "denied" }),
  ];
  const report = detect([known, ...decoys, change, read], config);
  A.equal(lateral(report).length, 0);
  A.equal(
    report.events.find((r) => r.event.event_id === "read")
      .route_context_event_id,
    "known",
  );
  A.ok(report.alerts.some((a) => a.rule === "access_after_role_change"));
  A.ok(report.alerts.some((a) => a.rule === "unexpected_role_change"));
  A.equal(lateral(detect([...decoys, read], config)).length, 1);
  A.equal(
    lateral(
      detect(
        [known, ...decoys, { ...read, received_time_utc: iso(0) }],
        config,
      ),
    ).length,
    1,
  );
  for (const badKnown of [
    { ...known, actor: "someone-else" },
    { ...known, outcome: "denied" },
    { ...known, received_time_utc: iso(-1) },
  ])
    A.equal(lateral(detect([badKnown, ...decoys, read], config)).length, 1);
  const shifted = [...decoys, read].map((e) => ({
    ...e,
    event_time_utc: iso(D.time(e.event_time_utc) - epoch + 1800001),
    received_time_utc: iso(D.time(e.received_time_utc) - epoch + 1800001),
  }));
  A.equal(lateral(detect([known, ...shifted], config)).length, 1);
  const revoked = event("revoke", "hub", "control", 500, {
    identity_state_after: "revoked",
  });
  const after = detect([known, revoked, read], {
    ...config,
    alert_on_novel: true,
  });
  A.ok(after.alerts.some((a) => a.rule === "access_after_revocation"));
  A.ok(after.alerts.some((a) => a.rule === "unexpected_service_access"));
  const newPath = event("new-path", "new", "beyond", 5000, {
    role_before: "writer",
    role_after: "writer",
  });
  A.ok(lateral(detect([known, decoys[0], change, newPath], config)).length);
});

test("labels, names and receipt ordering do not manufacture benign exceptions; ambiguous fan-out remains visible", () => {
  const rows = Array.from({ length: 3 }, (_, i) =>
    event("e" + i, "benign-hub", "benign-target/" + i, i * 1000, {
      label: "benign",
      scenario: "approved",
      outcome: i === 1 ? "denied" : "ok",
    }),
  );
  const original = detect(rows);
  A.ok(lateral(original).length);
  const renamed = rows.map((e, i) => ({
    ...e,
    actor: "random/actor",
    source_service: "random/hub",
    target_service: "random/" + i,
    label: "attack",
    scenario: "intrusion",
  }));
  A.deepEqual(
    lateral(detect(renamed)).map((a) => a.events),
    lateral(original).map((a) => a.events),
  );
  A.deepEqual(lateral(detect([...rows].reverse())), lateral(original));
  const poisoned = [
    event("poison", "hub", "new", 0),
    event("second", "new", "last", 1000),
  ];
  A.ok(lateral(detect(poisoned)).length); // Novel evaluation successes cannot certify themselves as familiar.
});

test("interval-sweep pivot index agrees with exhaustive witnesses under expiry, repeat edges and adversarial uncertainty", () => {
  let seed = 198491;
  const random = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  for (let trial = 0; trial < 40; trial++) {
    const rows = Array.from({ length: 100 }, (_, i) => {
      const t = random() % 1000,
        u = random() % 150;
      return {
        event: {
          event_id: String(i),
          actor: "a" + (random() % 3),
          source_service: "s" + (random() % 7),
          target_service: "s" + (random() % 7),
          outcome: random() % 5 ? "success" : "failure",
        },
        corrected_ms: t,
        earliest_ms: t - u,
        latest_ms: t + u,
        uncertain: random() % 11 === 0,
      };
    });
    const valid = (r) =>
      !r.uncertain &&
      r.event.outcome === "success" &&
      r.event.source_service !== r.event.target_service;
    const got = pivots(rows, 250).witnesses;
    for (const b of rows) {
      const expected =
        valid(b) &&
        rows.some(
          (a) =>
            valid(a) &&
            a.event.actor === b.event.actor &&
            a.event.target_service === b.event.source_service &&
            a.event.source_service !== b.event.target_service &&
            a.latest_ms < b.earliest_ms &&
            b.corrected_ms - a.corrected_ms <= 250,
        );
      A.equal(got.has(b.event.event_id), expected);
      if (expected) {
        const [a] = got.get(b.event.event_id);
        A.ok(
          a.latest_ms < b.earliest_ms && b.corrected_ms - a.corrected_ms <= 250,
        );
      }
    }
  }
});
