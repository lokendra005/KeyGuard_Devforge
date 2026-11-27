"use strict";
const { test } = require("node:test"),
  A = require("node:assert/strict"),
  D = require("../detect.cjs");
const at = Date.UTC(2026, 0, 1),
  iso = (t) => new Date(at + t).toISOString();
function row(id, from, to, ms = 0, outcome = "allowed") {
  return {
    event_id: id,
    actor: "one-actor",
    source_service: from,
    target_service: to,
    action: "access",
    outcome,
    event_time_utc: iso(ms),
    received_time_utc: iso(ms + 10),
    session_id: id,
  };
}
const detect = (events, config = {}) =>
  D.detect(events, { changes: [] }, { allowed_edges: [], ...config });
test("outcome mappings cover synonyms and overrides; exact repeated input never inflates learning or detection", () => {
  for (const outcome of [
    "allow",
    "allowed",
    "success",
    "succeeded",
    "granted",
    "permit",
    "ok",
  ]) {
    const r = row("a", "one", "two", 0, outcome);
    A.equal(detect([r]).events[0].event.outcome, "success");
    A.equal(D.learn([r, r]).actor_edges.length, 0);
    A.equal(detect([r, r]).events.length, 1);
  }
  for (const outcome of [
    "deny",
    "denied",
    "failure",
    "failed",
    "blocked",
    "rejected",
    "error",
  ])
    A.equal(
      detect([row("a", "one", "two", 0, outcome)]).events[0].event.outcome,
      "failure",
    );
  A.equal(
    detect([row("x", "a", "b", 0, "PASS")], {
      outcome_map: { pass: "success" },
    }).events[0].event.outcome,
    "success",
  );
  const a = row("same", "a", "b"),
    b = { ...a, target_service: "different" };
  for (const fn of [
    () => detect([a, b], { strict_input: true }),
    () => D.learn([a, b], { strict_input: true }),
  ])
    A.throws(
      fn,
      (e) =>
        e.code === "DUPLICATE_EVENT" && e.label === "conflicting_duplicate",
    );
  // Default: the first copy is analysed and the conflicting copy is quarantined, not fatal.
  const report = detect([a, b]);
  A.equal(report.counts.events, 1);
  A.equal(report.events[0].event.target_service, "b");
  A.deepEqual(
    report.rejected.map((r) => [r.event_id, r.reason]),
    [["same", "conflicting_duplicate"]],
  );
  A.deepEqual(
    D.learn([a, b]).rejected.map((r) => r.reason),
    ["conflicting_duplicate"],
  );
});
test("actor-wide undirected components catch fan-out, reversed edges, slow chains and two successful hops", () => {
  for (const edges of [
    [
      row("a", "hub", "leaf1", 0, "blocked"),
      row("b", "hub", "leaf2", 1000, "denied"),
      row("c", "hub", "leaf3", 2000, "error"),
    ],
    [
      row("a", "one", "two", 0, "denied"),
      row("b", "three", "two", 300000),
      row("c", "three", "four", 600000),
    ],
    [row("a", "one", "two"), row("b", "two", "three", 480000)],
  ]) {
    const report = detect(edges);
    A.ok(report.alerts.some((a) => a.rule === "lateral_movement_candidate"));
    A.equal(
      new Set(report.alerts.flatMap((a) => a.sessions)).size,
      edges.length,
    );
  }
  A.equal(
    detect([row("a", "a", "b"), row("b", "a", "b", 1000)]).alerts.length,
    0,
  );
  A.equal(
    detect([row("a", "a", "b"), row("b", "c", "d", 1000)]).alerts.length,
    0,
  );
  // A different identity leaving B is not the same actor's chain, but it is credential hopping.
  const hop = detect([
    row("a", "a", "b"),
    { ...row("b", "b", "c", 1000), actor: "different" },
  ]).alerts;
  A.deepEqual(
    hop.map((a) => [a.rule, a.identities]),
    [["cross_identity_lateral_candidate", ["one-actor", "different"]]],
  );
  A.equal(
    detect(
      [row("a", "a", "b"), { ...row("b", "b", "c", 1000), actor: "different" }],
      { cross_identity_window_ms: 0 },
    ).alerts.length,
    0,
  );
  A.equal(
    detect([
      row("a", "a", "b"),
      { ...row("b", "b", "c", 300001), actor: "different" },
    ]).alerts.length,
    0,
  );
  A.equal(
    detect([row("a", "a", "b"), row("b", "b", "c", 1800001)]).alerts.length,
    0,
  );
});
test("independent topology holdout measures misses and false positives without importing the original generator", () => {
  const result = require("./detector-topology-benchmark.cjs").benchmark();
  A.ok(result.heldout_events > 10000);
  A.ok(result.metrics.tp > 0);
  A.ok(result.metrics.fp >= 0);
  A.ok(result.metrics.fn > 0);
  for (const name of ["slow_chain", "fan_out", "session_hopping", "two_hop"])
    A.ok(result.scenario_counts[name] > 0);
});

test("sliding graph agrees with independent breadth-first components across expiry, retries and bridges", () => {
  const { Graph } = require("../lateral.cjs"),
    graph = new Graph(60, 20),
    active = new Map();
  let seed = 17;
  for (let i = 0; i < 500; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    const from = "v" + (seed % 13),
      to = "v" + ((seed >>> 8) % 13),
      r = {
        event: row("e" + i, from, to, i * 3, i % 3 ? "ok" : "denied"),
        corrected_ms: i * 3,
      };
    r.event.outcome = i % 3 ? "success" : "failure";
    const key = JSON.stringify([from, to].sort());
    for (const [k, v] of active)
      if (r.corrected_ms - v.corrected_ms > 60) active.delete(k);
    active.set(key, r);
    const got = graph.add(r),
      vertices = new Set([from]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const v of active.values())
        if (
          vertices.has(v.event.source_service) ||
          vertices.has(v.event.target_service)
        )
          for (const x of [v.event.source_service, v.event.target_service])
            if (!vertices.has(x)) {
              vertices.add(x);
              changed = true;
            }
    }
    const expected = [...active.values()].filter((v) =>
      vertices.has(v.event.source_service),
    );
    A.deepEqual(
      [...got.rows.values()].map((v) => v.event.event_id).sort(),
      expected.map((v) => v.event.event_id).sort(),
    );
    A.ok(
      Math.abs(
        got.score -
          expected.reduce(
            (sum, v) => sum + 2 ** (-(r.corrected_ms - v.corrected_ms) / 20),
            0,
          ),
      ) < 1e-8,
    );
  }
});
test("large fan-out retains complete evidence without quadratic alert duplication", () => {
  const events = Array.from({ length: 10020 }, (_, i) =>
    row("edge" + i, "hub", "target" + i, i),
  );
  const result = detect(events);
  A.equal(result.counts.events, 10020);
  A.ok(result.alerts.length < 5);
  A.equal(new Set(result.alerts.flatMap((a) => a.events)).size, 10020);
  A.ok(JSON.stringify(result).length < 16 * 1024 * 1024);
  const mixed = [
    row("denial", "old", "hub", 0, "denied"),
    row("a", "hub", "two", 600000),
    row("b", "two", "three", 1200000),
  ];
  A.ok(detect(mixed).alerts.length > 0);
});
