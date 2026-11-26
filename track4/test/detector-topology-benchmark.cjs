"use strict";
// Independent scenario builder: no imports, templates or labels from detector-benchmark.cjs.
const D = require("../detect.cjs");
function generate(seed = 314159) {
  let state = seed >>> 0,
    serial = 0;
  const random = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  const token = () => random().toString(16),
    base = Date.UTC(2025, 7, 19),
    reference = [],
    events = [],
    labels = [],
    changes = [];
  const service = Array.from({ length: 12 }, () => "mesh/" + token()),
    role = "operator/" + token();
  const success = ["allowed", "succeeded", "granted", "permit", "ok"],
    failed = ["denied", "failed", "blocked", "rejected", "error"];
  function emit(actor, ms, from, to, outcome, extra = {}) {
    const skew = ((random() % 601) - 300) * 1000,
      lag = random() % 120001;
    return {
      event_id: "topology/" + ++serial,
      actor,
      source_service: from,
      target_service: to,
      action: "invoke_" + token(),
      outcome,
      role_before: role,
      role_after: role,
      session_id: "login/" + token(),
      correlation_id: token(),
      event_time_utc: new Date(ms + skew).toISOString(),
      received_time_utc: new Date(ms + lag).toISOString(),
      source_clock_offset_ms: skew,
      ...extra,
    };
  }
  for (let i = 0; i < 3600; i++)
    reference.push(
      emit(
        "reference/" + (i % 60),
        base + i,
        service[i % 3],
        service[3 + (i % 3)],
        success[i % 5],
      ),
    );
  const mixes = {
    slow_chain: 0,
    fan_out: 0,
    session_hopping: 0,
    two_hop: 0,
    isolated_attack: 0,
    benign_approved_fan_out: 0,
    benign_unapproved_novelty: 0,
  };
  for (let i = 0; i < 700; i++) {
    const actor = "principal/" + token(),
      at = base + 3600000 + i * 3600000,
      kind = Object.keys(mixes)[i % 7];
    mixes[kind]++;
    const rows = [],
      attacks = new Set();
    for (let j = 0; j < 16; j++)
      rows.push(
        emit(
          actor,
          at + j * 1000,
          service[j % 3],
          service[3 + (j % 3)],
          success[j % 5],
        ),
      );
    function add(j, from, to, delay, ok = true, malicious = true, extra = {}) {
      rows.push(
        emit(
          actor,
          at + 60000 + delay,
          from,
          to,
          ok ? success[j % 5] : failed[j % 5],
          extra,
        ),
      );
      if (malicious) attacks.add(rows.at(-1).event_id);
    }
    if (kind === "slow_chain")
      for (let j = 0; j < 4; j++)
        add(j, service[6 + j], service[7 + j], j * 5 * 60000, j > 0);
    if (kind === "fan_out")
      for (let j = 0; j < 4; j++)
        add(j, service[6], service[7 + j], j * 1000, j !== 1);
    if (kind === "session_hopping")
      for (let j = 0; j < 3; j++)
        add(j, service[6 + j], service[7 + j], j * 90000, true, true, {
          session_id: "distinct/" + j + "/" + token(),
        });
    if (kind === "two_hop")
      for (let j = 0; j < 2; j++)
        add(j, service[8 + j], service[9 + j], j * 8 * 60000);
    if (kind === "isolated_attack") add(0, service[8], "offgrid/" + token(), 0);
    if (kind === "benign_unapproved_novelty")
      for (let j = 0; j < 2; j++)
        add(j, service[6], "benign-new/" + token(), j * 60000, true, false);
    if (kind === "benign_approved_fan_out") {
      const id = "change/" + token();
      changes.push({
        approval_id: id,
        operation: "grant_role",
        subject: actor,
        approved_by: "reviewer/" + token(),
        role,
        scope: service.slice(7, 11),
        valid_from_utc: new Date(at).toISOString(),
        valid_until_utc: new Date(at + 1800000).toISOString(),
      });
      for (let j = 0; j < 4; j++)
        add(j, service[6], service[7 + j], j * 1000, true, false, {
          approval_id: id,
        });
    }
    for (const row of rows) {
      events.push(row);
      labels.push({
        event_id: row.event_id,
        label: attacks.has(row.event_id) ? "intrusion" : "normal",
      });
    }
  }
  // Receipt order is deliberately different from event-time order.
  events.sort(
    (a, b) => Date.parse(a.received_time_utc) - Date.parse(b.received_time_utc),
  );
  return { reference, events, labels, approvals: { changes }, mixes };
}
function benchmark(seed = 314159) {
  const data = generate(seed),
    baseline = D.learn(data.reference),
    started = performance.now();
  const report = D.detect(data.events, data.approvals, { baseline });
  return {
    generator: "independent mesh-and-hub scenarios",
    seed,
    reference_events: data.reference.length,
    heldout_events: data.events.length,
    scenario_counts: data.mixes,
    metrics: D.score(report, data.labels, ["intrusion"]),
    elapsed_ms: Math.round(performance.now() - started),
    protocol:
      "Separate implementation, LCG random source, mesh/hub topology, outcome synonyms, distinct sessions, 5-minute slow hops and 8-minute two-hop paths. Frozen disjoint reference. Labels never enter detection. Unknown benign two-edge fan-out and isolated malicious access are explicit ambiguity cases; no threshold fitting.",
    timing: { offset_ms: [-300000, 300000], lateness_ms: [0, 120000] },
  };
}
if (require.main === module)
  console.log(
    JSON.stringify(benchmark(Number(process.argv[2] || 314159)), null, 2),
  );
module.exports = { generate, benchmark };
