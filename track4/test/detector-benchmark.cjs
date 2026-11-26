"use strict";
const D = require("../detect.cjs");
function generate(seed = 20261127, episodes = 600) {
  let state = seed >>> 0;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const name = (kind) => kind + "-" + next().toString(36);
  const services = Array.from({ length: 8 }, () => name("service"));
  const actions = Array.from({ length: 4 }, () => name("action"));
  const roles = [name("reader"), name("writer")];
  const base = Date.UTC(2026, 0, 1);
  const reference = [],
    events = [],
    labels = [],
    changes = [];
  const config = {
    window_ms: 1800000,
    half_life_ms: 600000,
    lateral_min_edges: 3,
    lateral_score_milli: 2000,
  };
  function event(actor, at, overrides = {}, reference = false) {
    const offset = reference ? 0 : (next() % 600001) - 300000;
    const delay = reference ? 20 : next() % 120001;
    const source = new Date(at + offset).toISOString();
    return {
      event_id: name("event"),
      actor,
      source_service: services[0],
      target_service: services[1],
      action: actions[0],
      outcome: "allow",
      role_before: roles[0],
      role_after: roles[0],
      event_time_utc: reference ? source : source.replace(/Z$/, "123+00:00"),
      received_time_utc: new Date(at + delay).toISOString(),
      source_clock_offset_ms: offset,
      session_id: actor,
      ...overrides,
    };
  }
  for (let i = 0; i < 4000; i++)
    reference.push(
      event(
        "reference-" + (i % 40),
        base + i,
        { target_service: services[1 + (i % 2)] },
        true,
      ),
    );
  for (let i = 0; i < episodes; i++) {
    const actor = name("actor"),
      at = base + 60000 + i * 600000;
    const rows = Array.from({ length: 20 }, (_, j) =>
      event(actor, at + j * 1000, { target_service: services[1 + (j % 2)] }),
    );
    // Benign novel edge and isolated denial are decoys, not attacks merely because unseen.
    rows[2].target_service = name("new-benign-service");
    rows[3].target_service = name("denied-service");
    rows[3].outcome = "deny";
    const malicious = new Set();
    switch (i % 5) {
      case 0:
      case 1: {
        const grant = rows[18],
          access = rows[19];
        Object.assign(grant, {
          action: actions[1],
          outcome: "success",
          role_after: roles[1],
        });
        Object.assign(access, { role_before: roles[1], role_after: roles[1] });
        if (i % 5 === 1) {
          grant.approval_id = name("approval");
          access.approval_id = grant.approval_id;
          changes.push({
            approval_id: grant.approval_id,
            operation: "grant_role",
            subject: actor,
            approved_by: actor,
            role: roles[1],
            scope: [services[1], services[2]],
            valid_from_utc: new Date(at).toISOString(),
            valid_until_utc: new Date(at + 300000).toISOString(),
          });
        }
        malicious.add(18);
        malicious.add(19);
        break;
      }
      case 2:
        for (let j = 0; j < 3; j++) {
          rows[17 + j] = event(actor, at + 20000 + j * 70000, {
            source_service: services[3 + j],
            target_service: services[4 + j],
            action: actions[j],
            correlation_id: name("independent-flow"),
            outcome: j === 0 ? "deny" : "allow",
          });
          malicious.add(17 + j);
        }
        break;
      case 3:
        Object.assign(rows[18], {
          action: actions[2],
          outcome: "success",
          identity_state_after: "revoked",
        });
        malicious.add(19);
        break;
      case 4:
        rows[19].target_service = name("isolated-stolen-credential-target");
        malicious.add(19);
        break;
    }
    for (let j = 0; j < rows.length; j++) {
      events.push(rows[j]);
      labels.push({
        event_id: rows[j].event_id,
        label: malicious.has(j) ? "attack" : "benign",
      });
    }
  }
  events.sort(
    (a, b) => D.time(a.received_time_utc) - D.time(b.received_time_utc),
  );
  return { reference, events, approvals: { changes }, labels, config };
}
function benchmark(seed = 20261127, episodes = 600) {
  const data = generate(seed, episodes);
  const baseline = D.learn(data.reference, data.config);
  const started = performance.now();
  const report = D.detect(data.events, data.approvals, {
    ...data.config,
    baseline,
  });
  return {
    seed,
    reference_events: data.reference.length,
    heldout_events: data.events.length,
    baseline_commitment: baseline.reference_commitment,
    elapsed_ms: Math.round(performance.now() - started),
    metrics: D.score(report, data.labels, ["attack"]),
    timing: {
      source_offset_range_ms: [-300000, 300000],
      receipt_delay_range_ms: [0, 120000],
      corrected_out_of_order_events: report.counts.out_of_order,
    },
    protocol:
      "Fixed rules and parameters; separate earlier reference window; services, identities, roles and action names renamed by seed. Labels are passed only to score(). Synthetic, not real-world accuracy.",
    tradeoff:
      "Actor-wide fan-out and two-hop sensitivity connect benign novelty and isolated denials in this original, unchanged holdout. Reported false positives are retained; recall is not evidence of identifying stolen credentials in isolation.",
  };
}
if (require.main === module)
  console.log(
    JSON.stringify(benchmark(Number(process.argv[2] || 20261127)), null, 2),
  );
module.exports = { generate, benchmark };
