"use strict";
const C = require("./crypto.cjs");

function csv(raw) {
  C.text(raw, 64 * 1024 * 1024);
  const rows = [];
  let row = [],
    value = "",
    quoted = false,
    closed = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quoted) {
      if (ch === '"' && raw[i + 1] === '"') {
        value += '"';
        i++;
      } else if (ch === '"') {
        quoted = false;
        closed = true;
      } else value += ch;
      continue;
    }
    if (ch === '"') {
      C.check(!value && !closed, "INVALID_CSV");
      quoted = true;
      continue;
    }
    if (ch === "," || ch === "\n" || ch === "\r") {
      row.push(value);
      value = "";
      closed = false;
      if (ch !== ",") {
        rows.push(row);
        row = [];
        if (ch === "\r" && raw[i + 1] === "\n") i++;
      }
      continue;
    }
    C.check(!closed, "INVALID_CSV");
    value += ch;
  }
  C.check(!quoted, "INVALID_CSV");
  if (value || row.length || closed) {
    row.push(value);
    rows.push(row);
  }
  C.check(rows.length > 0, "INVALID_CSV");
  const headers = rows.shift();
  C.check(
    new Set(headers).size === headers.length && headers.every((x) => x.length),
    "INVALID_CSV",
  );
  return rows.map((values) => {
    C.check(values.length === headers.length, "INVALID_CSV");
    return Object.fromEntries(headers.map((key, i) => [key, values[i]]));
  });
}
function time(raw) {
  C.text(raw, 64);
  const m =
    /^(\d{4})-(\d\d)-(\d\d)[Tt](\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?([Zz]|[+-]\d\d:\d\d)$/.exec(
      raw,
    );
  C.check(m, "INVALID_TIME");
  const [, year, month, day, hour, minute, second, fraction, zone] = m;
  const leap = +year % 4 === 0 && (+year % 100 !== 0 || +year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][
    +month - 1
  ];
  C.check(
    +month >= 1 &&
      +month <= 12 &&
      +day >= 1 &&
      +day <= days &&
      +hour < 24 &&
      +minute < 60 &&
      +second < 60 &&
      (/^[Zz]$/.test(zone) || (+zone.slice(1, 3) <= 23 && +zone.slice(4) < 60)),
    "INVALID_TIME",
  );
  const normalized = `${year}-${month}-${day}T${hour}:${minute}:${second}.${(fraction || "").padEnd(3, "0").slice(0, 3)}${zone.toUpperCase()}`;
  const n = Date.parse(normalized);
  C.check(Number.isSafeInteger(n), "INVALID_TIME");
  return n;
}
function number(value) {
  if (typeof value === "string") {
    C.check(/^-?\d+$/.test(value), "INVALID_NUMBER");
    value = Number(value);
  }
  return C.integer(value, -86400000, 86400000);
}
function estimateClock(t0, t1, t2, t3, precision = 1) {
  for (const x of [t0, t1, t2, t3]) C.integer(x, 0, Number.MAX_SAFE_INTEGER);
  C.integer(precision, 0, 1000);
  C.check(t3 >= t0 && t2 >= t1, "INVALID_CLOCK_SAMPLE");
  const delay = t3 - t0 - (t2 - t1);
  C.check(delay >= 0, "INVALID_CLOCK_SAMPLE");
  return {
    offset_ms: Math.round((t1 - t0 + (t2 - t3)) / 2),
    uncertainty_ms: Math.ceil(delay / 2) + precision,
    round_trip_ms: delay,
  };
}
const DEFAULT_OUTCOMES = Object.freeze(
  Object.fromEntries([
    ...[
      "allow",
      "allowed",
      "success",
      "succeeded",
      "granted",
      "permit",
      "ok",
    ].map((x) => [x, "success"]),
    ...[
      "deny",
      "denied",
      "failure",
      "failed",
      "blocked",
      "rejected",
      "error",
    ].map((x) => [x, "failure"]),
  ]),
);
function unique(events) {
  const seen = new Map();
  return events.filter((event) => {
    C.object(event);
    C.text(event.event_id);
    const content = C.digest(event),
      previous = seen.get(event.event_id);
    if (previous !== undefined && previous !== content) {
      const error = new C.Fault("DUPLICATE_EVENT");
      error.label = "conflicting_duplicate";
      error.event_id = event.event_id;
      throw error;
    }
    seen.set(event.event_id, content);
    return previous === undefined;
  });
}
function normalize(event, index, config) {
  C.object(event);
  const e = { ...event };
  for (const field of [
    "event_id",
    "actor",
    "source_service",
    "target_service",
    "action",
    "outcome",
  ])
    C.text(e[field]);
  for (const field of [
    "session_id",
    "correlation_id",
    "role_before",
    "role_after",
    "approval_id",
    "subject",
    "identity_state_after",
    "approved_by",
  ]) {
    e[field] ??= "";
    C.text(e[field]);
  }
  const mapping = {
    ...DEFAULT_OUTCOMES,
    ...C.object(config.outcome_map || {}),
  };
  for (const value of Object.values(mapping))
    C.check(["success", "failure"].includes(value), "INVALID_OUTCOME_MAP");
  const word = e.outcome.trim().toLowerCase();
  e.outcome = Object.hasOwn(mapping, word) ? mapping[word] : "unknown";
  const offset = number(e.source_clock_offset_ms ?? 0);
  const uncertainty = C.integer(
    number(e.source_clock_uncertainty_ms ?? config.uncertainty_ms ?? 0),
    0,
    3600000,
  );
  const corrected = time(e.event_time_utc) - offset;
  const received = time(e.received_time_utc ?? e.event_time_utc);
  return {
    event: e,
    index,
    corrected_ms: corrected,
    received_ms: received,
    earliest_ms: corrected - uncertainty,
    latest_ms: corrected + uncertainty,
    offset_ms: offset,
    uncertainty_ms: uncertainty,
    uncertain:
      Math.abs(offset) > (config.max_offset_ms ?? 300000) ||
      corrected - uncertainty > received ||
      received - corrected - uncertainty > (config.max_lateness_ms ?? 120000) ||
      event.received_time_utc === undefined,
    out_of_order: false,
    labels: [],
    alerts: [],
  };
}
function learn(reference, options = {}) {
  C.check(
    Array.isArray(reference) &&
      reference.length > 0 &&
      reference.length <= 100000,
    "REFERENCE_CAPACITY",
  );
  const minimum = C.integer(options.min_observations ?? 2, 1, 100000);
  const actors = new Map(),
    roles = new Map();
  let start = Infinity,
    end = -Infinity;
  reference = unique(reference);
  for (let i = 0; i < reference.length; i++) {
    const r = normalize(reference[i], i, options),
      e = r.event;
    start = Math.min(start, r.corrected_ms);
    end = Math.max(end, r.corrected_ms);
    if (
      e.outcome !== "success" ||
      e.role_before !== e.role_after ||
      r.uncertain
    )
      continue;
    for (const [map, who] of [
      [actors, e.actor],
      [roles, e.role_after],
    ]) {
      const id = C.canonical([who, e.source_service, e.target_service]);
      map.set(id, (map.get(id) || 0) + 1);
    }
  }
  const paths = (map) =>
    [...map]
      .filter(([, n]) => n >= minimum)
      .map(([key]) => JSON.parse(key))
      .sort((a, b) => C.canonical(a).localeCompare(C.canonical(b)));
  return {
    version: 1,
    reference_count: reference.length,
    reference_commitment: C.digest(reference),
    reference_start_ms: start,
    reference_end_ms: end,
    min_observations: minimum,
    actor_edges: paths(actors),
    role_edges: paths(roles),
  };
}
function detect(events, approvals, config = {}) {
  // shortcut: batch analysis has an explicit 100k-event/64-MiB budget; use partitioned ingestion above this workload.
  C.check(Array.isArray(events) && events.length <= 100000, "EVENT_CAPACITY");
  C.check(
    Buffer.byteLength(JSON.stringify(events)) <= 64 * 1024 * 1024,
    "EVENT_BYTES_CAPACITY",
  );
  C.object(config);
  const window = C.integer(config.window_ms ?? 1800000, 1, 3600000);
  const halfLife = C.integer(config.half_life_ms ?? 600000, 1, 3600000);
  const minEdges = C.integer(config.lateral_min_edges ?? 3, 2, 100);
  const minScore = C.integer(config.lateral_score_milli ?? 2000, 1, 100000);
  const maxOffset = C.integer(config.max_offset_ms ?? 300000, 0, 86400000);
  const maxDelay = C.integer(config.max_lateness_ms ?? 120000, 0, 86400000);
  const baseline = config.baseline;
  C.check(baseline || Array.isArray(config.allowed_edges), "BASELINE_REQUIRED");
  const pathSet = (values) =>
    new Set(
      values.map((edge) => {
        C.check(Array.isArray(edge) && edge.length === 3, "INVALID_BASELINE");
        edge.forEach((v) => C.text(v));
        return C.canonical(edge);
      }),
    );
  if (baseline)
    C.check(
      baseline.version === 1 && Number.isSafeInteger(baseline.reference_end_ms),
      "INVALID_BASELINE",
    );
  const actorEdges = pathSet(baseline?.actor_edges || []),
    roleEdges = pathSet(baseline?.role_edges || []);
  const explicitEdges = new Set(
    (config.allowed_edges || []).map((edge) => {
      C.check(Array.isArray(edge) && edge.length === 4, "INVALID_BASELINE");
      edge.forEach((v) => C.text(v));
      return C.canonical(edge);
    }),
  );
  const changes = C.object(approvals).changes;
  C.check(
    Array.isArray(changes) && changes.length <= 100000,
    "INVALID_APPROVALS",
  );
  const changeMap = new Map(),
    revokedRoles = new Map();
  for (const change of changes) {
    C.object(change);
    C.text(change.approval_id);
    C.check(!changeMap.has(change.approval_id), "DUPLICATE_APPROVAL");
    changeMap.set(change.approval_id, change);
    if (change.operation === "revoke_role") {
      const key = C.canonical([change.subject, change.role]);
      const at = time(change.effective_at_utc);
      const times = revokedRoles.get(key) || [];
      times.push(at);
      revokedRoles.set(key, times);
    }
  }
  for (const times of revokedRoles.values()) times.sort((a, b) => a - b);
  function lastRevocation(key, at) {
    const times = revokedRoles.get(key) || [];
    let lo = 0,
      hi = times.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (times[mid] <= at) lo = mid + 1;
      else hi = mid;
    }
    return lo ? times[lo - 1] : Infinity;
  }
  const observations = unique(events).map((event, index) => {
    const row = normalize(event, index, config);
    if (baseline)
      C.check(
        row.corrected_ms > baseline.reference_end_ms,
        "BASELINE_HOLDOUT_OVERLAP",
      );
    return row;
  });
  let watermark = -Infinity;
  for (const row of [...observations].sort(
    (a, b) => a.received_ms - b.received_ms || a.index - b.index,
  )) {
    row.out_of_order = row.latest_ms < watermark;
    watermark = Math.max(watermark, row.earliest_ms);
  }
  observations.sort(
    (a, b) => a.corrected_ms - b.corrected_ms || a.index - b.index,
  );
  const suspiciousChanges = new Map(),
    roleGrants = new Map(),
    revoked = new Map(),
    groups = new Map(),
    familiarRoutes = new Map(),
    movementRows = [],
    alerts = [];
  function alert(rule, rows, explanation, scoreMilli) {
    const support = [...new Set(rows.map((r) => r.event.event_id))];
    const result = {
      id: C.digest([rule, support]),
      rule,
      identity: rows.at(-1).event.actor,
      services: [
        ...new Set(
          rows.flatMap((r) => [r.event.source_service, r.event.target_service]),
        ),
      ],
      events: support,
      sessions: [
        ...new Set(rows.map((r) => r.event.session_id).filter(Boolean)),
      ],
      detected_at_ms: Math.max(...rows.map((r) => r.received_ms)),
      explanation,
      uncertain_order:
        rows.some((r) => r.uncertain) ||
        rows.some((r, i) => i > 0 && rows[i - 1].latest_ms >= r.earliest_ms),
      ...(scoreMilli === undefined ? {} : { decayed_score_milli: scoreMilli }),
    };
    alerts.push(result);
    for (const row of rows) {
      if (!row.alerts.includes(result.id)) row.alerts.push(result.id);
      row.first_alert_at_ms = Math.min(
        row.first_alert_at_ms ?? Infinity,
        result.detected_at_ms,
      );
    }
    return result;
  }
  function scoped(a, row, roleOnly = false) {
    const e = row.event;
    return (
      a &&
      a.operation === "grant_role" &&
      typeof a.approved_by === "string" &&
      a.approved_by.length > 0 &&
      a.subject === e.actor &&
      a.approved_by !== a.subject &&
      (!e.approved_by || e.approved_by !== e.actor) &&
      a.role === e.role_after &&
      row.earliest_ms >= time(a.valid_from_utc) &&
      row.latest_ms < time(a.valid_until_utc) &&
      (roleOnly ||
        (Array.isArray(a.scope) && a.scope.includes(e.target_service)))
    );
  }
  for (const row of observations) {
    const e = row.event,
      actor = e.actor;
    const successful = e.outcome === "success";
    if (row.uncertain) row.labels.push("timing_uncertain");
    if (row.out_of_order) row.labels.push("delayed_delivery");
    if (row.offset_ms) row.labels.push("clock_corrected");
    const isRevocation =
      ["revoked", "disabled"].includes(e.identity_state_after) ||
      (
        config.revocation_actions || ["revoke", "revoke_key", "disable_user"]
      ).includes(e.action);
    if (successful && isRevocation) {
      revoked.set(e.subject || e.actor, row);
      row.labels.push("revocation_observed");
      continue;
    }
    const a = changeMap.get(e.approval_id);
    if (
      successful &&
      ((a && a.approved_by === a.subject) ||
        (e.approved_by && e.approved_by === e.actor))
    ) {
      row.labels.push("self_approval");
      alert(
        "self_approval",
        [row],
        "The beneficiary approved their own successful change or access.",
      );
    }
    if (successful && e.role_before !== e.role_after) {
      const approvedRemoval =
        a &&
        a.operation === "revoke_role" &&
        a.subject === e.actor &&
        a.approved_by &&
        a.approved_by !== a.subject &&
        a.role === e.role_before &&
        row.earliest_ms >= time(a.effective_at_utc);
      if ((scoped(a, row, true) || approvedRemoval) && !row.uncertain) {
        row.labels.push("approved_change");
        suspiciousChanges.delete(actor);
        if (!approvedRemoval)
          roleGrants.set(C.canonical([e.actor, e.role_after]), {
            at: row.earliest_ms,
            until: time(a.valid_until_utc),
          });
      } else {
        row.labels.push("unexpected_role_change");
        suspiciousChanges.set(actor, row);
        alert(
          "unexpected_role_change",
          [row],
          "A successful role-state transition lacks an independent subject/role/time-matched approval; the action name is not used.",
        );
      }
      continue;
    }
    if (!["success", "failure"].includes(e.outcome)) continue;
    const previous = suspiciousChanges.get(actor);
    if (
      successful &&
      previous &&
      row.corrected_ms - previous.corrected_ms <= window
    ) {
      row.labels.push("review_after_role_change");
      alert(
        "access_after_role_change",
        [previous, row],
        "Allowed access follows an unexplained role transition in the same identity.",
      );
    }
    if (successful && revoked.has(e.actor)) {
      row.labels.push("access_after_revocation");
      // A legitimate revocation is supporting context, not itself a malicious event in event-level scoring.
      alert(
        "access_after_revocation",
        [row],
        "Successful access after observed revocation of this identity; revocation event " +
          revoked.get(e.actor).event.event_id,
      );
    }
    if (successful && a && !scoped(a, row)) {
      row.labels.push("approval_scope_violation");
      alert(
        "approval_scope_violation",
        [row],
        "Referenced approval does not authorize this beneficiary, role, service, approver or interval.",
      );
    }
    const roleID = C.canonical([e.actor, e.role_after]);
    const revokedAt = lastRevocation(roleID, row.earliest_ms),
      grant = roleGrants.get(roleID);
    const regranted =
      (grant && grant.at > revokedAt && row.latest_ms < grant.until) ||
      (scoped(a, row) && time(a.valid_from_utc) > revokedAt);
    if (successful && row.earliest_ms >= revokedAt && !regranted) {
      row.labels.push("access_after_role_revocation");
      alert(
        "access_after_role_revocation",
        [row],
        "Access still uses a role after its recorded revocation became effective.",
      );
    }
    const known =
      actorEdges.has(
        C.canonical([e.actor, e.source_service, e.target_service]),
      ) ||
      roleEdges.has(
        C.canonical([e.role_after, e.source_service, e.target_service]),
      ) ||
      [e.actor, "*"].some((actor) =>
        [e.action, "*"].some((action) =>
          explicitEdges.has(
            C.canonical([actor, e.source_service, e.target_service, action]),
          ),
        ),
      );
    const route = C.canonical([e.actor, e.source_service, e.target_service]);
    if (known) {
      if (successful && !row.uncertain && !row.alerts.length)
        familiarRoutes.set(route, row);
      continue;
    }
    if (successful && scoped(a, row) && !row.uncertain) continue;
    row.labels.push("novel_service_path");
    if (successful && config.alert_on_novel === true)
      alert(
        "unexpected_service_access",
        [row],
        "Explicit strict-baseline policy: this successful service edge is absent from the frozen baseline.",
      );
    if (e.source_service === e.target_service) continue;
    const familiar = familiarRoutes.get(route);
    if (
      familiar &&
      !row.uncertain &&
      familiar.latest_ms < row.earliest_ms &&
      row.corrected_ms - familiar.corrected_ms <= window
    ) {
      row.labels.push("familiar_actor_path");
      row.route_context_event_id = familiar.event.event_id;
      continue;
    }
    movementRows.push(row);
  }
  const { Graph, pivots } = require("./lateral.cjs");
  const witnesses = pivots(movementRows, window);
  for (const row of movementRows) {
    const actor = row.event.actor;
    if (!groups.has(actor)) groups.set(actor, new Graph(window, halfLife));
    const component = groups.get(actor).add(row);
    const scoreMilli = Math.floor(1000 * component.score + 1e-8);
    const qualifying =
      component.rows.size >= minEdges && scoreMilli >= minScore
        ? component
        : undefined;
    if (qualifying) {
      const pending = [...qualifying.pending];
      qualifying.pending.clear();
      for (const r of pending)
        if (!r.labels.includes("lateral_movement_candidate"))
          r.labels.push("lateral_movement_candidate");
      if (!qualifying.alert) {
        const rows = [...qualifying.rows.values()];
        qualifying.alert = alert(
          "lateral_movement_candidate",
          rows,
          "Actor-wide connected unusual service edges across sessions satisfy the configured distinct-edge count and decayed score. Evidence grows within an incident; detected_at_ms is its first signal.",
          Math.floor(qualifying.score * 1000 + 1e-8),
        );
        qualifying.evidenceIDs = new Set(qualifying.alert.events);
        qualifying.services = new Set(qualifying.alert.services);
        qualifying.sessions = new Set(qualifying.alert.sessions);
      } else {
        const result = qualifying.alert;
        for (const r of pending) {
          if (!qualifying.evidenceIDs.has(r.event.event_id)) {
            result.events.push(r.event.event_id);
            qualifying.evidenceIDs.add(r.event.event_id);
          }
          for (const service of [
            r.event.source_service,
            r.event.target_service,
          ])
            if (!qualifying.services.has(service)) {
              qualifying.services.add(service);
              result.services.push(service);
            }
          if (
            r.event.session_id &&
            !qualifying.sessions.has(r.event.session_id)
          ) {
            qualifying.sessions.add(r.event.session_id);
            result.sessions.push(r.event.session_id);
          }
          if (!r.alerts.includes(result.id)) r.alerts.push(result.id);
          r.first_alert_at_ms = Math.min(
            r.first_alert_at_ms ?? Infinity,
            Math.max(result.detected_at_ms, r.received_ms),
          );
          result.uncertain_order ||= r.uncertain || r.out_of_order;
        }
        result.decayed_score_milli = Math.floor(qualifying.score * 1000 + 1e-8);
      }
    } else if (witnesses.has(row.event.event_id)) {
      const pair = witnesses.get(row.event.event_id);
      for (const r of pair)
        if (!r.labels.includes("lateral_movement_candidate"))
          r.labels.push("lateral_movement_candidate");
      alert(
        "lateral_movement_candidate",
        pair,
        "Two successful unusual hops A -> B -> C visit three distinct services within the window. The first hop's latest possible time precedes the second hop's earliest possible time; session IDs need not match.",
      );
    }
  }
  for (const row of observations)
    if (!row.labels.length) row.labels.push("routine");
  return {
    version: 3,
    config_commitment: C.digest(config),
    approvals_commitment: C.digest(approvals),
    baseline: baseline
      ? {
          reference_count: baseline.reference_count,
          reference_commitment: baseline.reference_commitment,
          reference_end_ms: baseline.reference_end_ms,
        }
      : { source: "explicit operator policy" },
    events: observations.map(({ index, ...row }) => row),
    alerts,
    counts: {
      events: observations.length,
      alerts: alerts.length,
      uncertain: observations.filter((r) => r.uncertain).length,
      out_of_order: observations.filter((r) => r.out_of_order).length,
    },
    limits: {
      window_ms: window,
      half_life_ms: halfLife,
      lateral_score_milli: minScore,
      max_offset_ms: maxOffset,
      max_lateness_ms: maxDelay,
      max_events: 100000,
      timestamp_precision:
        "milliseconds; fractional digits beyond three are truncated; timezone required; leap seconds rejected",
      timing_source:
        "operator-supplied offset/uncertainty; no network time assumptions",
    },
  };
}
function score(report, labels, positiveLabels) {
  C.check(
    Array.isArray(positiveLabels) && positiveLabels.length > 0,
    "SCORING_POLICY_REQUIRED",
  );
  const positives = new Set(positiveLabels);
  const truth = new Map(
    labels.map((x) => [x.event_id, positives.has(x.label)]),
  );
  C.check(
    truth.size === labels.length &&
      truth.size === report.events.length &&
      report.events.every((r) => truth.has(r.event.event_id)),
    "LABEL_MISMATCH",
  );
  let tp = 0,
    fp = 0,
    fn = 0,
    tn = 0;
  const delays = [];
  const byID = new Map(report.alerts.map((a) => [a.id, a]));
  for (const row of report.events) {
    const actual = row.alerts.length > 0;
    const expected = truth.get(row.event.event_id);
    if (actual && expected) {
      tp++;
      delays.push(
        Math.max(
          0,
          Math.max(
            row.received_ms,
            row.first_alert_at_ms ??
              Math.min(...row.alerts.map((id) => byID.get(id).detected_at_ms)),
          ) - row.corrected_ms,
        ),
      );
    } else if (actual) fp++;
    else if (expected) fn++;
    else tn++;
  }
  delays.sort((a, b) => a - b);
  const median = delays.length
    ? (delays[Math.floor((delays.length - 1) / 2)] +
        delays[Math.floor(delays.length / 2)]) /
      2
    : null;
  return {
    unit: "event",
    tp,
    fp,
    fn,
    tn,
    precision: tp + fp ? tp / (tp + fp) : null,
    recall: tp + fn ? tp / (tp + fn) : null,
    f1: 2 * tp + fp + fn ? (2 * tp) / (2 * tp + fp + fn) : null,
    median_alert_latency_ms: median,
    false_alerted_events_per_1000_benign:
      fp + tn ? (1000 * fp) / (fp + tn) : null,
    limitation:
      "Retrospective event-level evaluation using receipt timestamps; not production accuracy or measured live processing latency.",
  };
}
module.exports = { csv, detect, score, estimateClock, learn, time, unique };
