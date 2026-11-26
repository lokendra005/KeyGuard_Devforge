"use strict";
const C = require("./crypto.cjs");

function csv(raw) {
  C.text(raw, 16 * 1024 * 1024);
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
  C.check(
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(raw),
    "INVALID_TIME",
  );
  const n = Date.parse(raw);
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
function detect(events, approvals, config) {
  C.check(Array.isArray(events) && events.length <= 10000, "EVENT_CAPACITY");
  C.object(config);
  C.check(Array.isArray(config.allowed_edges), "BASELINE_REQUIRED");
  const window = C.integer(config.window_ms ?? 60000, 1, 3600000);
  const minEdges = C.integer(config.lateral_min_edges ?? 3, 2, 100);
  const maxOffset = C.integer(config.max_offset_ms ?? 300000, 0, 86400000);
  const maxDelay = C.integer(config.max_lateness_ms ?? 120000, 0, 86400000);
  const uncertaintyDefault = C.integer(config.uncertainty_ms ?? 0, 0, 3600000);
  const sequenceCapacity = C.integer(config.sequence_capacity ?? 1024, 3, 4096);
  const changes = C.object(approvals).changes;
  C.check(Array.isArray(changes), "INVALID_APPROVALS");
  const changeMap = new Map();
  for (const change of changes) {
    C.object(change);
    C.text(change.approval_id);
    C.check(!changeMap.has(change.approval_id), "DUPLICATE_APPROVAL");
    changeMap.set(change.approval_id, change);
  }
  const edgeSet = new Set(
    config.allowed_edges.map((edge) => {
      C.check(Array.isArray(edge) && edge.length === 4, "INVALID_BASELINE");
      edge.forEach((v) => C.text(v));
      return C.canonical(edge);
    }),
  );
  const ids = new Set();
  const observations = events.map((event, index) => {
    C.object(event);
    for (const field of [
      "event_id",
      "actor",
      "source_service",
      "target_service",
      "action",
      "outcome",
      "session_id",
      "correlation_id",
      "role_before",
      "role_after",
      "approval_id",
    ])
      C.text(event[field]);
    C.check(!ids.has(event.event_id), "DUPLICATE_EVENT");
    ids.add(event.event_id);
    const offset = number(event.source_clock_offset_ms);
    const uncertainty = C.integer(
      event.source_clock_uncertainty_ms === undefined
        ? uncertaintyDefault
        : number(event.source_clock_uncertainty_ms),
      0,
      3600000,
    );
    const corrected = time(event.event_time_utc) - offset;
    const received = time(event.received_time_utc);
    const uncertain =
      Math.abs(offset) > maxOffset ||
      corrected - uncertainty > received ||
      received - (corrected + uncertainty) > maxDelay;
    return {
      event,
      index,
      corrected_ms: corrected,
      received_ms: received,
      earliest_ms: corrected - uncertainty,
      latest_ms: corrected + uncertainty,
      offset_ms: offset,
      uncertainty_ms: uncertainty,
      uncertain,
      out_of_order: false,
      labels: [],
      alerts: [],
    };
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
  const suspiciousChanges = new Map();
  const groups = new Map();
  const alerts = [];
  function alert(rule, rows, explanation) {
    const support = [...new Set(rows.map((r) => r.event.event_id))];
    const at = Math.max(...rows.map((r) => r.received_ms));
    const result = {
      id: C.digest([rule, support]),
      rule,
      identity: rows[0].event.actor,
      services: [
        ...new Set(
          rows.flatMap((r) => [r.event.source_service, r.event.target_service]),
        ),
      ],
      events: support,
      detected_at_ms: at,
      explanation,
      uncertain_order:
        rows.some((r) => r.uncertain) ||
        rows.some((r, i) => i > 0 && rows[i - 1].latest_ms >= r.earliest_ms),
    };
    alerts.push(result);
    for (const row of rows) row.alerts.push(result.id);
    return result;
  }
  for (const row of observations) {
    const e = row.event;
    const session = C.canonical([e.actor, e.session_id]);
    if (row.uncertain) row.labels.push("timing_uncertain");
    if (row.out_of_order) row.labels.push("delayed_delivery");
    if (row.offset_ms !== 0) row.labels.push("clock_corrected");
    if (e.action === "role_change" && e.outcome === "success") {
      const a = changeMap.get(e.approval_id);
      const match =
        a &&
        a.operation === "grant_role" &&
        a.subject === e.actor &&
        a.role === e.role_after &&
        row.earliest_ms >= time(a.valid_from_utc) &&
        row.latest_ms < time(a.valid_until_utc);
      if (match && !row.uncertain) row.labels.push("approved_change");
      else {
        row.labels.push("unexpected_role_change");
        suspiciousChanges.set(session, row);
        alert(
          "unexpected_role_change",
          [row],
          "Successful role change has no matching subject, role and fully valid approval interval.",
        );
      }
    } else if (["read", "list_roles", "write", "transfer"].includes(e.action)) {
      const previous = suspiciousChanges.get(session);
      if (
        e.outcome === "allow" &&
        previous &&
        row.corrected_ms - previous.corrected_ms <= window &&
        row.latest_ms >= previous.earliest_ms
      ) {
        row.labels.push("review_after_role_change");
        alert(
          "access_after_role_change",
          [previous, row],
          "Allowed access follows an unexplained role change in the same identity/session.",
        );
      }
      const known = [e.actor, "*"].some((actor) =>
        [e.action, "*"].some((action) =>
          edgeSet.has(
            C.canonical([actor, e.source_service, e.target_service, action]),
          ),
        ),
      );
      if (!known) {
        if (e.outcome === "allow") {
          row.labels.push("unexpected_service_access");
          alert(
            "unexpected_service_access",
            [row],
            "Allowed service edge is absent from the operator-supplied baseline.",
          );
        }
        const id = C.canonical([e.actor, e.session_id, e.correlation_id]);
        const group = groups.get(id) || [];
        group.push(row);
        groups.set(id, group);
      }
      const approval = changeMap.get(e.approval_id);
      if (
        e.outcome === "allow" &&
        approval &&
        approval.operation === "grant_role"
      ) {
        const scoped =
          approval.subject === e.actor &&
          approval.role === e.role_after &&
          Array.isArray(approval.scope) &&
          approval.scope.includes(e.target_service) &&
          row.earliest_ms >= time(approval.valid_from_utc) &&
          row.latest_ms < time(approval.valid_until_utc);
        if (!scoped) {
          row.labels.push("approval_scope_violation");
          alert(
            "approval_scope_violation",
            [row],
            "Allowed access references a grant outside its subject, role, service scope or valid interval.",
          );
        }
      }
    }
  }
  for (const rows of groups.values()) {
    let start = 0;
    let incident = null;
    let incidentEnd = -Infinity;
    for (let end = 0; end < rows.length; end++) {
      while (rows[end].corrected_ms - rows[start].corrected_ms > window)
        start++;
      C.check(end - start + 1 <= sequenceCapacity, "SEQUENCE_CAPACITY");
      const span = rows.slice(start, end + 1);
      const edges = new Set(
        span.map((r) =>
          C.canonical([r.event.source_service, r.event.target_service]),
        ),
      );
      // Require connected service edges; unrelated denials do not become a lateral path by counting alone.
      const graph = new Map();
      for (const r of span) {
        const targets = graph.get(r.event.source_service) || [];
        targets.push(r.event.target_service);
        graph.set(r.event.source_service, targets);
      }
      const visited = new Set();
      const queue = [span[0].event.source_service];
      for (let i = 0; i < queue.length; i++) {
        const service = queue[i];
        if (visited.has(service)) continue;
        visited.add(service);
        queue.push(
          ...(graph.get(service) || []).filter(
            (target) => !visited.has(target),
          ),
        );
      }
      if (
        edges.size >= minEdges &&
        span.every((r) => visited.has(r.event.source_service))
      ) {
        const fresh = span.filter(
          (r) => !r.labels.includes("lateral_movement_candidate"),
        );
        if (fresh.length) {
          for (const r of span)
            if (!r.labels.includes("lateral_movement_candidate"))
              r.labels.push("lateral_movement_candidate");
          if (!incident || span[0].corrected_ms > incidentEnd + window)
            incident = alert(
              "lateral_movement_candidate",
              span,
              "Unexpected connected service edges under one identity/session/flow. Denied attempts are not evidence of successful compromise.",
            );
          else {
            incident.events = [
              ...new Set([
                ...incident.events,
                ...fresh.map((r) => r.event.event_id),
              ]),
            ];
            incident.services = [
              ...new Set([
                ...incident.services,
                ...fresh.flatMap((r) => [
                  r.event.source_service,
                  r.event.target_service,
                ]),
              ]),
            ];
            incident.uncertain_order ||= fresh.some((r) => r.uncertain);
            for (const r of fresh)
              if (!r.alerts.includes(incident.id)) r.alerts.push(incident.id);
          }
          incidentEnd = rows[end].corrected_ms;
          incident.last_observed_at_ms = Math.max(
            ...span.map((r) => r.received_ms),
          );
        }
      }
    }
  }
  for (const row of observations)
    if (!row.labels.length) row.labels.push("routine");
  return {
    version: 1,
    config_commitment: C.digest(config),
    approvals_commitment: C.digest(approvals),
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
      sequence_capacity: sequenceCapacity,
      max_offset_ms: maxOffset,
      max_lateness_ms: maxDelay,
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
module.exports = { csv, detect, score, estimateClock };
