"use strict";
const C = require("./crypto.cjs");

function csv(raw) {
  C.text(raw, 64 * 1024 * 1024);
  // Spreadsheet/PowerShell exports start with a UTF-8 byte-order mark.
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
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
  // Blank lines (for example trailing newlines) carry no record.
  const records = rows.filter((r) => !(r.length === 1 && r[0] === ""));
  C.check(records.length > 0, "INVALID_CSV");
  // Header names are matched case-insensitively and without surrounding spaces.
  const headers = records.shift().map((h) => h.trim().toLowerCase());
  C.check(
    new Set(headers).size === headers.length && headers.every((x) => x.length),
    "INVALID_CSV",
  );
  return records.map((values) => {
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
      (+second < 60 || (+second === 60 && +minute === 59)) &&
      (/^[Zz]$/.test(zone) || (+zone.slice(1, 3) <= 23 && +zone.slice(4) < 60)),
    "INVALID_TIME",
  );
  // An RFC 3339 leap second (hh:59:60 local) is held at the last millisecond of that minute.
  const normalized =
    +second === 60
      ? `${year}-${month}-${day}T${hour}:${minute}:59.999${zone.toUpperCase()}`
      : `${year}-${month}-${day}T${hour}:${minute}:${second}.${(fraction || "").padEnd(3, "0").slice(0, 3)}${zone.toUpperCase()}`;
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
      "permitted",
      "ok",
      "completed",
      "complete",
      "authorized",
      "authorised",
      "approved",
      "accepted",
      "pass",
      "passed",
    ].map((x) => [x, "success"]),
    ...[
      "deny",
      "denied",
      "failure",
      "failed",
      "blocked",
      "rejected",
      "error",
      "fail",
      "unauthorized",
      "unauthorised",
      "forbidden",
      "declined",
      "refused",
    ].map((x) => [x, "failure"]),
  ]),
);
// Who/where a quarantined record claims to describe, so quarantine is reported, never silent.
function brief(event) {
  const text = (v) => (typeof v === "string" && v.length ? v : null);
  if (!event || typeof event !== "object") return {};
  return {
    actor: text(event.actor),
    services: [text(event.source_service), text(event.target_service)].filter(Boolean),
  };
}
// Identical redelivery is dropped. A conflicting copy throws unless `rejected` is supplied;
// then the first copy is analysed and later conflicting copies are quarantined.
function unique(events, rejected) {
  const seen = new Map();
  return events.filter((event, index) => {
    let content, id;
    try {
      C.object(event);
      id = C.text(event.event_id);
      content = C.digest(event);
    } catch (error) {
      if (!rejected) throw error;
      rejected.push({ index, event_id: null, reason: error.code || "INVALID_EVENT", ...brief(event) });
      return false;
    }
    const previous = seen.get(id);
    if (previous !== undefined && previous !== content) {
      if (rejected) {
        rejected.push({ index, event_id: id, reason: "conflicting_duplicate", ...brief(event) });
        return false;
      }
      const error = new C.Fault("DUPLICATE_EVENT");
      error.label = "conflicting_duplicate";
      error.event_id = id;
      throw error;
    }
    seen.set(id, content);
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
    // Missing receipt time is weaker than contradictory timing: ordering can still be proven from event time.
    receipt_missing_only:
      event.received_time_utc === undefined &&
      Math.abs(offset) <= (config.max_offset_ms ?? 300000),
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
  const rejected = [];
  reference = unique(reference, options.strict_input ? undefined : rejected);
  for (let i = 0; i < reference.length; i++) {
    let r;
    try {
      r = normalize(reference[i], i, options);
    } catch (error) {
      if (options.strict_input) throw error;
      rejected.push({ index: i, event_id: reference[i].event_id, reason: error.code || "INVALID_EVENT" });
      continue;
    }
    const e = r.event;
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
    ...(rejected.length ? { rejected } : {}),
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
  const strict = config.strict_input === true;
  const adminWindow = C.integer(config.approval_admin_window_ms ?? 30000, 0, 3600000);
  const changeMap = new Map(),
    revokedRoles = new Map(),
    rejected = [],
    rejectedApprovals = [];
  // A malformed or conflicting approval authorizes nothing; events citing it are treated as unapproved.
  for (const change of changes) {
    let id;
    try {
      C.object(change);
      id = C.text(change.approval_id);
      const previous = changeMap.get(id);
      if (previous) {
        C.check(!strict, "DUPLICATE_APPROVAL");
        if (previous.digest !== C.digest(change)) {
          changeMap.set(id, { approval_id: id, invalid: true, digest: previous.digest });
          rejectedApprovals.push({ approval_id: id, reason: "conflicting_duplicate" });
        }
        continue;
      }
      const a = { ...change, digest: C.digest(change) };
      if (a.operation === "grant_role") {
        for (const f of ["subject", "role", "approved_by"]) C.text(a[f]);
        a.from_ms = time(a.valid_from_utc);
        a.until_ms = time(a.valid_until_utc);
        if (a.scope !== undefined)
          C.check(Array.isArray(a.scope) && a.scope.every((s) => typeof s === "string"), "INVALID_APPROVAL");
      } else if (a.operation === "revoke_role") {
        for (const f of ["subject", "role"]) C.text(a[f]);
        a.effective_ms = time(a.effective_at_utc);
        const key = C.canonical([a.subject, a.role]);
        const times = revokedRoles.get(key) || [];
        times.push(a.effective_ms);
        revokedRoles.set(key, times);
      }
      changeMap.set(id, a);
    } catch (error) {
      if (strict) throw error;
      if (id !== undefined && !changeMap.has(id))
        changeMap.set(id, { approval_id: id, invalid: true });
      rejectedApprovals.push({ approval_id: id ?? null, reason: error.code || "INVALID_APPROVAL" });
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
  // One malformed, conflicting or baseline-overlapping record is quarantined, not fatal.
  // Only a holdout that overlaps the baseline entirely is refused as label leakage.
  const kept = unique(events, strict ? undefined : rejected);
  let overlapping = 0;
  const observations = [];
  kept.forEach((event, index) => {
    try {
      const row = normalize(event, index, config);
      if (baseline && row.corrected_ms <= baseline.reference_end_ms) {
        overlapping++;
        C.check(!strict, "BASELINE_HOLDOUT_OVERLAP");
        rejected.push({ index, event_id: event.event_id, reason: "BASELINE_HOLDOUT_OVERLAP", ...brief(event) });
        return;
      }
      observations.push(row);
    } catch (error) {
      if (strict) throw error;
      if (error.code !== "BASELINE_HOLDOUT_OVERLAP")
        rejected.push({ index, event_id: event.event_id, reason: error.code || "INVALID_EVENT", ...brief(event) });
    }
  });
  C.check(!overlapping || observations.length > 0, "BASELINE_HOLDOUT_OVERLAP");
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
      identities: [...new Set(rows.map((r) => r.event.actor))],
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
      !a.invalid &&
      a.operation === "grant_role" &&
      typeof a.approved_by === "string" &&
      a.approved_by.length > 0 &&
      a.subject === e.actor &&
      a.approved_by !== a.subject &&
      (!e.approved_by || e.approved_by !== e.actor) &&
      a.role === e.role_after &&
      row.earliest_ms >= a.from_ms &&
      row.latest_ms < a.until_ms &&
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
    if (e.outcome === "unknown") row.labels.push("unknown_outcome");
    // An administration event names its target in `subject`; without one, only an explicit
    // identity_state_after describes the actor itself. Never revoke the operator by default.
    const selfRevoked = ["revoked", "disabled"].includes(e.identity_state_after);
    const isRevocation =
      selfRevoked ||
      (
        config.revocation_actions || ["revoke", "revoke_key", "disable_user"]
      ).includes(e.action);
    if (successful && isRevocation) {
      const target = e.subject || (selfRevoked ? e.actor : "");
      if (target) revoked.set(target, row);
      row.labels.push(target ? "revocation_observed" : "revocation_without_subject");
      continue;
    }
    const reinstated = ["active", "enabled"].includes(e.identity_state_after);
    if (
      successful &&
      (reinstated ||
        (
          config.reinstate_actions || ["enable_user", "reinstate", "restore_user"]
        ).includes(e.action))
    ) {
      const target = e.subject || (reinstated ? e.actor : "");
      if (target && revoked.delete(target)) row.labels.push("reinstatement_observed");
    }
    const a = changeMap.get(e.approval_id);
    if (
      successful &&
      ((a && !a.invalid && a.approved_by && a.approved_by === a.subject) ||
        (e.approved_by && e.approved_by === e.actor))
    ) {
      row.labels.push("self_approval");
      alert(
        "self_approval",
        [row],
        "The beneficiary approved their own successful change or access.",
      );
    }
    // An unrecognized outcome on a role transition fails closed: it is evaluated as if it succeeded.
    if ((successful || e.outcome === "unknown") && e.role_before !== e.role_after) {
      const approvedRemoval =
        a &&
        !a.invalid &&
        a.operation === "revoke_role" &&
        a.subject === e.actor &&
        a.approved_by &&
        a.approved_by !== a.subject &&
        a.role === e.role_before &&
        row.earliest_ms >= a.effective_ms;
      if ((scoped(a, row, true) || approvedRemoval) && !row.uncertain) {
        row.labels.push("approved_change");
        suspiciousChanges.delete(actor);
        if (!approvedRemoval)
          roleGrants.set(C.canonical([e.actor, e.role_after]), {
            at: row.earliest_ms,
            until: a.until_ms,
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
    // The approver issuing an approval (at its valid_from) or revocation (at its effective time) is not
    // its beneficiary. Citing it at any other time, e.g. on the approver's own access, stays a violation.
    const issuedAt = a && (a.operation === "revoke_role" ? a.effective_ms : a.from_ms);
    if (
      successful &&
      a &&
      !a.invalid &&
      a.approved_by === e.actor &&
      a.subject !== e.actor &&
      Number.isSafeInteger(issuedAt) &&
      row.earliest_ms <= issuedAt + adminWindow &&
      row.latest_ms >= issuedAt - adminWindow
    )
      row.labels.push("approval_administration");
    else if (successful && a && !scoped(a, row)) {
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
      (scoped(a, row) && a.from_ms > revokedAt);
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
  const crossWindow = C.integer(
    config.cross_identity_window_ms ?? 300000,
    0,
    3600000,
  );
  const { witnesses, cross } = pivots(movementRows, window, crossWindow);
  const crossIncidents = new Map();
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
        const result = alert(
          "lateral_movement_candidate",
          rows,
          "Actor-wide connected unusual service edges across sessions satisfy the configured distinct-edge count and decayed score. Evidence grows within an incident; detected_at_ms is its first signal.",
          scoreMilli,
        );
        qualifying.alert = {
          result,
          evidenceIDs: new Set(result.events),
          services: new Set(result.services),
          sessions: new Set(result.sessions),
        };
        for (const r of rows) r.incident = qualifying.alert;
      } else {
        const incident = qualifying.alert,
          result = incident.result;
        for (const r of pending) {
          r.incident = incident;
          if (!incident.evidenceIDs.has(r.event.event_id)) {
            result.events.push(r.event.event_id);
            incident.evidenceIDs.add(r.event.event_id);
          }
          for (const service of [
            r.event.source_service,
            r.event.target_service,
          ])
            if (!incident.services.has(service)) {
              incident.services.add(service);
              result.services.push(service);
            }
          if (
            r.event.session_id &&
            !incident.sessions.has(r.event.session_id)
          ) {
            incident.sessions.add(r.event.session_id);
            result.sessions.push(r.event.session_id);
          }
          if (!r.alerts.includes(result.id)) r.alerts.push(result.id);
          r.first_alert_at_ms = Math.min(
            r.first_alert_at_ms ?? Infinity,
            Math.max(result.detected_at_ms, r.received_ms),
          );
          result.uncertain_order ||= r.uncertain || r.out_of_order;
        }
        result.decayed_score_milli = Math.max(
          result.decayed_score_milli,
          scoreMilli,
        );
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
    } else if (cross.has(row.event.event_id)) {
      const pair = cross.get(row.event.event_id);
      for (const r of pair)
        if (!r.labels.includes("lateral_movement_candidate"))
          r.labels.push("lateral_movement_candidate");
      // One incident per pivot service B while hops keep arriving within the cross window.
      const pivot = row.event.source_service,
        open = crossIncidents.get(pivot);
      if (open && row.corrected_ms - open.at <= crossWindow) {
        open.at = row.corrected_ms;
        for (const r of pair) {
          if (!open.result.events.includes(r.event.event_id))
            open.result.events.push(r.event.event_id);
          if (!open.result.identities.includes(r.event.actor))
            open.result.identities.push(r.event.actor);
          for (const service of [r.event.source_service, r.event.target_service])
            if (!open.result.services.includes(service))
              open.result.services.push(service);
          if (!r.alerts.includes(open.result.id)) r.alerts.push(open.result.id);
          r.first_alert_at_ms = Math.min(
            r.first_alert_at_ms ?? Infinity,
            Math.max(open.result.detected_at_ms, r.received_ms),
          );
        }
        continue;
      }
      const result = alert(
        "cross_identity_lateral_candidate",
        pair,
        "Two successful unusual hops A -> B -> C under different identities: an identity reaches B, then another identity leaves B for a third service within cross_identity_window_ms. Consistent with credential hopping; all identities are named.",
      );
      crossIncidents.set(pivot, { result, at: row.corrected_ms });
    }
  }
  // Quarantine is loud: a conflicting copy alerts on the analysed copy (a decoy can hide the real
  // record), and every other quarantined record joins one input_integrity alert per reason.
  const analysed = new Map(observations.map((r) => [r.event.event_id, r])),
    integrity = new Map();
  for (const r of rejected) {
    const row = r.reason === "conflicting_duplicate" && analysed.get(r.event_id);
    if (row) {
      if (!row.labels.includes("conflicting_event_record")) row.labels.push("conflicting_event_record");
      const result = alert(
        "conflicting_event_record",
        [row],
        "Different records share this event_id. The first copy was analysed and the conflicting copy quarantined; a decoy copy can hide the real record, so both need review.",
      );
      for (const x of [r.actor, ...(r.services || [])].filter(Boolean))
        if (x === r.actor ? !result.identities.includes(x) : !result.services.includes(x))
          (x === r.actor ? result.identities : result.services).push(x);
      continue;
    }
    const list = integrity.get(r.reason) || [];
    list.push(r);
    integrity.set(r.reason, list);
  }
  for (const [reason, list] of integrity) {
    const ids = [...new Set(list.map((r) => r.event_id).filter((id) => id !== null))];
    const identities = [...new Set(list.map((r) => r.actor).filter(Boolean))];
    alerts.push({
      id: C.digest(["input_integrity", reason, ids, list.length]),
      rule: "input_integrity",
      reason,
      identity: identities[0] ?? null,
      identities,
      services: [...new Set(list.flatMap((r) => r.services || []))],
      events: ids,
      sessions: [],
      detected_at_ms: null,
      explanation: `${list.length} record(s) were quarantined (${reason}) and not evaluated by the behavioural rules. Malformed, backdated or out-of-window records can hide activity; review them.`,
      uncertain_order: true,
    });
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
    events: observations.map(({ index, incident, receipt_missing_only, ...row }) => row),
    alerts,
    counts: {
      events: observations.length,
      alerts: alerts.length,
      uncertain: observations.filter((r) => r.uncertain).length,
      out_of_order: observations.filter((r) => r.out_of_order).length,
      unknown_outcome: observations.filter((r) => r.event.outcome === "unknown")
        .length,
      rejected: rejected.length,
      rejected_approvals: rejectedApprovals.length,
    },
    rejected,
    rejected_approvals: rejectedApprovals,
    limits: {
      window_ms: window,
      half_life_ms: halfLife,
      lateral_score_milli: minScore,
      max_offset_ms: maxOffset,
      max_lateness_ms: maxDelay,
      max_events: 100000,
      timestamp_precision:
        "milliseconds; fractional digits beyond three are truncated; timezone required; a leap second (:59:60) is held at :59.999",
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
  // A quarantined record counts as alerted only if an integrity alert names it.
  const quarantined = new Set(
    (report.rejected || []).map((r) => r.event_id).filter((id) => id !== null),
  );
  for (const r of report.events) quarantined.delete(r.event.event_id);
  C.check(
    truth.size === labels.length &&
      truth.size === report.events.length + quarantined.size &&
      report.events.every((r) => truth.has(r.event.event_id)) &&
      [...quarantined].every((id) => truth.has(id)),
    "LABEL_MISMATCH",
  );
  let tp = 0,
    fp = 0,
    fn = 0,
    tn = 0;
  const named = new Set(report.alerts.flatMap((a) => a.events));
  for (const id of quarantined)
    if (named.has(id)) truth.get(id) ? tp++ : fp++;
    else truth.get(id) ? fn++ : tn++;
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
