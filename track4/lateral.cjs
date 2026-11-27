"use strict";
// Sliding undirected components. Union by size avoids rebuilding a growing fan-out on every edge.
const C = require("./crypto.cjs");
class Graph {
  constructor(window, halfLife) {
    this.window = window;
    this.halfLife = halfLife;
    this.edges = new Map();
    this.nodes = new Map();
    this.queue = [];
    this.head = 0;
  }
  root(vertex) {
    let n = this.nodes.get(vertex);
    if (!n) {
      n = {
        rows: new Map(),
        pending: new Set(),
        score: 0,
        at: 0,
      };
      this.nodes.set(vertex, n);
    }
    let r = n;
    while (r.parent) r = r.parent;
    while (n.parent) {
      const next = n.parent;
      n.parent = r;
      n = next;
    }
    return r;
  }
  decay(component, now) {
    component.score *= 2 ** (-(now - component.at) / this.halfLife);
    component.at = now;
  }
  // Incident state lives on rows (row.incident) so a rebuild after expiry or a merge of
  // components extends the existing alert instead of opening a new one per event.
  insert(key, row, rebuilding = false) {
    const now = row.corrected_ms,
      e = row.event;
    let a = this.root(e.source_service),
      b = this.root(e.target_service);
    this.decay(a, now);
    if (a !== b) {
      this.decay(b, now);
      if (a.rows.size < b.rows.size) [a, b] = [b, a];
      b.parent = a;
      for (const [k, r] of b.rows) a.rows.set(k, r);
      for (const r of b.pending) a.pending.add(r);
      a.score += b.score;
      // A bridge into a reported component joins that incident; unreported rows become its new evidence.
      if (b.alert && b.alert !== a.alert) {
        const absorbed = a.alert ? b.rows.values() : a.rows.values();
        a.alert ??= b.alert;
        if (!rebuilding)
          for (const r of absorbed) if (r.incident !== a.alert) a.pending.add(r);
      }
      b.rows.clear();
      b.pending.clear();
    }
    const old = a.rows.get(key);
    if (old) {
      a.score -= 2 ** (-(now - old.corrected_ms) / this.halfLife);
      a.pending.delete(old);
    }
    a.rows.set(key, row);
    if (row.incident) a.alert ??= row.incident;
    if (!(rebuilding && row.incident)) a.pending.add(row);
    a.score += 1;
    return a;
  }
  add(row) {
    const now = row.corrected_ms;
    let expired = 0;
    while (
      this.head < this.queue.length &&
      now - this.queue[this.head].row.corrected_ms > this.window
    ) {
      const { key, row: r } = this.queue[this.head++];
      if (this.edges.get(key) === r) {
        this.edges.delete(key);
        expired++;
      }
    }
    this.stale = (this.stale || 0) + expired;
    // ponytail: exact rebuild per expiry is O(live edges). Above 512 live edges per actor (already a
    // large incident) rebuild once stale edges reach 1/8 of live ones, so components may briefly keep
    // up to 12.5% expired edges; an exact decremental-connectivity structure is the upgrade path.
    if (
      this.stale &&
      (this.edges.size < 512 || this.stale * 8 >= this.edges.size)
    ) {
      this.stale = 0;
      this.nodes.clear();
      for (const [key, r] of [...this.edges].sort(
        (a, b) => a[1].corrected_ms - b[1].corrected_ms,
      ))
        this.insert(key, r, true);
    }
    if (this.head > 4096 && this.head > this.queue.length / 2) {
      this.queue = this.queue.slice(this.head);
      this.head = 0;
    }
    const key = C.canonical(
      [row.event.source_service, row.event.target_service].sort(),
    );
    this.edges.set(key, row);
    this.queue.push({ key, row });
    return this.insert(key, row);
  }
}
// A -> B -> C requires two successful, temporally ordered edges, not two spokes.
// Rows lacking only a receipt time qualify; contradictory timing never does.
// Cross-identity: hop 2 leaves B under a different identity within crossWindow (credential hopping).
function pivots(rows, window, crossWindow = 0) {
  const eligible = rows.filter(
    (r) =>
      r.event.outcome === "success" &&
      (!r.uncertain || r.receipt_missing_only === true) &&
      r.event.source_service !== r.event.target_service,
  );
  const ended = [...eligible].sort((a, b) => a.latest_ms - b.latest_ms);
  const incoming = new Map(),
    arrivals = new Map(),
    witnesses = new Map(),
    cross = new Map();
  // Keep the newest two candidates that differ in `field`; one may be excluded by the query.
  const keep = (map, key, prior, field) => {
    const choices = [...(map.get(key) || []), prior].sort(
      (a, b) => b.corrected_ms - a.corrected_ms,
    );
    map.set(
      key,
      choices
        .filter(
          (r, i) => choices.findIndex((p) => field(p) === field(r)) === i,
        )
        .slice(0, 2),
    );
  };
  let next = 0;
  for (const row of [...eligible].sort(
    (a, b) => a.earliest_ms - b.earliest_ms,
  )) {
    while (next < ended.length && ended[next].latest_ms < row.earliest_ms) {
      const prior = ended[next++],
        e = prior.event;
      keep(incoming, C.canonical([e.actor, e.target_service]), prior, (r) => r.event.source_service);
      if (crossWindow) keep(arrivals, e.target_service, prior, (r) => r.event.actor);
    }
    const e = row.event;
    const prior = (
      incoming.get(C.canonical([e.actor, e.source_service])) || []
    ).find((r) => r.event.source_service !== e.target_service);
    if (prior && row.corrected_ms - prior.corrected_ms <= window)
      witnesses.set(e.event_id, [prior, row]);
    else if (crossWindow) {
      const other = (arrivals.get(e.source_service) || []).find(
        (r) =>
          r.event.actor !== e.actor &&
          r.event.source_service !== e.target_service &&
          row.corrected_ms - r.corrected_ms <= crossWindow,
      );
      if (other) cross.set(e.event_id, [other, row]);
    }
  }
  return { witnesses, cross };
}
module.exports = { Graph, pivots };
