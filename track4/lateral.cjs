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
  insert(key, row) {
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
      // A bridge between already reported components creates a new combined incident.
      if (b.alert) {
        a.alert = undefined;
        for (const r of a.rows.values()) a.pending.add(r);
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
    a.pending.add(row);
    a.score += 1;
    return a;
  }
  add(row) {
    const now = row.corrected_ms;
    let expired = false;
    while (
      this.head < this.queue.length &&
      now - this.queue[this.head].row.corrected_ms > this.window
    ) {
      const { key, row: r } = this.queue[this.head++];
      if (this.edges.get(key) === r) {
        this.edges.delete(key);
        expired = true;
      }
    }
    if (expired) {
      this.nodes.clear();
      for (const [key, r] of [...this.edges].sort(
        (a, b) => a[1].corrected_ms - b[1].corrected_ms,
      ))
        this.insert(key, r);
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
function pivots(rows, window) {
  const eligible = rows.filter(
    (r) =>
      r.event.outcome === "success" &&
      !r.uncertain &&
      r.event.source_service !== r.event.target_service,
  );
  const ended = [...eligible].sort((a, b) => a.latest_ms - b.latest_ms);
  const incoming = new Map(),
    witnesses = new Map();
  let next = 0;
  for (const row of [...eligible].sort(
    (a, b) => a.earliest_ms - b.earliest_ms,
  )) {
    while (next < ended.length && ended[next].latest_ms < row.earliest_ms) {
      const prior = ended[next++],
        e = prior.event;
      const key = C.canonical([e.actor, e.target_service]);
      const best = incoming.get(key) || [];
      // Only one origin is forbidden by a query; the newest two distinct origins suffice.
      const choices = [...best, prior].sort(
        (a, b) => b.corrected_ms - a.corrected_ms,
      );
      const distinct = choices.filter(
        (r, i) =>
          choices.findIndex(
            (p) => p.event.source_service === r.event.source_service,
          ) === i,
      );
      incoming.set(key, distinct.slice(0, 2));
    }
    const e = row.event;
    const prior = (
      incoming.get(C.canonical([e.actor, e.source_service])) || []
    ).find((r) => r.event.source_service !== e.target_service);
    if (prior && row.corrected_ms - prior.corrected_ms <= window)
      witnesses.set(e.event_id, [prior, row]);
  }
  return witnesses;
}
module.exports = { Graph, pivots };
