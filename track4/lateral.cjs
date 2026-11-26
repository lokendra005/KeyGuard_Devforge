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
        successes: 0,
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
      a.successes += b.successes;
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
      a.successes -= Number(old.event.outcome === "success");
      a.pending.delete(old);
    }
    a.rows.set(key, row);
    a.pending.add(row);
    a.score += 1;
    a.successes += Number(e.outcome === "success");
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
module.exports = { Graph };
