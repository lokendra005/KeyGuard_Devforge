"use strict";
// Optional comparison against a separately retained, trusted earlier checkout; not a runtime dependency.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  A = require("node:assert/strict"),
  D = require("../detect.cjs");
A.ok(
  process.argv[2],
  "Usage: node track4/test/detector-comparison.cjs /path/to/earlier-checkout",
);
const beforeRoot = path.resolve(process.argv[2]),
  old = require(path.join(beforeRoot, "track4/detect.cjs"));
const root = path.resolve(__dirname, "../.."),
  comparisons = [];
const files = [
  "track4/detect.cjs",
  "track4/lateral.cjs",
  "track4/test/detector-benchmark.cjs",
  "track4/test/detector-topology-benchmark.cjs",
];
for (const file of files.slice(2))
  A.deepEqual(
    fs.readFileSync(path.join(root, file)),
    fs.readFileSync(path.join(beforeRoot, file)),
    "Generator changed: " + file,
  );
for (const [name, file, seeds, positive] of [
  [
    "original",
    "./detector-benchmark.cjs",
    [20261127, 987654321, 1, 17, 89, 613, 2027, 65537, 314159, 2147483647],
    "attack",
  ],
  [
    "independent_topology",
    "./detector-topology-benchmark.cjs",
    [314159, 1, 17, 89, 613, 2027, 65537, 20261127, 987654321, 2147483647],
    "intrusion",
  ],
]) {
  const generator = require(file);
  for (const seed of seeds) {
    const data = generator.generate(seed),
      config = { ...data.config, baseline: D.learn(data.reference) };
    const before = old.detect(data.events, data.approvals, config),
      after = D.detect(data.events, data.approvals, config);
    const flags = new Set(
      after.events.filter((r) => r.alerts.length).map((r) => r.event.event_id),
    );
    const truth = new Set(
      data.labels.filter((r) => r.label === positive).map((r) => r.event_id),
    );
    const lost = before.events
      .filter(
        (r) =>
          r.alerts.length &&
          truth.has(r.event.event_id) &&
          !flags.has(r.event.event_id),
      )
      .map((r) => r.event.event_id);
    const a = D.score(before, data.labels, [positive]),
      b = D.score(after, data.labels, [positive]);
    A.equal(
      lost.length,
      0,
      "Previously detected attack lost: " + name + "/" + seed,
    );
    A.ok(b.fp <= a.fp, "False positives increased: " + name + "/" + seed);
    comparisons.push({
      generator: name,
      seed,
      before: a,
      after: b,
      previously_detected_attack_events_lost: lost,
    });
  }
}
const hash = (base, f) =>
  crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(base, f)))
    .digest("hex");
console.log(
  JSON.stringify(
    {
      algorithm:
        "Directed interval-ordered two-hop witnesses plus actor-specific familiarity certified only by prior trusted-baseline success; unchanged graph window, decay and thresholds.",
      generators_unchanged: true,
      before_source_sha256: Object.fromEntries(
        files.map((f) => [f, hash(beforeRoot, f)]),
      ),
      source_sha256: Object.fromEntries(files.map((f) => [f, hash(root, f)])),
      comparisons,
      limitations:
        "Synthetic event labels are used only for evaluation. Zero observed lost positives does not prove universal recall preservation. Three-edge ambiguous fan-out remains alertable; two-edge spokes and temporally ambiguous pivots no longer invoke the two-hop shortcut.",
    },
    null,
    2,
  ),
);
