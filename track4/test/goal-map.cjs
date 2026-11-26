"use strict";
const fs = require("node:fs");
const path = require("node:path");
const goals = [
  [
    "1 Rotation / transfer continuity",
    "review.test.cjs",
    "partial transfers survive receiver rotation",
  ],
  [
    "2 Revocation across independent nodes",
    "replica.test.cjs",
    "five independent processes enforce revocation",
  ],
  ["3 Crash recovery", "core.test.cjs", "SIGKILL"],
  ["4 Backup integrity", "core.test.cjs", "backup"],
  ["5 Log integrity", "core.test.cjs", "signed audit rejects edits"],
  [
    "6 Routine vs suspicious activity",
    "detect-holdout.test.cjs",
    "frozen reference baseline",
  ],
  ["7 Lateral movement", "detect-holdout.test.cjs", "70s paths"],
  [
    "8 Clock differences / late events",
    "detect.test.cjs",
    "clock normalization",
  ],
  [
    "9 Replay and recipient binding",
    "messaging.test.cjs",
    "recipient, sender, suite",
  ],
  ["10 Forward secrecy", "messaging.test.cjs", "ephemeral"],
  ["11 Loss and reordering", "messaging.test.cjs", "bounded loss recovery"],
];
for (const [goal, file, evidence] of goals) {
  if (!fs.readFileSync(path.join(__dirname, file), "utf8").includes(evidence))
    throw Error("Missing goal evidence: " + goal);
  console.log(goal + " -> track4/test/" + file);
}
console.log(
  "12 Session resumption -> intentionally unsupported; restart invalidates ephemeral receiver state and requires a fresh offer. This is a limitation, not a passing resumption test.",
);
