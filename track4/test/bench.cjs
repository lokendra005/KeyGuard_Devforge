"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const C = require("../crypto.cjs");
const { Store } = require("../store.cjs");
const S = require("../service.cjs");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "kig-bench-"));
const store = new Store({ directory });
try {
  const actor = C.random(),
    asset = C.random(),
    key = C.generate();
  S.execute(
    store,
    {
      op: "setup",
      owners: { [asset]: actor },
      contents: { [asset]: C.random().repeat(22) },
      disabled: [],
      key_material: C.random(),
      identities: [{ actor, role: "user", public_key: key.public_key }],
    },
    { trusted: true },
  );
  const kem = C.c.generateKeyPairSync("ml-kem-768");
  const public_key = kem.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(C.KEM_SPKI.length)
    .toString("base64");
  const report = {
    node: process.version,
    architecture: process.arch,
    platform: process.platform,
    samples: 40,
    units: "milliseconds",
    measurements: {},
  };
  for (const op of ["read", "protected_read"]) {
    const elapsed = [];
    for (let i = 0; i < report.samples; i++) {
      const body =
        op === "read"
          ? { op, actor, asset, request_id: C.random() }
          : { op, actor, asset, challenge: C.random(), public_key };
      const start = process.hrtime.bigint();
      S.execute(store, S.command(key, S.info(store, actor), body));
      elapsed.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    elapsed.sort((a, b) => a - b);
    report.measurements[op] = {
      median: (elapsed[19] + elapsed[20]) / 2,
      p95: elapsed[37],
      max: elapsed[39],
    };
  }
  report.max_rss_kib = process.resourceUsage().maxRSS;
  report.scope =
    "Single-process, signed-command core including signature verification, crypto, SQLite commit and signed audit; excludes HTTP/process startup. Local filesystem/cache conditions apply.";
  console.log(JSON.stringify(report, null, 2));
} finally {
  store.close();
  fs.rmSync(directory, { recursive: true, force: true });
}
