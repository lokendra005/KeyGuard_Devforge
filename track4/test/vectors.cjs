"use strict";
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const A = require("node:assert/strict");
const C = require("../crypto.cjs");
const [major, minor] = process.versions.node.split(".").map(Number);
C.check(
  major > 24 || (major === 24 && minor >= 8),
  "NODE_CONTEXT_SUPPORT_REQUIRED",
);
const corpus = JSON.parse(
  zlib.gunzipSync(
    fs.readFileSync(
      path.resolve(
        __dirname,
        "../../internal/guard/testdata/crypto-vectors.json.gz",
      ),
    ),
  ),
);
const prefix = Buffer.from(
  "308207b2300b0609608648016503040312038207a100",
  "hex",
);
let valid = 0,
  invalid = 0;
for (const test of corpus.verify) {
  let accepted = false;
  try {
    const key = C.publicKey(
      Buffer.concat([prefix, Buffer.from(test.pk, "hex")]).toString("base64"),
    );
    const signature = C.b64(
      Buffer.from(test.sig, "hex").toString("base64"),
      3309,
    );
    accepted = C.c.verify(
      null,
      Buffer.from(test.msg, "hex"),
      { key, context: Buffer.from(test.ctx, "hex") },
      signature,
    );
  } catch {
    accepted = false;
  }
  A.equal(accepted, test.valid, test.id);
  if (test.valid) valid++;
  else invalid++;
}
A.equal(corpus.verify.length, 225);
A.equal(valid, 82);
A.equal(invalid, 143);
console.log(
  `PASS: Node ${process.version} / OpenSSL ${process.versions.openssl}; 225 independent NIST/Wycheproof ML-DSA-65 verification vectors (${valid} valid, ${invalid} invalid), including native context handling and canonical key/length validation.`,
);
