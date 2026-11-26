"use strict";
const A = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const C = require("../crypto.cjs");
const root = path.resolve(__dirname, "../..");
const directory = fs.mkdtempSync(
  path.join(os.tmpdir(), "keyguard-walkthrough-"),
);
const actor = "owner-" + C.random().slice(0, 8),
  asset = "document-" + C.random().slice(0, 8),
  body = "Public demonstration resource; no operator data.";
function call(request) {
  const output = execFileSync(
    process.execPath,
    [path.join(root, "track4_service.cjs")],
    {
      env: { ...process.env, TRACK4_STATE_DIR: directory },
      input: JSON.stringify(request),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  return JSON.parse(output);
}
function show(action, result) {
  console.log(action + "\n" + JSON.stringify(result) + "\n");
}
try {
  console.log(
    "ACTUAL ADAPTER WALKTHROUGH | " +
      process.version +
      " | " +
      process.platform +
      "/" +
      process.arch,
  );
  const setup = {
    op: "setup",
    owners: { [asset]: actor },
    contents: { [asset]: body },
    key_material: C.random(),
  };
  show(
    "setup (fresh randomized identity/resource; disabled omitted)",
    call(setup),
  );
  const read = { op: "read", actor, asset, request_id: C.random() };
  const allowed = call(read);
  A.equal(allowed.body, body);
  show("read by current owner", allowed);
  const pair = C.c.generateKeyPairSync("ml-kem-768");
  const challenge = C.random();
  const request = {
    op: "protected_read",
    actor,
    asset,
    challenge,
    public_key: pair.publicKey
      .export({ format: "der", type: "spki" })
      .subarray(C.KEM_SPKI.length)
      .toString("base64"),
  };
  const result = call(request);
  const shared = C.c.decapsulate(
    pair.privateKey,
    C.b64(result.ciphertext, 1088),
  );
  const expected = C.c
    .createHmac("sha256", shared)
    .update(challenge + body)
    .digest("hex");
  shared.fill(0);
  A.equal(result.proof, expected);
  show("protected_read (real encapsulation and local decapsulation)", {
    ciphertext_bytes: C.b64(result.ciphertext).length,
    exact_hmac_verified: result.proof === expected,
  });
  A.equal(call(request).error, "REPLAY");
  show("repeat protected_read", { error: "REPLAY", process_exit: 0 });
  show("revoke owner", call({ op: "revoke", actor }));
  const denied = { ...read, request_id: C.random() };
  A.equal(call(denied).decision, "deny");
  show("read after revocation", call({ ...denied, request_id: C.random() }));
  show(
    "audit the denied request",
    call({ op: "audit", request_id: denied.request_id }),
  );
  show(
    "unknown actor revocation is a structured error",
    call({ op: "revoke", actor: C.random() }),
  );
  show(
    "second setup in the same worker state",
    call({
      ...setup,
      owners: { second: "new-owner" },
      contents: { second: "New scenario resource." },
    }),
  );
  const old = call({ ...read, request_id: C.random() });
  A.equal(old.decision, "deny");
  show("old scenario is inaccessible", old);
  const fresh = call({
    op: "read",
    actor: "new-owner",
    asset: "second",
    request_id: C.random(),
  });
  A.equal(fresh.body, "New scenario resource.");
  show("new scenario's owner can read", fresh);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
