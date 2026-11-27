"use strict";
const fs = require("node:fs");
const C = require("./track4/crypto.cjs");
const { Store } = require("./track4/store.cjs");
const { execute } = require("./track4/service.cjs");
let store, request;
try {
  const chunks = [];
  let size = 0;
  const buffer = Buffer.alloc(65536);
  for (;;) {
    const n = fs.readSync(0, buffer, 0, buffer.length, null);
    if (!n) break;
    size += n;
    C.check(size <= 16 * 1024 * 1024, "INPUT_TOO_LARGE");
    chunks.push(Buffer.from(buffer.subarray(0, n)));
  }
  request = C.object(C.parse(Buffer.concat(chunks)));
  store = new Store();
  // This local worker boundary is trusted. Network callers must use signed commands.
  const result = execute(store, request, {
    trusted: true,
    resetScenario: request.op === "setup",
  });
  process.stdout.write(C.canonical(result) + "\n");
} catch (error) {
  const code = error instanceof C.Fault ? error.code : "REQUEST_FAILED";
  // Reads and audits fail closed in the contract's own shape: a denied decision, never content.
  const op = request && request.op;
  const shaped =
    op === "read" || op === "protected_read"
      ? { decision: "deny", error: code }
      : op === "audit"
        ? {
            ...(typeof request.request_id === "string" ? { request_id: request.request_id } : {}),
            decision: "deny",
            recorded: false,
            error: code,
          }
        : { error: code };
  process.stdout.write(JSON.stringify(shaped) + "\n");
  process.exitCode =
    error instanceof C.Fault ||
    error instanceof SyntaxError ||
    error instanceof TypeError
      ? 0
      : 1;
} finally {
  if (store) store.close();
}
