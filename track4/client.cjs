"use strict";
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const C = require("./crypto.cjs");
const { command } = require("./service.cjs");
function client(base, identity, actor, ca) {
  const origin = new URL(base);
  C.check(
    ["http:", "https:"].includes(origin.protocol) &&
      !origin.username &&
      !origin.password,
    "INVALID_URL",
  );
  C.check(
    origin.protocol === "https:" ||
      ["127.0.0.1", "[::1]", "localhost"].includes(origin.hostname),
    "TLS_REQUIRED",
  );
  async function request(route, body) {
    const data = body === undefined ? undefined : C.canonical(body);
    return new Promise((resolve, reject) => {
      const r = (origin.protocol === "https:" ? https : http).request(
        new URL(route, origin),
        {
          method: data ? "POST" : "GET",
          ca: ca ? fs.readFileSync(ca) : undefined,
          headers: data
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
              }
            : {},
        },
        (response) => {
          const chunks = [];
          let size = 0;
          response.on("data", (b) => {
            size += b.length;
            if (size > 16 * 1024 * 1024)
              response.destroy(new C.Fault("RESPONSE_CAPACITY"));
            else chunks.push(b);
          });
          response.on("error", reject);
          response.on("end", () => {
            try {
              const result = C.parse(Buffer.concat(chunks));
              if (response.statusCode !== 200) {
                const error = new C.Fault(result.error || "REMOTE_FAILURE");
                if (result.label === "conflicting_duplicate") {
                  error.label = result.label;
                  error.event_id = result.event_id;
                }
                throw error;
              }
              resolve(result);
            } catch (e) {
              reject(e);
            }
          });
        },
      );
      r.setTimeout(8000, () => r.destroy(new C.Fault("NETWORK_TIMEOUT")));
      r.on("error", reject);
      r.end(data);
    });
  }
  async function info(who) {
    if (who !== actor) return call({ op: "info", actor: who });
    C.check(identity, "IDENTITY_REQUIRED");
    const context = await request("/v1/context");
    const envelope = command(
      identity,
      { ...context, actor, epoch: 0 },
      { op: "info", actor },
    );
    const { signature, ...body } = envelope;
    return request("/v1/identity", {
      ...body,
      signature: C.sign(
        identity.private_key,
        "KIG/identity-bootstrap/v2",
        body,
      ),
    });
  }
  async function prepare(body) {
    return command(identity, await info(actor), body);
  }
  async function call(body) {
    return request("/v1/command", await prepare(body));
  }
  return {
    request,
    info,
    prepare,
    call,
  };
}
module.exports = { client };
