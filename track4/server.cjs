"use strict";
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const C = require("./crypto.cjs");
const { Store } = require("./store.cjs");
const { execute } = require("./service.cjs");

function server(options = {}) {
  const host = options.host || "127.0.0.1";
  const local = ["127.0.0.1", "::1", "localhost"].includes(host);
  C.check(
    local || (options.cert && options.tlsKey && options.origin),
    "TLS_AND_ORIGIN_REQUIRED",
  );
  C.check(!!options.cert === !!options.tlsKey, "TLS_CONFIG_REQUIRED");
  const store =
    options.replica ||
    new Store({
      directory: options.directory,
      node: options.node,
      anchor: options.anchor,
    });
  C.check(store.get("authority"), "NOT_INITIALIZED");
  const run = (input, auth) =>
    options.replica ? store.execute(input, auth) : execute(store, input, auth);
  const assets = new Map([
    ["/", ["index.html", "text/html; charset=utf-8"]],
    ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
    ["/style.css", ["style.css", "text/css; charset=utf-8"]],
  ]);
  const rates = new Map();
  let inflight = 0;
  const handler = async (req, res) => {
    let admitted = false;
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-store");
    function send(code, body, requireLease = false) {
      const encoded = JSON.stringify(body);
      C.check(
        Buffer.byteLength(encoded) <= 16 * 1024 * 1024,
        "RESPONSE_CAPACITY",
      );
      if (requireLease) C.check(store.ready(), "LEASE_EXPIRED");
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(encoded);
    }
    try {
      const port = api.address().port;
      const origin =
        options.origin ||
        `${options.cert ? "https" : "http"}://${host.includes(":") ? "[" + host + "]" : host}:${port}`;
      C.check(req.headers.host === new URL(origin).host, "WRONG_HOST");
      C.check(
        !req.headers.origin || req.headers.origin === origin,
        "WRONG_ORIGIN",
      );
      C.check(inflight < 32, "BUSY");
      inflight++;
      admitted = true;
      const peer = req.socket.remoteAddress;
      const minute = Math.floor(Date.now() / 60000);
      for (const [key, bucket] of rates)
        if (bucket.minute < minute) rates.delete(key);
      C.check(rates.has(peer) || rates.size < 1024, "RATE_LIMIT");
      const bucket = rates.get(peer) || { minute, count: 0 };
      bucket.count++;
      rates.set(peer, bucket);
      C.check(bucket.count <= 600, "RATE_LIMIT");
      const url = new URL(req.url, origin);
      if (req.method === "GET" && assets.has(url.pathname)) {
        const [name, type] = assets.get(url.pathname);
        res.writeHead(200, { "Content-Type": type });
        res.end(fs.readFileSync(path.join(__dirname, "web", name)));
        return;
      }
      if (req.method === "GET" && url.pathname === "/healthz") {
        const ready = options.replica
          ? store.ready()
          : store.db.prepare("SELECT 1 AS ok").get().ok === 1;
        send(ready ? 200 : 503, { ready });
        return;
      }
      if (req.method === "GET" && url.pathname === "/v1/identity") {
        send(403, { error: "UNAUTHORIZED" });
        return;
      }
      if (req.method === "GET" && url.pathname === "/v1/context") {
        send(200, {
          version: 1,
          authority: store.get("authority"),
          request_lifetime_ms: store.policy().request_lifetime_ms,
        });
        return;
      }
      if (
        req.method === "GET" &&
        ["/v1/status", "/v1/evidence"].includes(url.pathname)
      ) {
        C.check(
          typeof req.headers.authorization === "string" &&
            req.headers.authorization.startsWith("Bearer "),
          "UNAUTHORIZED",
        );
        send(
          200,
          run(
            { op: url.pathname.slice(4) },
            { observer: req.headers.authorization.slice(7) },
          ),
        );
        return;
      }
      C.check(
        req.method === "POST" &&
          ["/v1/command", "/v1/identity"].includes(url.pathname),
        "NOT_FOUND",
      );
      C.check(
        /^application\/json(?:;\s*charset=utf-8)?$/i.test(
          req.headers["content-type"] || "",
        ),
        "UNSUPPORTED_CONTENT_TYPE",
      );
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        C.check(size <= 16 * 1024 * 1024, "INPUT_TOO_LARGE");
        chunks.push(chunk);
      }
      const envelope = C.object(C.parse(Buffer.concat(chunks)));
      send(
        200,
        run(envelope, { bootstrap: url.pathname === "/v1/identity" }),
        !!options.replica,
      );
    } catch (error) {
      if (!res.headersSent) {
        const code = error instanceof C.Fault ? error.code : "REQUEST_FAILED";
        const status = [
          "UNAUTHORIZED",
          "INVALID_SIGNATURE",
          "FORBIDDEN",
        ].includes(code)
          ? 403
          : ["RATE_LIMIT", "BUSY"].includes(code)
            ? 429
            : code === "NOT_FOUND"
              ? 404
              : 400;
        send(status, { error: code });
      } else res.end();
    } finally {
      if (admitted) inflight--;
    }
  };
  const api = options.cert
    ? https.createServer(
        {
          cert: fs.readFileSync(options.cert),
          key: fs.readFileSync(options.tlsKey),
          minVersion: "TLSv1.3",
        },
        handler,
      )
    : http.createServer(handler);
  api.requestTimeout = 10000;
  api.headersTimeout = 10000;
  api.maxHeadersCount = 32;
  api.keepAliveTimeout = 2000;
  api.on("close", () => store.close());
  api.on("clientError", (_, socket) =>
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"),
  );
  return api;
}
module.exports = { server };
