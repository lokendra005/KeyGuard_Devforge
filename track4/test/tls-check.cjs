"use strict";
// Optional host check: the judge core needs only Node; this certificate-generation check also needs OpenSSL CLI.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const A = require("node:assert/strict");
const C = require("../crypto.cjs");
const { Store } = require("../store.cjs");
const { execute } = require("../service.cjs");
const { server } = require("../server.cjs");
const { client } = require("../client.cjs");
(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "kig-tls-"));
  let api;
  try {
    const cert = path.join(directory, "cert.pem"),
      tlsKey = path.join(directory, "tls.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-keyout",
        tlsKey,
        "-out",
        cert,
      ],
      { stdio: "pipe" },
    );
    const key = C.generate();
    const actor = C.random();
    const store = new Store({ directory });
    execute(
      store,
      {
        op: "setup",
        owners: {},
        contents: {},
        disabled: [],
        key_material: C.random(),
        identities: [{ actor, role: "admin", public_key: key.public_key }],
      },
      { trusted: true },
    );
    store.close();
    api = server({ directory, cert, tlsKey });
    await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
    const url = "https://127.0.0.1:" + api.address().port;
    const remote = client(url, key, actor, cert);
    A.equal((await remote.call({ op: "status" })).actors[0].id, actor);
    await A.rejects(() => client(url, key, actor).call({ op: "status" }));
    A.throws(
      () => server({ directory, host: "0.0.0.0" }),
      (e) => e.code === "TLS_AND_ORIGIN_REQUIRED",
    );
    console.log(
      "PASS: actual TLS 1.3 API, explicit CA trust, rejection of untrusted certificate and non-loopback plaintext configuration.",
    );
  } finally {
    if (api)
      await new Promise((resolve) => {
        api.close(resolve);
        api.closeAllConnections();
      });
    fs.rmSync(directory, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e.code || e.message);
  process.exitCode = 1;
});
