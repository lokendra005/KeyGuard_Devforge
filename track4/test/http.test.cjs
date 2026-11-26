"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const C = require("../crypto.cjs");
const { fixture } = require("./helpers.cjs");
const { server } = require("../server.cjs");
const { client } = require("../client.cjs");
const run = promisify(execFile);

test("HTTP uses the same authority; public raw actor assertions cannot bypass signatures", async (t) => {
  const f = fixture(t);
  const api = server({ directory: f.directory });
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        api.close(resolve);
        api.closeAllConnections();
      }),
  );
  const url = "http://127.0.0.1:" + api.address().port;
  const remote = client(url, f.keys.owner, f.actors.owner);
  A.equal(
    (
      await remote.call({
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      })
    ).body,
    f.body,
  );
  const bypass = await fetch(url + "/v1/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      op: "read",
      actor: f.actors.owner,
      asset: f.asset,
      request_id: C.random(),
    }),
  });
  A.notEqual(bypass.status, 200);
  A.equal((await bypass.text()).includes(f.body), false);
  A.equal((await fetch(url + "/v1/status")).status, 403);
  const admin = client(url, f.keys.admin, f.actors.admin);
  const session = await admin.call({ op: "dashboard.open" });
  const status = await fetch(url + "/v1/status", {
    headers: { Authorization: "Bearer " + session.token },
  });
  A.equal(status.status, 200);
  const snapshot = await status.json();
  A.equal(snapshot.files[0].body, undefined);
  A.notEqual(
    (
      await fetch(url + "/v1/status", {
        headers: {
          Authorization: "Bearer " + session.token,
          Origin: "https://evil.example",
        },
      })
    ).status,
    200,
  );
  const page = await fetch(url);
  A.match(
    page.headers.get("content-security-policy"),
    /frame-ancestors 'none'/,
  );
  A.match(await page.text(), /Authority, with evidence/);
  const script = await fetch(url + "/app.js");
  A.equal(script.status, 200);
  await admin.call({ op: "revoke", actor: f.actors.owner });
  await A.rejects(
    () =>
      remote.call({
        op: "read",
        actor: f.actors.owner,
        asset: f.asset,
        request_id: C.random(),
      }),
    (e) => e.code === "UNAUTHORIZED",
  );
});

test(
  "real CLI sender/receiver deliver an encrypted file through HTTP and acknowledge it",
  { timeout: 15000 },
  async (t) => {
    const f = fixture(t);
    const api = server({ directory: f.directory });
    await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
    t.after(
      () =>
        new Promise((resolve) => {
          api.close(resolve);
          api.closeAllConnections();
        }),
    );
    const url = "http://127.0.0.1:" + api.address().port;
    const cli = path.resolve(__dirname, "../cli.cjs");
    const files = {
      sender: f.keys.owner,
      receiver: f.keys.peer,
      senderPublic: {
        actor: f.actors.owner,
        public_key: f.keys.owner.public_key,
      },
      receiverPublic: {
        actor: f.actors.peer,
        public_key: f.keys.peer.public_key,
      },
    };
    for (const [name, value] of Object.entries(files))
      fs.writeFileSync(
        path.join(f.directory, name + ".json"),
        JSON.stringify(value),
        { mode: 0o600 },
      );
    const content = C.c.randomBytes(65537);
    fs.writeFileSync(path.join(f.directory, "input.bin"), content);
    const receive = run(
      process.execPath,
      [
        cli,
        "receive",
        "--url",
        url,
        "--actor",
        f.actors.peer,
        "--key",
        path.join(f.directory, "receiver.json"),
        "--peer",
        path.join(f.directory, "senderPublic.json"),
        "--out",
        path.join(f.directory, "output.bin"),
      ],
      { timeout: 12000 },
    );
    receive.catch(() => {});
    const sender = client(url, f.keys.owner, f.actors.owner);
    for (let i = 0; i < 60; i++) {
      if (
        (await sender.call({ op: "mail.lookup", recipient: f.actors.peer }))
          .offer
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const sent = await run(process.execPath, [
      cli,
      "send",
      "--url",
      url,
      "--actor",
      f.actors.owner,
      "--key",
      path.join(f.directory, "sender.json"),
      "--peer",
      path.join(f.directory, "receiverPublic.json"),
      "--input",
      path.join(f.directory, "input.bin"),
    ]);
    A.equal(JSON.parse(sent.stdout).queued, 5);
    const received = await receive;
    A.equal(JSON.parse(received.stdout).delivered, true);
    A.deepEqual(fs.readFileSync(path.join(f.directory, "output.bin")), content);
    A.equal(f.store.db.prepare("SELECT count(*) AS n FROM mail").get().n, 0);
  },
);
