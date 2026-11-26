"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const C = require("../crypto.cjs");
const { Store } = require("../store.cjs");
const S = require("../service.cjs");
function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "kig-track4-test-"));
  let now = Date.now();
  const keys = Object.fromEntries(
    ["owner", "peer", "admin", "recoveryA", "recoveryB"].map((n) => [
      n,
      C.generate(),
    ]),
  );
  const actors = Object.fromEntries(
    Object.keys(keys).map((n) => [n, C.random() + "/" + n + " भारत"]),
  );
  const identities = Object.keys(keys).map((n) => ({
    actor: actors[n],
    role:
      n === "admin" ? "admin" : n.startsWith("recovery") ? "recovery" : "user",
    public_key: keys[n].public_key,
  }));
  const asset = "__proto__/\0" + C.random();
  const other = C.random();
  const body = "private-" + C.random() + "\nनमस्ते\0";
  const secret = C.random();
  const store = new Store({ directory, clock: () => now, node: "test-node" });
  S.execute(
    store,
    {
      op: "setup",
      owners: { [asset]: actors.owner, [other]: actors.peer },
      contents: { [asset]: body, [other]: "peer-" + C.random() },
      disabled: [],
      key_material: secret,
      identities,
      ...options,
    },
    { trusted: true },
  );
  t.after(() => {
    try {
      store.close();
    } catch {}
    fs.rmSync(directory, { recursive: true, force: true });
  });
  function envelope(who, operation, key = keys[who]) {
    return S.command(key, S.info(store, actors[who]), operation, now);
  }
  function call(who, operation, key) {
    return S.execute(store, envelope(who, operation, key));
  }
  function trusted(operation) {
    return S.execute(store, operation, { trusted: true });
  }
  return {
    directory,
    store,
    keys,
    actors,
    asset,
    other,
    body,
    secret,
    envelope,
    call,
    trusted,
    now: () => now,
    tick: (ms) => {
      now += ms;
    },
  };
}
module.exports = { fixture };
