"use strict";
const fs = require("node:fs");
const path = require("node:path");
const C = require("../crypto.cjs");
const { writeExclusive } = require("../store.cjs");
const dir = process.argv[2];
C.check(typeof dir === "string", "OUTPUT_DIRECTORY_REQUIRED");
fs.mkdirSync(dir, { recursive: false, mode: 0o700 });
const identities = [];
for (const [actor, role] of [
  ["owner", "user"],
  ["recipient", "user"],
  ["operator", "admin"],
  ["custodian", "recovery"],
  ["node", "replicator"],
]) {
  const key = C.generate();
  writeExclusive(
    path.join(dir, actor + ".json"),
    Buffer.from(JSON.stringify(key, null, 2) + "\n"),
  );
  writeExclusive(
    path.join(dir, actor + "-public.json"),
    Buffer.from(JSON.stringify({ actor, public_key: key.public_key }) + "\n"),
  );
  identities.push({ actor, role, public_key: key.public_key });
}
const setup = {
  owners: { document: "owner", inbox: "recipient" },
  contents: {
    document: "Replace this sample resource with your own content.",
    inbox: "Recipient-owned resource.",
  },
  disabled: [],
  key_material: C.random(),
  identities,
};
writeExclusive(
  path.join(dir, "setup.json"),
  Buffer.from(JSON.stringify(setup, null, 2) + "\n"),
);
console.log(
  JSON.stringify({
    directory: path.resolve(dir),
    setup: path.resolve(dir, "setup.json"),
    note: "Fresh generated keys. Example identities/content are editable fixture configuration, not authorization logic.",
  }),
);
