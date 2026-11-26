"use strict";
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
const manifestPath = path.join(root, "evidence/source-sha256.json");
const digest = (file) =>
  crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(root, file)))
    .digest("hex");
if (process.argv[2] === "--record") {
  const files = [];
  function visit(relative) {
    const stat = fs.lstatSync(path.join(root, relative));
    assert(!stat.isSymbolicLink(), "Unexpected source symlink: " + relative);
    if (stat.isDirectory())
      for (const name of fs.readdirSync(path.join(root, relative)).sort())
        visit(path.posix.join(relative, name));
    else if (stat.isFile()) files.push(relative);
  }
  for (const item of [
    "track4",
    "scripts",
    ".github",
    "track4_service.cjs",
    "threat-model.json",
    "Makefile",
    "Dockerfile",
    "Dockerfile.dockerignore",
    "Dockerfile.track4",
    "Dockerfile.track4.dockerignore",
    "compose.yaml",
    "compose.track4.yaml",
    "compose.replicas.yaml",
    ".gitignore",
    ".dockerignore",
  ])
    visit(item);
  fs.writeFileSync(
    manifestPath,
    JSON.stringify(
      {
        version: 1,
        files: Object.fromEntries(
          files.sort().map((file) => [file, digest(file)]),
        ),
      },
      null,
      2,
    ) + "\n",
  );
} else
  assert(process.argv.length === 2, "Usage: verify-evidence.cjs [--record]");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
for (const [file, expected] of Object.entries(manifest.files)) {
  assert(!path.isAbsolute(file) && !file.split(/[\\/]/).includes(".."), file);
  assert.equal(
    digest(file),
    expected,
    "Source differs from recorded evidence: " + file,
  );
}
console.log(
  "PASS: " +
    Object.keys(manifest.files).length +
    " recorded source/config/script hashes match.",
);
