#!/usr/bin/env node
"use strict";
// Test transport only: run the real root adapter in a fresh, offline, read-only Linux container.
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const state = process.env.TRACK4_STATE_DIR;
const arch =
  process.env.KIG_REVIEW_ARCH || (process.arch === "arm64" ? "arm64" : "amd64");
if (!state || !["arm64", "amd64"].includes(arch)) {
  process.stderr.write("Set TRACK4_STATE_DIR and a supported architecture.\n");
  process.exit(2);
}
const root = path.resolve(__dirname, "..");
const args = [
  "run",
  "--rm",
  "-i",
  "--pull",
  "never",
  "--platform",
  "linux/" + arch,
  "--network",
  "none",
  "--read-only",
  "--cap-drop",
  "ALL",
  "--security-opt",
  "no-new-privileges",
  "--memory",
  "512m",
  "--pids-limit",
  "64",
  "--user",
  `${process.getuid()}:${process.getgid()}`,
  "--tmpfs",
  "/tmp:rw,noexec,nosuid,size=64m",
  "-v",
  root + ":/app:ro",
  "-v",
  path.resolve(state) + ":/state",
  "-e",
  "TRACK4_STATE_DIR=/state",
  "-w",
  "/app",
  "keyguard-review-node:" + arch,
  "node",
  "track4_service.cjs",
];
const result = spawnSync("docker", args, {
  input: fs.readFileSync(0),
  maxBuffer: 16 * 1024 * 1024,
  timeout: 7500,
});
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exit(result.status === null ? 2 : result.status);
