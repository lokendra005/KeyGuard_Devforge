#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const { parseArgs } = require("node:util");
const C = require("./crypto.cjs");
const { Store, verifyEvidence, writeExclusive } = require("./store.cjs");
const { execute } = require("./service.cjs");
const Backup = require("./backup.cjs");
const Detect = require("./detect.cjs");
const HELP = `Key Identity Guard / Track 4 (Node 24.11.1; no npm install)
  keygen --out KEY
  init --state DIR --input CONFIG
  serve --state DIR [--host IP --port PORT --cert PEM --tls-key PEM --origin URL] [--replica CONFIG]
  local --state DIR --body JSON            trusted local administration
  request --url URL --actor ID --key KEY --body JSON [--ca PEM]
  prepare --url URL --actor ID --key KEY --body JSON --out SIGNED_JSON
  submit --url URL --input SIGNED_JSON
  replica-init --state DIR --node ID --trust TRUST_JSON --out BINDING_JSON
  enroll --url URL --actor ADMIN --key KEY --target ID --role ROLE --new-key NEW [--binding BINDING_JSON]
  rotate --url URL --actor ID --key OLD --new-key NEW --grace-ms MS
  recovery-prepare --url URL --actor CUSTODIAN --key KEY --target ID --new-key NEW --out BODY
  dashboard --url URL --actor ID --key KEY
  send --url URL --actor ID --key KEY --peer PUBLIC_IDENTITY --input FILE
  receive --url URL --actor ID --key KEY --peer PUBLIC_IDENTITY --out FILE
  detect --events CSV --approvals JSON --config JSON [--reference CSV] [--labels CSV --positive-labels A,B]
  backup --state DIR --password-file FILE --out BUNDLE --checkpoint CHECKPOINT
  restore --input BUNDLE --password-file FILE --state NEW_DIR --anchor CHECKPOINT
  key-backup --key KEY --password-file FILE --out BUNDLE
  key-restore --input BUNDLE --password-file FILE --out KEY
  verify --input EVIDENCE --trust PUBLIC_KEY_JSON [--anchor CHECKPOINT]
Files written with --out must not already exist. Secrets never belong in command-line arguments.
`;
function read(file, max = 16 * 1024 * 1024) {
  C.text(file);
  const stat = fs.statSync(file);
  C.check(stat.isFile() && stat.size <= max, "FILE_CAPACITY");
  return C.parse(fs.readFileSync(file), max);
}
function save(file, value) {
  C.text(file);
  writeExclusive(file, Buffer.from(JSON.stringify(value, null, 2) + "\n"));
}
async function main(args = process.argv.slice(2)) {
  const names = [
    "state",
    "input",
    "out",
    "key",
    "new-key",
    "body",
    "url",
    "actor",
    "target",
    "role",
    "grace-ms",
    "peer",
    "ca",
    "host",
    "port",
    "cert",
    "tls-key",
    "origin",
    "node",
    "events",
    "approvals",
    "config",
    "labels",
    "positive-labels",
    "password-file",
    "checkpoint",
    "anchor",
    "trust",
    "reference",
    "replica",
    "binding",
  ];
  const { values: v, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: Object.fromEntries(names.map((n) => [n, { type: "string" }])),
  });
  const op = positionals[0];
  C.check(positionals.length <= 1, "INVALID_ARGUMENTS");
  if (!op || op === "help") {
    process.stdout.write(HELP);
    return;
  }
  const password = () => {
    C.text(v["password-file"]);
    const data = fs.readFileSync(v["password-file"]);
    C.check(data.length <= 4096, "INVALID_PASSWORD_FILE");
    return new TextDecoder("utf8", { fatal: true })
      .decode(data)
      .replace(/\r?\n$/, "");
  };
  if (op === "keygen") {
    const identity = C.generate();
    save(v.out, identity);
    return {
      public_key: identity.public_key,
      key_id: C.keyID(identity.public_key),
    };
  }
  if (op === "key-backup") {
    save(v.out, Backup.backupKey(read(v.key), password()));
    return { saved: true };
  }
  if (op === "key-restore") {
    save(v.out, Backup.restoreKey(read(v.input), password()));
    return { restored: true };
  }
  if (op === "restore")
    return Backup.restoreAuthority(
      read(v.input, 180 * 1024 * 1024),
      password(),
      v.state,
      read(v.anchor),
    );
  if (op === "verify") {
    const trust = read(v.trust);
    return verifyEvidence(
      read(v.input),
      trust.public_key,
      v.anchor ? read(v.anchor) : undefined,
    );
  }
  if (op === "detect") {
    const config = read(v.config);
    if (v.reference)
      config.baseline = Detect.learn(
        Detect.csv(fs.readFileSync(v.reference, "utf8")),
        config,
      );
    const report = Detect.detect(
      Detect.csv(fs.readFileSync(v.events, "utf8")),
      read(v.approvals),
      config,
    );
    if (v.labels)
      report.metrics = Detect.score(
        report,
        Detect.csv(fs.readFileSync(v.labels, "utf8")),
        (v["positive-labels"] || "").split(",").filter(Boolean),
      );
    if (v.out) save(v.out, report);
    return report;
  }
  if (op === "replica-init") {
    const node = new (require("./replica.cjs").Replica)({
      directory: v.state,
      node: v.node,
      trust: read(v.trust),
    });
    try {
      const binding = {
        node_id: node.node,
        node_public_key: node.audit.public_key,
      };
      save(v.out, binding);
      return binding;
    } finally {
      node.close();
    }
  }
  if (op === "serve") {
    const host = v.host || "127.0.0.1";
    const port = C.integer(Number(v.port || 8444), 0, 65535);
    let replica, stopReplication;
    if (v.replica) {
      const config = read(v.replica);
      const { Replica, replicate } = require("./replica.cjs");
      replica = new Replica({
        directory: v.state,
        trust: read(config.trust_file),
        node: v.node || process.env.KIG_NODE_ID || config.node_id,
        lease_ms: config.lease_ms,
      });
      stopReplication = await replicate(
        replica,
        require("./client.cjs").client(
          config.upstream,
          read(config.key_file),
          config.actor,
          config.ca_file,
        ),
        config.sync_ms,
      );
    }
    let api;
    try {
      api = require("./server.cjs").server({
        directory: v.state,
        host,
        cert: v.cert,
        tlsKey: v["tls-key"],
        origin: v.origin,
        node: v.node,
        anchor: v.anchor ? read(v.anchor) : undefined,
        replica,
      });
      await new Promise((resolve, reject) => {
        api.once("error", reject);
        api.listen(port, host, resolve);
      });
    } catch (error) {
      if (stopReplication) stopReplication();
      if (replica) replica.close();
      throw error;
    }
    process.stdout.write(
      JSON.stringify({ listening: api.address(), tls: !!v.cert }) + "\n",
    );
    for (const signal of ["SIGINT", "SIGTERM"])
      process.on(signal, () => {
        if (stopReplication) stopReplication();
        api.close();
        api.closeIdleConnections();
      });
    return;
  }
  if (["init", "local", "backup"].includes(op)) {
    C.text(v.state);
    const store = new Store({ directory: v.state, node: v.node });
    try {
      if (op === "backup") {
        C.check(
          !fs.existsSync(v.out) && !fs.existsSync(v.checkpoint),
          "OUTPUT_EXISTS",
        );
        const result = Backup.backupAuthority(store, password());
        save(v.out, result.bundle);
        save(v.checkpoint, result.checkpoint);
        return { saved: true, checkpoint: result.checkpoint };
      }
      const body = read(op === "init" ? v.input : v.body);
      if (op === "init") body.op = "setup";
      return execute(store, body, { trusted: true });
    } finally {
      store.close();
    }
  }
  const identity = v.key ? read(v.key) : undefined;
  const remote = require("./client.cjs").client(v.url, identity, v.actor, v.ca);
  if (op === "submit") return remote.request("/v1/command", read(v.input));
  if (op === "request") return remote.call(read(v.body));
  if (op === "prepare") {
    save(v.out, await remote.prepare(read(v.body)));
    return { saved: true };
  }
  if (op === "enroll") {
    const key = read(v["new-key"]);
    const details = await remote.info(v.actor);
    const binding = v.role === "replicator" ? read(v.binding) : {};
    const body = {
      ...binding,
      op: "enroll",
      actor: v.target,
      role: v.role,
      public_key: key.public_key,
      proof: C.sign(key.private_key, "KIG/enroll/v1", {
        authority: details.authority,
        actor: v.target,
        role: v.role,
        ...binding,
      }),
    };
    return remote.call(body);
  }
  if (op === "rotate") {
    const key = read(v["new-key"]);
    const details = await remote.info(v.actor);
    const grace = Number(v["grace-ms"] || 0);
    const proposal = {
      authority: details.authority,
      actor: v.actor,
      epoch: details.epoch,
      new_public_key: key.public_key,
      grace_ms: grace,
    };
    return remote.call({
      op: "rotate",
      new_public_key: key.public_key,
      grace_ms: grace,
      proof: C.sign(key.private_key, "KIG/rotate/v1", proposal),
    });
  }
  if (op === "recovery-prepare") {
    const details = await remote.info(v.target);
    const key = read(v["new-key"]);
    const proposal = {
      authority: details.authority,
      actor: v.target,
      epoch: details.epoch,
      new_public_key: key.public_key,
      recovery_id: C.random(),
      expires: Date.now() + details.request_lifetime_ms,
    };
    save(v.out, {
      op: "recover",
      ...proposal,
      proof: C.sign(key.private_key, "KIG/recover/v1", proposal),
    });
    return { saved: true, expires: proposal.expires };
  }
  if (op === "dashboard") return remote.call({ op: "dashboard.open" });
  if (op === "send") {
    const peer = read(v.peer);
    const size = fs.statSync(v.input).size;
    C.check(size <= 1048576, "MESSAGE_TOO_LARGE");
    const { offer } = await remote.call({
      op: "mail.lookup",
      recipient: peer.actor,
    });
    C.check(offer, "NO_RECIPIENT_OFFER");
    const frames = require("./messaging.cjs").encrypt(
      identity,
      v.actor,
      peer,
      offer,
      fs.readFileSync(v.input),
    );
    let last;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const receipt = await remote.call({ op: "mail.deliver", frames });
        return {
          message_id: frames[0].header.message_id,
          ...receipt,
          delivery: "queued; recipient acknowledgment is separate",
        };
      } catch (e) {
        last = e;
        if (!["NETWORK_TIMEOUT", "ECONNRESET", "ECONNREFUSED"].includes(e.code))
          throw e;
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(250 * 2 ** attempt, 2000)),
        );
      }
    }
    throw last;
  }
  if (op === "receive") {
    C.check(!fs.existsSync(v.out), "OUTPUT_EXISTS");
    const peer = read(v.peer);
    const details = await remote.info(v.actor);
    const Receiver = require("./messaging.cjs").Receiver;
    const receiver = new Receiver(identity, v.actor, peer, details.authority);
    const offer = receiver.offer(Math.min(120000, details.mailbox_lifetime_ms));
    await remote.call({ op: "mail.offer", offer });
    process.stderr.write(
      "Recipient offer published; waiting until its signed expiry.\n",
    );
    try {
      while (Date.now() <= offer.expires) {
        const response = await remote.call({ op: "mail.poll" });
        for (const frames of response.messages)
          for (const frame of frames) {
            if (frame.header.offer_id !== offer.id) continue;
            const result = receiver.receive(frame);
            if (result.complete) {
              writeExclusive(v.out, result.body);
              result.body.fill(0);
              await remote.call({
                op: "mail.ack",
                message_id: result.message_id,
              });
              return { delivered: true, message_id: result.message_id };
            }
          }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      throw new C.Fault("DELIVERY_TIMEOUT");
    } finally {
      receiver.close();
    }
  }
  throw new C.Fault("UNKNOWN_COMMAND");
}
if (require.main === module)
  main()
    .then(async (result) => {
      // A revoke is reported only once every replica lease that predates it has expired.
      if (result?.revoked && result.replica_grace_ms > 0) {
        await new Promise((resolve) => setTimeout(resolve, result.replica_grace_ms));
        result.effective_everywhere = true;
      }
      if (result !== undefined)
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    })
    .catch((error) => {
      process.stderr.write(
        JSON.stringify({
          error: error instanceof C.Fault ? error.code : "COMMAND_FAILED",
          ...(error.label
            ? { label: error.label, event_id: error.event_id }
            : {}),
        }) + "\n",
      );
      process.exitCode = 1;
    });
module.exports = { main };
