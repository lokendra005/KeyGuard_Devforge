"use strict";
const { test } = require("node:test");
const A = require("node:assert/strict");
const c = require("node:crypto");
const M = require("../merkle.cjs");
const { fixture } = require("./helpers.cjs");

const H = (...p) => c.createHash("sha384").update(Buffer.concat(p)).digest();
// Brute force: bottom-up levels, an odd last node is promoted unchanged (equivalent to RFC 9162 split).
function bruteRoot(leaves) {
  let level = leaves.map((l) => Buffer.from(l, "hex"));
  if (level.length === 0) return H().toString("hex");
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(i + 1 < level.length ? H(Buffer.from([1]), level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0].toString("hex");
}
const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1);

test("merkle root, inclusion and consistency agree with brute force for sizes 1..70", () => {
  A.equal(M.root([]), H().toString("hex"));
  const sizes = [...Array(70).keys()].map((i) => i + 1);
  for (let k = 0; k < 20; k++) sizes.push(1 + c.randomInt(70));
  for (const n of sizes) {
    const leaves = Array.from({ length: n }, () =>
      M.leafHash(c.randomBytes(48).toString("hex")),
    );
    const root = M.root(leaves);
    A.equal(root, bruteRoot(leaves), "root n=" + n);
    for (let i = 0; i < n; i++) {
      const proof = M.inclusionProof(leaves, i);
      A.ok(M.verifyInclusion(leaves[i], i, n, proof, root), `incl ${i}/${n}`);
      A.ok(!M.verifyInclusion(leaves[i], i, n, proof, flip(root)));
      if (n > 1) {
        A.ok(!M.verifyInclusion(leaves[(i + 1) % n], i, n, proof, root));
        const bad = [...proof];
        const j = c.randomInt(bad.length);
        bad[j] = flip(bad[j]);
        A.ok(!M.verifyInclusion(leaves[i], i, n, bad, root));
      }
    }
    for (let m = 1; m <= n; m++) {
      const rootM = bruteRoot(leaves.slice(0, m));
      const proof = M.consistencyProof(leaves, m);
      A.ok(M.verifyConsistency(m, n, rootM, root, proof), `cons ${m}/${n}`);
      A.ok(!M.verifyConsistency(m, n, flip(rootM), root, proof));
      A.ok(!M.verifyConsistency(m, n, rootM, flip(root), proof));
      if (proof.length) {
        const bad = [...proof];
        const j = c.randomInt(bad.length);
        bad[j] = flip(bad[j]);
        A.ok(!M.verifyConsistency(m, n, rootM, root, bad));
      }
    }
  }
});

test("audit op inclusion proof verifies against the signed tree head (ML-DSA + SLH-DSA)", (t) => {
  const f = fixture(t);
  f.call("owner", { op: "read", actor: f.actors.owner, asset: f.asset, request_id: "r1" });
  f.call("owner", { op: "read", actor: f.actors.owner, asset: f.asset, request_id: "r2" });
  const audit = f.call("owner", { op: "audit", request_id: "r1" });
  const { inclusion } = audit;
  const status = f.trusted({ op: "status" });
  const head = status.tree_head;
  A.equal(inclusion.tree_size, head.tree_size);
  A.equal(inclusion.root, head.root);
  const leafEventHash = f.store.db
    .prepare("SELECT hash FROM events WHERE seq=?")
    .get(inclusion.leaf_index + 1).hash;
  const leaf = M.leafHash(leafEventHash);
  A.ok(M.verifyInclusion(leaf, inclusion.leaf_index, inclusion.tree_size, inclusion.proof, head.root));
  const bad = [...inclusion.proof];
  bad[0] = flip(bad[0]);
  A.ok(!M.verifyInclusion(leaf, inclusion.leaf_index, inclusion.tree_size, bad, head.root));

  A.ok(M.verifyTreeHead(head, status.audit_public_key));
  A.ok(!M.verifyTreeHead({ ...head, root: flip(head.root) }, status.audit_public_key));
  const evidence = f.trusted({ op: "evidence" });
  A.equal(evidence.slh_public_key, status.slh_public_key);

  let slhAvailable = true;
  try {
    c.generateKeyPairSync("slh-dsa-sha2-128s");
  } catch {
    slhAvailable = false;
  }
  if (!slhAvailable) {
    A.equal(head.slh_dsa, "unavailable");
    A.equal(status.slh_public_key, "unavailable");
    return;
  }
  A.ok(head.slh_signature);
  A.ok(M.verifyTreeHead(head, status.audit_public_key, status.slh_public_key));
  A.ok(!M.verifyTreeHead({ ...head, tree_size: head.tree_size + 1 }, status.audit_public_key, status.slh_public_key));
  A.ok(!M.verifyTreeHead({ ...head, slh_signature: undefined }, status.audit_public_key, status.slh_public_key));
  // Key persists: a later head (new events) is co-signed by the same SLH key.
  f.call("owner", { op: "read", actor: f.actors.owner, asset: f.asset, request_id: "r3" });
  const later = f.trusted({ op: "status" });
  A.equal(later.slh_public_key, status.slh_public_key);
  A.ok(M.verifyTreeHead(later.tree_head, status.audit_public_key, status.slh_public_key));
});
