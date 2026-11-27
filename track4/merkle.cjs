"use strict";
// RFC 9162 section 2.1 Merkle tree over audit event hashes, SHA-384, hex encoded.
const C = require("./crypto.cjs");

const H = (...parts) =>
  C.c.createHash("sha384").update(Buffer.concat(parts)).digest();
const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);
const hex = (s) => C.b64(Buffer.from(C.text(s), "hex").toString("base64"), 48);
function leafHash(eventHash) {
  return H(LEAF, hex(eventHash)).toString("hex");
}
function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function mth(leaves) {
  if (leaves.length === 0) return H();
  if (leaves.length === 1) return Buffer.from(leaves[0], "hex");
  const k = split(leaves.length);
  return H(NODE, mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
// `leaves` are leaf hashes (leafHash(eventHash)), not raw entries.
function root(leaves) {
  return mth(leaves).toString("hex");
}
function path(m, leaves) {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...path(m, leaves.slice(0, k)), root(leaves.slice(k))]
    : [...path(m - k, leaves.slice(k)), root(leaves.slice(0, k))];
}
function inclusionProof(leaves, index) {
  C.integer(index, 0, leaves.length - 1);
  return path(index, leaves);
}
function verifyInclusion(leaf, index, size, proof, rootHash) {
  try {
    if (!Number.isSafeInteger(index) || index < 0 || index >= size) return false;
    let fn = index;
    let sn = size - 1;
    let r = hex(leaf);
    for (const p of proof) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = H(NODE, hex(p), r);
        if (fn % 2 === 0)
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
      } else r = H(NODE, r, hex(p));
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && r.equals(hex(rootHash));
  } catch {
    return false;
  }
}
function subproof(m, leaves, complete) {
  const n = leaves.length;
  if (m === n) return complete ? [] : [root(leaves)];
  const k = split(n);
  return m <= k
    ? [...subproof(m, leaves.slice(0, k), complete), root(leaves.slice(k))]
    : [...subproof(m - k, leaves.slice(k), false), root(leaves.slice(0, k))];
}
function consistencyProof(leaves, m) {
  C.integer(m, 1, leaves.length);
  return subproof(m, leaves, true);
}
function verifyConsistency(m, n, rootM, rootN, proof) {
  try {
    if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 1 || m > n)
      return false;
    if (m === n) return proof.length === 0 && hex(rootM).equals(hex(rootN));
    if (proof.length === 0) return false;
    const path = (m & (m - 1)) === 0 ? [rootM, ...proof] : [...proof];
    let fn = m - 1;
    let sn = n - 1;
    while (fn % 2 === 1) {
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    let fr = hex(path[0]);
    let sr = fr;
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        fr = H(NODE, hex(c), fr);
        sr = H(NODE, hex(c), sr);
        if (fn % 2 === 0)
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
      } else sr = H(NODE, sr, hex(c));
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && fr.equals(hex(rootM)) && sr.equals(hex(rootN));
  } catch {
    return false;
  }
}

// SLH-DSA co-signature (FIPS 205). Absent on Node < 24.11: callers degrade to "unavailable".
const SLH = "slh-dsa-sha2-128s";
const input = (domain, value) => Buffer.from(C.canonical([domain, value]));
function slhGenerate() {
  try {
    const pair = C.c.generateKeyPairSync(SLH);
    return {
      public_key: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
      private_key: pair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    };
  } catch {
    return undefined;
  }
}
function slhSign(privateKey, domain, value) {
  try {
    const key = C.c.createPrivateKey({ key: C.b64(privateKey), format: "der", type: "pkcs8" });
    if (key.asymmetricKeyType !== SLH) return undefined;
    return C.c.sign(null, input(domain, value), key).toString("base64");
  } catch {
    return undefined;
  }
}
function slhVerify(publicKey, domain, value, signature) {
  try {
    return C.c.verify(null, input(domain, value), C.publicKey(publicKey, SLH), C.b64(signature, 7856));
  } catch {
    return false;
  }
}
const TREE_HEAD = "KIG/tree-head/v1";
function treeHeadBody(head) {
  return { authority: head.authority, tree_size: head.tree_size, root: head.root };
}
// ML-DSA always; SLH-DSA too whenever the caller pins an SLH public key.
function verifyTreeHead(head, mldsaPublicKey, slhPublicKey) {
  try {
    const body = treeHeadBody(C.object(head));
    if (!C.verify(mldsaPublicKey, TREE_HEAD, body, head.signature)) return false;
    if (!slhPublicKey) return true;
    return slhVerify(slhPublicKey, TREE_HEAD, body, head.slh_signature);
  } catch {
    return false;
  }
}
module.exports = {
  leafHash,
  root,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  slhGenerate,
  slhSign,
  slhVerify,
  treeHeadBody,
  verifyTreeHead,
  TREE_HEAD,
};
