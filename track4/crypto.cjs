"use strict";
const c = require("node:crypto");

class Fault extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
function check(condition, code = "INVALID_INPUT") {
  if (!condition) throw new Fault(code);
}
function text(value, max = 4096) {
  check(
    typeof value === "string" &&
      value.isWellFormed() &&
      Buffer.byteLength(value) <= max,
  );
  return value;
}
function integer(value, min, max) {
  check(Number.isSafeInteger(value) && value >= min && value <= max);
  return value;
}
function object(value) {
  check(value !== null && typeof value === "object" && !Array.isArray(value));
  return value;
}
function canonical(value) {
  if (typeof value === "string")
    return JSON.stringify(text(value, 16 * 1024 * 1024));
  if (typeof value === "number") {
    check(Number.isSafeInteger(value));
    return String(value);
  }
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  object(value);
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((k) => canonical(k) + ":" + canonical(value[k]))
      .join(",") +
    "}"
  );
}
// Duplicate names must fail before JSON.parse can silently choose an authority field.
function parse(raw, max = 16 * 1024 * 1024) {
  if (Buffer.isBuffer(raw)) {
    const s = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    raw = s;
  }
  text(raw, max);
  let i = 0;
  function ws() {
    while (" \n\r\t".includes(raw[i]) && i < raw.length) i++;
  }
  function string() {
    const start = i++;
    let escaped = false;
    while (i < raw.length) {
      const x = raw[i++];
      if (!escaped && x === '"')
        return text(JSON.parse(raw.slice(start, i)), max);
      if (!escaped && x === "\\") escaped = true;
      else escaped = false;
    }
    throw new Fault("INVALID_JSON");
  }
  function value(depth) {
    check(depth <= 32, "INVALID_JSON");
    ws();
    if (raw[i] === '"') return string();
    if (raw[i] === "{") {
      i++;
      ws();
      const result = Object.create(null);
      const seen = new Set();
      if (raw[i] === "}") {
        i++;
        return result;
      }
      while (i < raw.length) {
        ws();
        check(raw[i] === '"', "INVALID_JSON");
        const k = string();
        check(!seen.has(k), "DUPLICATE_FIELD");
        seen.add(k);
        ws();
        check(raw[i++] === ":", "INVALID_JSON");
        result[k] = value(depth + 1);
        ws();
        const end = raw[i++];
        if (end === "}") return result;
        check(end === ",", "INVALID_JSON");
      }
    } else if (raw[i] === "[") {
      i++;
      ws();
      const result = [];
      if (raw[i] === "]") {
        i++;
        return result;
      }
      while (i < raw.length) {
        result.push(value(depth + 1));
        ws();
        const end = raw[i++];
        if (end === "]") return result;
        check(end === ",", "INVALID_JSON");
      }
    } else {
      const m =
        /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
          raw.slice(i),
        );
      check(m, "INVALID_JSON");
      i += m[0].length;
      const v = JSON.parse(m[0]);
      if (typeof v === "number") check(Number.isSafeInteger(v), "INVALID_JSON");
      return v;
    }
    throw new Fault("INVALID_JSON");
  }
  const result = value(0);
  ws();
  check(i === raw.length, "INVALID_JSON");
  return result;
}
function b64(s, size, max = 16 * 1024 * 1024) {
  text(s, max * 2);
  const b = Buffer.from(s, "base64");
  check(
    b.toString("base64") === s &&
      b.length <= max &&
      (size === undefined || b.length === size),
    "INVALID_ENCODING",
  );
  return b;
}
function hash(data) {
  return c.createHash("sha384").update(data).digest("hex");
}
function digest(value) {
  return hash(canonical(value));
}
function random() {
  return c.randomBytes(24).toString("hex");
}
function publicKey(encoded, algorithm = "ml-dsa-65") {
  let key;
  try {
    key = c.createPublicKey({
      key: b64(encoded, undefined, 8192),
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Fault("INVALID_KEY");
  }
  check(
    key.asymmetricKeyType === algorithm &&
      key.export({ format: "der", type: "spki" }).equals(b64(encoded)),
    "INVALID_KEY",
  );
  return key;
}
function generate() {
  const pair = c.generateKeyPairSync("ml-dsa-65");
  return {
    public_key: pair.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
    private_key: pair.privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64"),
  };
}
function signatureInput(domain, value) {
  return Buffer.from(canonical([domain, value]));
}
function sign(privateKey, domain, value) {
  const key = c.createPrivateKey({
    key: b64(privateKey, undefined, 8192),
    format: "der",
    type: "pkcs8",
  });
  check(key.asymmetricKeyType === "ml-dsa-65", "INVALID_KEY");
  return c.sign(null, signatureInput(domain, value), key).toString("base64");
}
function verify(key, domain, value, signature) {
  try {
    return c.verify(
      null,
      signatureInput(domain, value),
      publicKey(key),
      b64(signature, 3309),
    );
  } catch {
    return false;
  }
}
function keyID(key) {
  publicKey(key);
  return hash(b64(key));
}
function seal(key, bytes, aad) {
  const nonce = c.randomBytes(12);
  const cipher = c.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(canonical(aad)));
  const body = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return {
    nonce: nonce.toString("base64"),
    body: body.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}
function open(key, packet, aad, max = 16 * 1024 * 1024) {
  try {
    object(packet);
    const decipher = c.createDecipheriv(
      "aes-256-gcm",
      key,
      b64(packet.nonce, 12),
    );
    decipher.setAAD(Buffer.from(canonical(aad)));
    decipher.setAuthTag(b64(packet.tag, 16));
    return Buffer.concat([
      decipher.update(b64(packet.body, undefined, max)),
      decipher.final(),
    ]);
  } catch {
    throw new Fault("INTEGRITY_FAILURE");
  }
}
// ASN.1 SubjectPublicKeyInfo for id-alg-ml-kem-768; only the raw FIPS 203 key is on the judge wire.
const KEM_SPKI = Buffer.from(
  "308204b2300b0609608648016503040402038204a100",
  "hex",
);
function kemKey(raw) {
  const bytes = b64(raw, 1184);
  try {
    return c.createPublicKey({
      key: Buffer.concat([KEM_SPKI, bytes]),
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Fault("INVALID_KEY");
  }
}
function encapsulate(raw) {
  try {
    return c.encapsulate(kemKey(raw));
  } catch {
    throw new Fault("INVALID_KEY");
  }
}
function protectedRead(raw, challenge, body) {
  const { ciphertext, sharedKey } = encapsulate(raw);
  try {
    return {
      ciphertext: ciphertext.toString("base64"),
      proof: c
        .createHmac("sha256", sharedKey)
        .update(text(challenge))
        .update(body)
        .digest("hex"),
    };
  } finally {
    sharedKey.fill(0);
  }
}
module.exports = {
  c,
  Fault,
  check,
  text,
  integer,
  object,
  canonical,
  parse,
  b64,
  hash,
  digest,
  random,
  publicKey,
  generate,
  sign,
  verify,
  keyID,
  seal,
  open,
  encapsulate,
  protectedRead,
  KEM_SPKI,
};
