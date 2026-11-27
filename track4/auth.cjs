"use strict";
const C = require("./crypto.cjs");
function verifyCommand(envelope, context, now, bootstrap = false) {
  C.object(envelope);
  const { signature, ...request } = envelope;
  C.check(
    Object.keys(request).sort().join(",") ===
      "actor,audience,authority,body,epoch,expires,key_id,nonce,version",
    "INVALID_ENVELOPE",
  );
  C.check(
    request.version === 2 && request.authority === context.authority,
    "WRONG_AUTHORITY",
  );
  C.check(request.audience === context.audience, "WRONG_AUDIENCE");
  C.text(request.actor);
  C.text(request.key_id, 96);
  C.text(request.nonce, 128);
  C.check(request.nonce.length >= 16, "INVALID_NONCE");
  C.integer(request.expires, now, now + context.policy.request_lifetime_ms);
  const { actor, key } = context;
  C.check(actor && key && key.actor === actor.id, "UNAUTHORIZED");
  C.check(
    C.verify(
      key.public_key,
      bootstrap ? "KIG/identity-bootstrap/v2" : "KIG/command/v2",
      request,
      signature,
    ),
    "INVALID_SIGNATURE",
  );
  if (
    actor.disabled ||
    key.revoked ||
    now < key.not_before ||
    (key.not_after !== null && now >= key.not_after) ||
    (!bootstrap && request.epoch !== actor.epoch)
  ) {
    const error = new C.Fault("UNAUTHORIZED");
    error.verifiedActor = actor.id;
    error.verifiedKey = key.id;
    error.rule = key.revoked
      ? "revoked_key_use"
      : actor.disabled
        ? "disabled_actor_use"
        : !bootstrap && request.epoch !== actor.epoch
          ? "stale_epoch_use"
          : "expired_key_use";
    throw error;
  }
  if (bootstrap)
    C.check(
      request.epoch === 0 &&
        request.body.op === "info" &&
        request.body.actor === actor.id,
      "UNAUTHORIZED",
    );
  return {
    actor: actor.id,
    role: actor.role,
    key_id: key.id,
    body: C.object(request.body),
    trusted: false,
  };
}
module.exports = { verifyCommand };
