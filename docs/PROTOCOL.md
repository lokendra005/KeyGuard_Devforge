# Legacy protocol v1 and shared API contract

Protocol v2 is the default for new clients and installations. See [the v2 specification and migration runbook](PROTOCOL_V2.md) for its exact bytes and cutover rules. This document retains the original v1 encoding for historical verification; the action semantics and HTTP routes remain shared. v1 writes are rejected after cutover.

## Cryptography and exact bytes

Algorithm: pure ML-DSA-65, CIRCL's pinned implementation, randomized signing. Public keys and signatures use the raw standardized encodings. Their sizes are library constants (1952 and 3309 bytes respectively). Private keys remain local files with mode 0600. Base64 in JSON is the Go standard padded encoding, not PEM. Key IDs are lowercase SHA-256 of the raw public key.

A signed request has `envelope`, `body`, `signature`. **Body is base64 of exact UTF-8 JSON object bytes**, avoiding whitespace/key-order changes by transport serializers. Its SHA-256 must equal `envelope.body_hash`. The envelope fields, in signing order, are:

```
"KIG/v1", decimal(version), algorithm, subject, key_id, audience, action,
resource, decimal(resource_version), body_hash, challenge, operation, decimal(expires)
```

Encode each string as `uint32 big-endian byte length || UTF-8 bytes`. Concatenate these fields, then sign directly with ML-DSA context `KIG/action/v1`. No JSON canonicalization, delimiter concatenation, homemade prehash, or HTTP header signing is involved. Every integer's canonical decimal spelling comes from a typed Go integer. All identifiers are ASCII `[A-Za-z0-9_.:-]{1,128}`. Version is exactly 1; algorithm exactly `ML-DSA-65`; audience is the configured deployment identity.

Contexts:

| Purpose | Context |
|---|---|
| Action | `KIG/action/v1` |
| Challenge request | `KIG/challenge/v1` |
| Enrollment proof | `KIG/enroll/v1` |
| Log checkpoint | `KIG/checkpoint/v1` |
| Witness endorsement | `KIG/witness/v1` |

The body digest, Merkle hashes, transport and key custody limit the composed system's assurances; ML-DSA-65 alone does not make every component offer the same security level. TLS certificates are classical ECDSA in local setup. There is no FIPS module certification claim.

## Challenge and execution

1. Client creates a cryptographically random operation ID and expiry (default now +60 seconds).
2. Sign the envelope with empty challenge using the challenge context and send `POST /v1/challenges`.
3. Server validates current signer/role and signature under the authority lock. Expiry must be in `(database_now, database_now+120s]`. It stores a random 256-bit challenge bound to the complete envelope intent, including body digest and operation ID.
4. Client inserts that challenge and signs the envelope using the action context.
5. Persist the entire request before `POST /v1/actions`.
6. Server locks current authority, checks the registered signer and current role, verifies the signature, resolves any exact committed retry, and otherwise checks expiry/challenge/resource constraints. Apply effect + consume challenge + persist operation + audit event atomically.

Challenge issuance is not authorization for future execution. Unused challenges expire. Capacity is bounded at 4096 pending challenges, 1000 retained active observer sessions and 100,000 total event leaves. Capacity errors fail closed; operators must plan migration before reaching the event limit. Full-history export is also limited to 64 MiB by the CLI; whichever bound is reached first requires a reviewed archival/streaming release, not deleting replay guards. Read `SECURITY.md` for the scaling boundary.

Composite idempotency keys are hashes of length-prefixed `(subject, operation)`; separators in identifiers cannot create ambiguous keys. Reusing an ID for another request is `CONFLICT`. A revoked signer cannot retrieve an old receipt through the execution path. Lost responses require exact-file retry, not a fresh `act`.

## Actions and bodies

All actions other than transfers require `resource_version=0`. Unknown body fields, duplicate JSON keys at any depth, trailing JSON, malformed encodings, nesting beyond 32 levels and bodies over 1 MiB are rejected.

| Action | Role | Resource | Body |
|---|---|---|---|
| `resource.create` | admin | new resource ID | `{"balance":1000}` |
| `resource.transfer` | writer/admin | source ID | `{"to":"reserve","amount":25,"to_version":1}` |
| `key.enroll` | admin | new subject | Enrollment below; only writer/auditor roles |
| `key.revoke` | admin/recovery | registered key fingerprint | `{}` |
| `subject.quarantine` | admin/recovery | subject ID | `{}` |
| `subject.role` | admin | existing writer/auditor | `{"role":"auditor"}` or writer |
| `recovery.approve` | recovery | target subject | Shared recovery body below |
| `session.create` | any active identity | own subject ID | `{"token_hash":"lowercase SHA256 of random token"}` |

Balances are signed 64-bit integers constrained to `[0,10^12]`; transfer amounts are positive, bounded and cannot overdraft or overflow the destination. Transfers require current source and destination versions; each increases by one. No floating point, fractional units or same-resource transfers. Resource creation is explicit privileged issuance; only transfers conserve total value.

Enrollment: `{subject,role,public,proof}`. Proof signs length-prefixed `("KIG/enrollment/v1",subject,role,raw-public-bytes)` using the new key and enrollment context. Key/public identity cannot be reused. Bootstrap is an explicit trusted installer operation requiring one admin and two distinct recovery subjects.

Recovery body: `{id,expires,enrollment}`. Two distinct active recovery identities must submit the **same** body (same ID, expiry, target role and new public key). The second approval revokes every old key for the target, creates the new key and advances the epoch. First approval alone does not restore access. Old keys cannot authorize recovery. Administrative/recovery-root roles cannot be minted by routine enrollment or role edits. Routine revocation of recovery roots is deliberately denied: replacement of those roots requires a reviewed operational re-bootstrap, not an insecure hidden override.

Observer sessions are random 256-bit bearer tokens, hashed in state and bound to issuing subject/key. They expire after 30 minutes. Every read checks the live subject/key and requires admin/auditor/recovery. Session creation by a writer does not grant observation. Sessions cannot mutate anything. The server does not log tokens; prefer `KIG_TOKEN` to command arguments. Logout clears browser memory; revoke/quarantine invalidates server access.

## HTTP

- `GET /healthz`: process availability.
- `GET /readyz`: authoritative state/trust/anchor transaction works.
- `POST /v1/challenges`, `POST /v1/actions`: exact signed request, `Content-Type: application/json`.
- `GET /v1/state`, `GET /v1/evidence`: `Authorization: Bearer <token>`.
- `GET /`: embedded dashboard; no third-party assets.

Success: HTTP 200 JSON. Failures: `{"code":"..."}`; invalid protocol/body 400, invalid/revoked auth 401, policy denial 403, stale/replay/conflict 409, capacity 429, unavailable/unknown outcome 503. Unknown implementation/storage failures return 500 without leaking database details. `OUTCOME_UNKNOWN` means retry the exact signed file to resolve the result. Cross-origin browser requests are rejected; no CORS wildcard. Server caps body/header sizes and concurrent HTTP work, and has header/read/write/request timeouts.

## Evidence

An event is exact JSON bytes with sequence, database Unix time, and either genesis or `(signed request, result)`. Sequence zero is genesis. The authority counter, unlike a SQL sequence allocated before commit, orders effects under the same guard lock. Sequence and time are checked during replay.

Merkle leaf = SHA256(`0x00 || event_bytes`); parent = SHA256(`0x01 || left || right`). `transparency-dev/merkle` computes the compact RFC6962 root. A checkpoint signs length-prefixed `("KIG/checkpoint/v1",audience,decimal(size),root)`.

The bundle contains all event bytes and the checkpoint. The verifier validates signatures, hashes, sequence, context, expiry, no repeated challenge/operation, current roles/revocation at each historical transition, and deterministic results. A separately supplied earlier checkpoint must match the bundle prefix. Witnesses retain their last checkpoint durably and reject rollback/fork before signing an extension. An embedded key never becomes a trusted audit key: trust is an explicit separate file. Witness state requires its separate trusted witness public key.

Full-history replay intentionally substitutes for individual Merkle inclusion/consistency endpoints in this release. It is linear, inspectable and bounded; it is not a scalable transparency network. Audit signing occurs on export; commits are durable beforehand. No UI label claims independent witnessing until a separate witness has actually run.
