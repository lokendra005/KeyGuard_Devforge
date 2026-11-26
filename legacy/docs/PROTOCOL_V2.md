# Protocol v2 and SHA-384 migration

Implemented 27 November 2026. Fresh CLI initializations and clients use v2. Existing v1 databases remain v1 until an administrator submits the explicit, audited cutover below. No key is regenerated, no event is rewritten, and no completed operation record is deleted. The old [v1 byte specification](PROTOCOL.md) remains the verification contract for historical evidence.

## Signed suite and exact bytes

The sole v2 suite is `ML-DSA-65/SHA-384`, with algorithm `ML-DSA-65` and envelope `version: 2`. Unknown versions/suites, mixed fields and mismatched signature contexts fail closed. There is no automatic client fallback or unauthenticated negotiation.

Each string is encoded as a four-byte big-endian byte length followed by its bytes. The fixed v2 request signing order is:

```
"KIG/v2", "2", suite, algorithm, subject, key_id, key_commitment,
audience, action, resource, decimal(resource_version), body_hash,
challenge, operation, decimal(expires)
```

`body` is still base64 of exact UTF-8 JSON object bytes. `body_hash` is lowercase SHA-384 of those bytes (96 hex characters). `key_commitment` is SHA-384 of the full registered raw ML-DSA public key. Both the signature and this commitment must match that registered key.

Existing `key_id = SHA256(raw_public_key)` values remain stable lookup handles, including for new keys. They are not the v2 proof of public-key binding: the signed SHA-384 commitment and signature over the envelope supply that binding. A duplicate key ID is rejected on enrollment; a hypothetical lookup collision cannot substitute another public key or bypass its signature check. Keeping the handles preserves revocation targets, identities and historical references without changing key material.

| Use | v2 definition |
|---|---|
| Action/challenge signature | `KIG/action/v2` / `KIG/challenge/v2` |
| Body and full public-key commitments | SHA-384 of exact bytes |
| Challenge intent | SHA-384 of v2 signing bytes with empty challenge |
| Request digest | SHA-384 of v2 signing bytes |
| Operation index | SHA-384 of length-prefixed `(subject,operation)` |
| Recovery proposal digest | SHA-384 of the typed recovery body's Go JSON encoding |
| Observer-token storage | SHA-384 of the random token's string bytes |
| Enrollment proof | `KIG/enroll/v2` over `("KIG/enrollment/v2",suite,subject,role,raw_public_bytes)` |
| Checkpoint signature | `KIG/checkpoint/v2` |
| Witness endorsement | `KIG/witness/v2` over the checkpoint's signing bytes |

Enrollment objects include `version: 2`. v1 proofs are rejected inside v2 enrollment/recovery actions. ML-DSA keys/signatures retain their standardized lengths and randomized signing. Random operation IDs, challenges and session tokens remain 256 bits; these are guessing/non-reuse values, not collision-based content commitments. The primitive is unchanged; application commitments use [SHA-384 from FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

The HTTP transport routes remain `/v1/challenges`, `/v1/actions`, `/v1/state` and `/v1/evidence`. That stable API path does not select the cryptographic suite. The signed envelope and authoritative protocol state do. All existing action/body rules continue, with v2 proofs and digest widths as above. `protocol.upgrade` is the only cross-version action admitted on a v1 authority, and only with a v2 signature by a current administrator.

## Audit history and witness continuity

A v2 checkpoint adds `version: 2` and `suite: "ML-DSA-65/SHA-384"`. Its signing tuple is:

```
"KIG/checkpoint/v2", suite, audience, decimal(size), root
```

The 96-character root uses SHA-384 with leaf prefix `0x00` and internal-node prefix `0x01`, preserving the [RFC9162 tree shape](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1). This is the application's versioned tree, not a claim of CT wire-protocol conformance. The tree covers the exact original event bytes, including the entire legacy prefix. Older checkpoint objects omit version/suite and retain their original SHA-256 root and signing bytes.

The verifier replays the history's protocol state. A fresh v2 genesis must name the exact suite. A migrated history must contain a valid cutover. No v1 action may occur after it, no later cutover is allowed, and the final checkpoint version must equal the replayed protocol. Even an audit-key holder cannot simply relabel v2 history with a validly signed v1 checkpoint and have this verifier accept it.

An old v1 anchor is checked by recomputing the old SHA-256 prefix; a v2 anchor uses SHA-384. A witness can advance from a retained v1 receipt to v2, then refuses a v1 checkpoint or an inconsistent prefix. It signs new endorsements in the checkpoint's matching context. Original receipts remain verifiable with their original context. The CLI defaults to minimum protocol 2; `verify --min-protocol 1` explicitly permits historical v1-only evidence. Low-level `VerifyBundle` supports both for compatibility; callers must inspect the returned version or supply an appropriate retained anchor.

The upgrade does not retroactively improve the security of signatures/commitments that were created under v1. It pins the observed historical bytes under a stronger commitment at cutover and uses the stronger suite for subsequent work. Independent witness custody is still needed for independent rollback/fork detection; an unobserved lost suffix cannot be detected by a retained older prefix alone.

## One atomic cutover

`upgrade-body` verifies supplied evidence against a separately trusted audit key and optional retained anchor, then creates:

```json
{
  "version": 2,
  "suite": "ML-DSA-65/SHA-384",
  "previous": {"audience": "...", "size": 42, "root": "...", "signature": "..."},
  "history_root": "SHA-384 Merkle root of the exact same prefix"
}
```

The administrator signs that exact body with a v2 envelope for action `protocol.upgrade`, resource `protocol`, resource version 0. This makes the migration body itself SHA-384-bound rather than relying on a v1 body hash. The prior audit signature authenticates the checkpoint; it is evidence, not a second administrative vote. The policy is one currently authorized administrator, whose normal powers already govern this deployment. Two-person key recovery remains a separate policy.

Under the authority row lock the server checks the signed checkpoint, its audience and size, both roots against the actual stored event prefix, and all normal signer/challenge/expiry conditions. The checkpoint must be the latest committed prefix. A concurrent protected write makes a stale migration fail; challenge issuance and read-only observation do not append events.

On success, the same transaction:

1. Advances authority/schema protocol to 2 and increments every member's epoch.
2. Invalidates every outstanding challenge and observer session.
3. Removes pending recovery proposals while retaining completed recovery records.
4. Preserves all identities, keys, revoked flags, roles, resource balances/versions and prior operation records.
5. Records the cutover operation and its signed event once.

Any failure rolls everything back. Retrying the exact persisted v2 cutover request returns the original result without another cutover, while the administrator retains authority. A second new cutover request is denied. Original v1 requests are rejected after cutover, including receipt retries. To resolve a pre-cutover uncertain outcome, inspect verified history for its subject/operation; never create a new operation ID merely to retry. A v2 request reusing a committed v1 subject/operation is rejected with `CONFLICT`. The offline verifier enforces the same cross-version non-reuse rule.

## Old binaries and restored databases

The owner-run schema migration permits schema versions 1/2 and installs a trigger. New runtime transactions set a transaction-local compatibility marker; once schema version 2 is committed, the trigger requires that marker and matching v2 state, and rejects any schema downgrade. An original v1 executable never supplies the marker and cannot commit an authority update after cutover. The guard is a compatibility fence, not protection against a malicious database owner who can disable triggers or drop tables.

A full old backup can restore the old metadata and triggers. Therefore the minimum accepted version must also live outside the database. `serve --min-protocol 2` is the default; Compose and `scripts/local.sh` use `KIG_MIN_PROTOCOL=2` by default. Readiness and every runtime authority transaction reject a restored v1 database. Configure an independently retained v2 witness anchor as well to detect rollback within the v2 era. Neither protection relies on automatically trusting a checkpoint from the restored database.

## Operator migration sequence

Keep an owner-level database backup and the pre-cutover checkpoint under separate custody. Stop ordinary mutating clients for the short cutover window. Do not remove the database volume, rerun `init` over existing keys, or regenerate a genesis.

1. Build the new binary/image. Run `kig migrate` using the database owner credentials to install the schema guard; this preserves authority and history. Run it again safely if interrupted. For Compose, rebuild `api`, then run the `migrate` service with the new image. The restricted runtime credentials cannot perform DDL.
2. Start the new server against the existing database with **explicit** `--min-protocol 1` only during migration. For Compose/local scripts, set `KIG_MIN_PROTOCOL=1`. Existing v1 clients must explicitly use `--protocol 1`; new clients never automatically fall back. Existing key files are used as-is.
3. Create the observer session before exporting the checkpoint, because session creation is audited. Generate the migration body and submit it as follows (adjust origin/CA/key paths to the deployment):

```sh
export KIG_TOKEN=$(./dist/kig session --protocol 1 --url https://127.0.0.1:8443 \
  --ca .local/tls-cert.pem --key .local/observer.json)
./dist/kig export --url https://127.0.0.1:8443 --ca .local/tls-cert.pem \
  --out .local/pre-v2-evidence.json
./dist/kig upgrade-body --bundle .local/pre-v2-evidence.json \
  --trust .local/audit-public.json --out .local/upgrade-v2.json
./dist/kig act --protocol 2 --url https://127.0.0.1:8443 --ca .local/tls-cert.pem \
  --key .local/admin.json --action protocol.upgrade --resource protocol \
  --body @.local/upgrade-v2.json --out .local/upgrade-v2-request.json
```

Supply `upgrade-body --anchor <retained receipt> --witness-trust <witness public key>` when an independent anchor exists. If submission returns an unknown outcome, retry with `submit --request .local/upgrade-v2-request.json`. Do not regenerate an operation. If it is rejected as stale, re-export and create a new proposal/request with new output paths after quiescing writers; the failed request had no effect.

4. Obtain a new observer session with protocol 2, export evidence, verify it against the previous anchor, and advance the independently held witness receipt using `kig witness`. The former session and pending recovery approvals are intentionally invalidated. Generate new enrollment/recovery proofs using the default v2 CLI for any fresh recovery.
5. Restart with `--min-protocol 2` (or unset `KIG_MIN_PROTOCOL`, which defaults to 2), and configure the newly retained witness receipt through `--anchor` and `--witness-trust`. Verify readiness and a v2 operation before resuming clients. Secure the external minimum-version setting against rollback with the deployment configuration. Do not leave compatibility mode enabled after migration.

The shipped migration smoke test executes this path with actual TLS, CLI, original key-file comparisons, old-session rejection, v1 evidence verification, exact migration retry, witness advancement and a v2-pinned restart. Backups of a pre-v2 database are historical evidence/recovery inputs; they are not safe substitutes for the live post-cutover state without reconciliation of all later effects.

## Reviewer checks and guarantee boundary

`make crypto` checks the SHA-384 known answer, fixed Merkle leaf, tree shapes against a separate recursive oracle, signed suite/context/key binding, the independent ML-DSA corpus and finite models. `make test` additionally exercises:

- Original schema upgrade and idempotent DDL without rewriting event bytes.
- Successful cutover with unchanged keys/history and retained idempotency records.
- Bad suites/versions, wrong commitments, corrupt predecessor signatures and unauthorized migration.
- Stale prefixes, simultaneous legacy writes, failed audit insertion and exact retry.
- Old challenge/session/recovery invalidation and fresh v2 recovery using existing identities.
- Old-binary writes, schema downgrade attempts and a simulated full v1 backup restore.
- v1/v2 operation reuse in both the online authority and offline replay.
- Legacy-to-v2 witness continuity and validly signed checkpoint downgrade attempts.

`scripts/offline-review.sh --docker` executes the embedded tests and the migration smoke workflow with bundled images and no downloads. `--network none` encloses the complete CLI/TLS workflow. This is tested conditional assurance, not independent certification, a universal program proof, or a promise that every component of the deployment has a uniform NIST category.
