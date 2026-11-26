# Security argument, threat model and limits

## Threat model

Assume the Go executable, PostgreSQL transaction engine/primary, OS, CSPRNG, admitted bootstrap identities and operator custody execute their specified behavior. Attackers can steal an ordinary signing key, alter requests, replay traffic, race revocation, send malformed bodies, control a client, or tamper with exported evidence. A retained witness can detect a history inconsistent with its checkpoint if its custody and signing key remain independent.

Do not assume that signing prevents stolen-key abuse, that a log proves a dishonest server executed truthfully, or that an online verifier can infer the newest authority state from an arbitrary old bundle. Ordinary recovery tolerates compromise of the target key, not collusion of both recovery authorities. The same host holding API and witness keys is a functional integration, not independent custody.

The signature primitive is ML-DSA-65; the whole application is not claimed to meet category 3. Legacy SHA-256 application commitments retain their original bound; new v2 commitments use SHA-384, with an explicit signed transition that leaves historical bytes intact. Recovery is two-person authorization using complete signatures, not threshold signing. The detailed lattice equations, security assumptions, bounded recovery proof and implemented versioned hash upgrade are in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

## Conditional invariant argument

Let `L` be the exclusive PostgreSQL row lock on `kig_authority(id=1)`. Let `E(k)` be a committed protected transition authenticated by key k and `R(k)` its permanent revocation. Failed transactions do not enter the committed history. Commit order, not request arrival or HTTP response order, defines the history.

**Lemma 1 — serialized authority.** Every authority mutation and protected effect obtains `L` before reading current authority and holds it until commit/rollback. Conflicting transactions cannot overlap their authority-critical sections. PostgreSQL READ COMMITTED performs the post-lock read after prior committed changes; replicas and cached role decisions are not used.

**Lemma 2 — authorization at the effect.** `Apply` checks current subject, key and role in that section. It returns no effect for a revoked key. Recovery never changes an old key back to active. Because the effect is in the same transaction, no unguarded interval exists between the decision and effect commit.

**Theorem — no post-revocation old-key effect.** Suppose R(k) commits before E(k). By Lemma 1, E's critical section reads state after R (or else E would have held L and committed before R). By Lemma 2, it rejects k. Therefore such a committed E cannot exist, a contradiction. This applies only to the modeled database-backed resource transition. A write delegated to another service would require its own fence/transaction protocol.

**At-most-once theorem.** Let O be the length-prefix-derived `(subject,operation)` key. Under L, the first successful transition records O and consumes its challenge atomically with the effect. A later same-digest retry returns that recorded result without `Apply`; a different digest conflicts. Rollback undoes all four changes. Induction over serialized commits establishes at most one effect per O. This is not exactly-once remote delivery.

**Conservation theorem.** For a valid transfer amount a between distinct balances x,y, the preconditions are `a>0`, `x>=a`, `y<=MaxBalance-a`. New balances are `x-a,y+a`, so the sum is unchanged and both remain in range. These are integer operations; no rounding. Resource creation is separately authorized issuance.

**Audit coupling.** Event insertion failure aborts the same transaction as effect and idempotency changes. Successful commits therefore have an event, under database integrity assumptions. Merkle/checkpoint verification detects changes relative to trusted signatures/checkpoints under cryptographic assumptions. It cannot prove unobserved events or a malicious executor's behavior.

These are proofs of the specified transition discipline under stated assumptions, not mechanically verified proofs of every Go/SQL line or of ML-DSA. `spec/model_test.go` exhaustively explores the finite action-versus-revocation graph and confirms the invariant in 13 reachable guarded states. The intentionally unsafe version exposes a stale-check counterexample. Integration tests check the implementation's correspondence through concurrent processes/connections, fault injection and replay. Neither finite exploration nor testing covers all possible programs/environments.

`spec/recovery_test.go` additionally explores two competing replacement keys, two recovery approvers and one epoch-changing invalidation in every permitted order (124 reachable guarded states). Its unsafe negative control removes the epoch equality check and exposes a stale approval; it also checks the explicit A-first, B-first, B-second, A-second takeover trace. This finite abstraction does not prove arbitrary numbers of actors, database behavior or cryptographic assumptions.

## Attack coverage and limitations

| Attack/failure | Handling | Boundary |
|---|---|---|
| Stolen ordinary key | Permanent revoke/quarantine; fresh final authority | Work committed before incident/revoke cannot be undone |
| Payload/audience/action substitution | Exact field/body binding and contexts | Requires cryptographic/library/serialization assumptions |
| Duplicate request/lost response | Persist exact request + transactional idempotency | Caller generating another operation ID intentionally requests another operation |
| Role changes with outstanding challenge | Role checked again at commit | Changes to recovery roots use a separate reviewed procedure |
| Revoked observer token | Live session subject/key check on each read | Data already received cannot be erased |
| Recovery misuse | Two distinct approved actors + new-key possession | Two compromised recovery actors can recover targets |
| Audit tamper/truncation/fork | Signed full-history replay + retained prefix | Independent anchor required; no anchor means no external freshness claim |
| Audit insert/disk failure | Whole transaction rolls back | Physical database corruption remains an operational concern |
| Stale restored database | Startup comparison and explicit external witness anchor | No system can detect an unobserved lost suffix without independent durable knowledge |
| Database unavailable | Fail closed, bounded timeouts | Availability is sacrificed intentionally |
| Backward clock step | Mutating transitions fail closed on regressed event time | Clock must be restored; expiry uses primary time |
| Resource exhaustion | Size, nesting, pending/session/event/concurrency bounds | Not a DDoS appliance; deployment still needs network admission/rate policy |
| Malicious database superuser/API host | Outside enforcement trust model | Witness detects some history changes, not fabricated truthful execution |

## Engineering decisions from the blueprint

- One executable and one package for the small shared authority core; CLI, HTTP and replay use the same documented transition rules. Independent tests assert conservation and denial behavior, not only replay equality.
- One bounded JSONB authority aggregate rather than many tables/ORM: a single clear lock and atomic snapshot reduce race surfaces. All events are separate immutable rows; runtime role cannot UPDATE/DELETE them. Reads currently acquire the same lock for consistent live authorization. This favors correctness and reviewability over throughput.
- One short-lived database connection per operation, bounded by HTTP concurrency. No connection-pool abstraction or worker fleet before measuring a need. Do not advertise high throughput without measurement.
- A fixed length-prefixed signing representation replaces the blueprint's optional JCS route. The exact grammar is smaller and avoids a canonicalization dependency. Base64 exact body bytes prevent serializer whitespace mutations.
- Audit publication/signing is export-driven, with a separately runnable witness. Full history is replayed instead of implementing several unneeded proof endpoints. Add streaming/checkpoint storage before increasing bounded histories.
- No JWT authorization cache, blockchain, custom cryptographic primitive, remote effect hidden behind an outbox, or automatic trust-root regeneration.
- The dashboard is an observer and explicit signed-request submitter; it cannot sign on behalf of users.

## Research that informed implementation

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): pure ML-DSA and context separation; implementation in `protocol.go`.
- [CIRCL ML-DSA-65](https://pkg.go.dev/github.com/cloudflare/circl/sign/mldsa/mldsa65): supported API; library is not a certification or audit of this application.
- [OpenSSL ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/): independently exercised context-aware sign/verify in `interop_test.go`.
- [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final): identity possession separated from current authorization.
- [Zanzibar](https://www.usenix.org/conference/atc19/presentation/pang): authorization consistency motivation. The implementation uses local transactional authority, not a claim to reproduce Zanzibar.
- [PostgreSQL explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html): row-lock semantics underlying the invariant.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): replay and sender binding considerations. The application's envelope is not advertised as interoperable DPoP.
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) and [Merkle library](https://github.com/transparency-dev/merkle): domain-separated history commitments. Application checkpoints are a versioned custom format, not CT protocol conformance.

Before use with real sensitive workflows: independent review, secure root custody, deployment hardening, restore rehearsal, bounded-load measurement and an explicit mapping of every real side effect to the stated enforcement boundary are required. There is no claim to handle every possible edge case or to guarantee competition outcomes.

## Versioned cutover guarantees

The [v2 specification](PROTOCOL_V2.md) defines the SHA-384 commitments, matching contexts, retained-key binding and atomic migration predicate. The migration checks the actual latest prefix under the same lock as the state/effect commit. Old requests are then denied; legacy operation records remain reserved. A database trigger fences original binaries, while an externally pinned minimum protocol and retained witness checkpoint reject restored legacy state. These controls assume trusted runtime/owner administration; an owner capable of disabling controls is outside the enforcement model. Historical signatures are not retroactively strengthened.
