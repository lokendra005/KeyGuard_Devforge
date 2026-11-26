# Security reviews — 26–27 November 2026

Scope: Key Identity Guard's protocol/parser, authority transitions, PostgreSQL serialization, recovery, audit replay, file IO, CLI/HTTP boundary and offline packaging. Expected use is the documented bounded single-authority deployment. This is an implementation review and adversarial validation, not an independent third-party certification.

## Confirmed findings fixed

1. **Stale partial recovery could override newer keys.** Reproduced by approving proposal A once, completing proposal B, then completing A with a second actor. Proposals now retain the target's epoch; later recovery, quarantine, role changes or key revocation invalidate earlier partial approval. Concurrent competing proposals yield one completed recovery. Legacy epoch-less partial approvals remain unusable; valid older historical state is reconciled explicitly.
2. **Clock regression only guarded protected writes.** Read/session access, challenge issuance and readiness could proceed against regressed time. The common transaction boundary now checks and persists primary-database time for all successful operations. Tests exercise reads, evidence export, readiness, issuance and execution.
3. **JSON aliases and null scalars silently changed meaning.** Go's decoder accepted field-name case variants and null integer values. Typed schema checks now require exact field spelling and reject null scalars, alongside duplicate/unknown/trailing/depth/UTF-8 checks. Typed roundtrip fuzzing checks that accepted requests preserve meaning.
4. **Startup reconciliation omitted sessions.** An injected unaudited session could survive startup. Replay reconciliation now compares session state as well as identities, keys, resources, recoveries and operation records. Tests inject both sessions and recovery metadata and require refusal.
5. **Audit capacity exceeded the verifier's file/transport budget.** Event-count limits alone allowed histories too large to read back. A 32 MiB aggregate raw-event budget now limits commits and exported trees; capacity rejection rolls back the effect and nonce. The resulting base64 export fits the 64 MiB reader limit. Fault-injection verifies retry after capacity failure.
6. **File validation reopened paths after checking them.** Readers now bound actual bytes and inspect the same open file descriptor; private-key permissions and key consistency are checked against that read. Tests cover oversized files, insecure key permissions, and refusal to overwrite symlink targets.
7. **Expanded private-key decoding trusted more than length checks established.** The library decoder accepts the packed size without validating all components. Signing now checks the stored SHAKE256 public-key hash and eta=4 secret-coefficient bounds, retains the rederived public-key comparison, and verifies each resulting signature before returning it. A bounded-rejection-loop panic is converted to an error. Corrupted hash/coefficient tests require rejection; corrupted rounding-component tests require either a valid signature or an error. This is not full expanded-key consistency validation or a physical-fault countermeasure.

Compatibility improvement: `application/json; charset=utf-8` is accepted, while non-JSON media types remain rejected. CLI readiness removes brittle smoke-test dependence on curl and makes the complete workflow executable inside the offline database image.

## Regression and submission gates

- Build, vet and full Go race-enabled database/adversarial/model suite: passed.
- OpenSSL independent ML-DSA sign/verify interoperability: passed on host.
- Current Go vulnerability scan: no vulnerabilities found.
- ARM64 standalone full database suite and network-disabled TLS smoke workflow: passed.
- AMD64 standalone full database suite and network-disabled TLS smoke workflow: passed under emulation.
- Typed-request fuzzing: 14,630 executions; strict-JSON fuzzing: 19,249 executions; no failures in the final bounded runs.
- Clean extracted reviewer archive: all checksums passed; the full offline command passed.
- Clean extracted source: built successfully with empty build/module caches and module downloads disabled.

Raw logs are included so reviewers can distinguish executed checks from claims. Tests cover replay, concurrent consumers, revocation races, wrong signatures/contexts, transfer bounds/conservation, recovery approvals, persisted-state tampering, failure rollback, witness forks, parser ambiguity and capacity limits.

## Mathematical assurance follow-up

The follow-up prioritizes algorithms and research over UI. The full race-enabled suite and host OpenSSL interoperability passed after signing hardening. `TestIndependentMLDSAVectors` passes 25 NIST key-generation answers, 15 exact deterministic signature answers, checks of all 30 supplied NIST signing outputs, and 225 verification cases (82 valid, 143 invalid). The latter includes the entire pinned 210-case Wycheproof corpus. Public test keys and vectors are embedded into reviewer binaries and their upstream revisions/checksums are recorded in the fixture. `TestRecoveryEpochModel` explores 124 guarded states; removing the guard exposes a stale-approval counterexample across 106 unsafe states.

The rebuilt arm64 and amd64 binaries passed the full offline database/crypto/model suites and network-disabled end-to-end workflow; amd64 ran under emulation. The verifier fuzz target ran 1,612 executions in a bounded 20-second campaign without failure. Updated Apple M4 measurements including signing self-verification were 0.397489 ms/sign and 0.086586 ms/verify. The follow-up logs use the `math-` prefix in the archive's `validation/` directory; older logs are retained as historical evidence, not relabeled as new executions.

See [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) for the derivations and assumptions. No category-3 claim is made for the complete SHA-256-based v1 protocol; the 27 November follow-up below implements the versioned SHA-384 upgrade. Existing operator keys, signatures, identities and historical evidence retain their original format.

## Remaining limits

No official hidden evaluator contract was supplied. No independent penetration test, universal formal proof, hardware side-channel assessment or production-scale load qualification was performed. Browser visual QA remains unverified because the local self-signed certificate was not bypassed. Audit/witness custody must be independent for independent rollback assurance; a retained prefix cannot reveal an unobserved lost suffix. Ordinary key compromise is tolerated only within the documented revoke/recovery model; both recovery authorities or the trusted server/database being compromised remain outside that guarantee.

## SHA-384 v2 implementation — 27 November 2026

Fresh installs and clients default to v2. Existing v1 state changes only through an administrator-signed v2 `protocol.upgrade` action binding both the latest signed legacy checkpoint and the SHA-384 root of its exact event prefix. The transaction preserves keys, identities, resources, completed recovery records and operation records; it invalidates pending challenges, sessions and partial recoveries. The full byte specification, trust boundaries and operator sequence are in [PROTOCOL_V2.md](PROTOCOL_V2.md).

The new regression coverage passes: SHA-384 known answers and independent tree-shape checks; unknown suite/version/context/key substitutions; original-schema migration and idempotent DDL; unchanged history/key checks; stale-prefix rejection; simultaneous v1-write/cutover outcomes; audit-insert failure rollback; cross-version operation reuse in execution and replay; fresh v2 recovery; invalidation of legacy proofs/sessions/challenges; older-writer and schema-downgrade denial; simulated full old-backup restore against an external version pin; witness continuity and validly signed checkpoint downgrade rejection.

Build/vet, the full race-enabled PostgreSQL suite, focused cryptographic checks and the actual CLI/TLS migration smoke workflow passed. Both Linux arm64 and amd64 standalone full suites and `--network none` migration workflows passed; amd64 was executed under emulation. Typed-request fuzzing with v2 fields ran 9,839 executions without failure in a bounded 20-second campaign. Independent NIST/Wycheproof vectors remain embedded and mandatory; OpenSSL remains optional inside the offline images and passed on the host.

The archive's `validation/v2-*.log` files record this implementation's runs. Earlier validation files are historical. The existing local deployment's live cutover is a separate operator action, not something test success or installing the new binary performs automatically. Keep the external minimum version pinned to 2 after an approved cutover, and retain an independent witness anchor; a database guard alone cannot detect a complete old backup restore. Historical v1 signatures retain their original security bound. No independent certification or universal program proof is claimed.
