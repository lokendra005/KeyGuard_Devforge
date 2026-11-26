# Validation record — 26 November 2026

The final security-fixed submission supersedes the earlier build results below. See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for fixed findings and final gates, and [SUBMISSION.md](SUBMISSION.md) for the tested offline entrypoint. Final tests executed both arm64 and amd64 (the latter through emulation), plus the full command from a clean extracted reviewer archive.

## Executed successfully

- `make build` and `make vet` with Go **1.26.11**, locally installed in the project's ignored cache; the user's system Go installation was not replaced.
- `make test`: real isolated PostgreSQL **16.11**, all unit/integration/model tests under `-race`; dependency resolution disabled (`GOPROXY=off`, `GOSUMDB=off`, vendored modules).
- `scripts/smoke.sh`: actual TLS process and CLI, signed resource creation/transfer, exact retry, quarantine denial, two-distinct-identity recovery, exported history, independent verifier/witness, and process restart retaining state.
- OpenSSL **4.1.0**: independently verified CIRCL ML-DSA-65 signatures and generated signatures accepted by CIRCL; wrong-context negative check passed.
- Exhaustive finite model: **13** reachable guarded states, no forbidden post-revocation commit; unsafe negative control explored **16** states and exposed the race.
- Parser fuzzing: **49,175 executions** during a 10-second configured run (about 11.4 seconds wall time); no failure. Finite fuzzing is not proof of parser correctness.
- `node --check internal/guard/web/app.js`: dashboard JavaScript syntax checked; HTTP tests check static serving and security headers.
- Fresh Docker initialization and API startup: migrations/bootstrap exited zero; PostgreSQL **16.16** on ARM64. Runtime SQL account `kig_app` has INSERT but **not UPDATE** privileges on audit rows.
- Deployed HTTPS readiness, real signed transfer and exported-history verification/witnessing passed through the container's localhost port.
- Precompiled Linux ARM64 unit/model tests passed with `--network none`; full PostgreSQL integration tests also passed inside the scratch image on a private-only network with no internet or Go SDK. Only the optional OpenSSL cross-check skipped there because OpenSSL is absent; it passed on the host.
- Linux **amd64 and arm64** static builds; ARM64 scratch-container execution. The AMD64 binary was cross-compiled, not executed on an AMD64 machine.
- Go vulnerability check after updating dependencies/toolchain: **“No vulnerabilities found.”** This is a point-in-time code-path analysis, not a complete security audit. Initial findings in older Go/pgx/text versions were remediated before release.

## Measurements

Apple M4, macOS ARM64, Go 1.26.11. These are Go benchmark means, **not p95 latency or production SLOs**.

| Benchmark | Observed mean | Sample count / scope |
|---|---:|---|
| ML-DSA-65 signing | 0.292 ms/op | 4,108 iterations; includes raw private-key parsing |
| ML-DSA-65 verification | 0.0839 ms/op | 14,200 iterations; includes public-key parsing |
| PostgreSQL signed transfer pipeline | 5.55 ms/op | 100 sequential transfers; local Unix socket, challenge issuance + signing + execution; no HTTP |

The PostgreSQL benchmark allocated approximately 861 KB/op. The bounded JSONB snapshot and fresh connections make this a correctness-first service; these numbers do not justify large-scale throughput claims. Benchmark over realistic history sizes, network latency and concurrent actors before extending its operating envelope.

Reproduce crypto measurements with `make bench`. Reproduce database measurement with `KIG_BENCH=1 ./scripts/test.sh`. Record your own hardware/results rather than copying these into a different environment's scorecard.

## Cases exercised

Signature/body/audience/context/key substitution; malformed key/signature sizes; duplicate/unknown/trailing/nested JSON; fractional integers; transfer overdraft/overflow/self-transfer and both resource versions; inappropriate roles; enrollment possession; duplicate/mismatched recovery approvals; permanent old-key denial; concurrent identical requests; stale requests racing revocation; role changes after challenge issuance; expired challenge issuance; nonce substitution; session invalidation; evidence mutation/reorder/truncation/forged signed transitions; witness rollback; startup state reconciliation; audit-write failure with transactional rollback; process restart; HTTP size/origin/content-type controls; backward-clock rejection.

## Not claimed or not checked

- Browser visual inspection could not proceed past the local self-signed certificate trust requirement. The browser warning was not bypassed. Layout/responsiveness require a human check after explicitly trusting the local development certificate or installing a correctly issued certificate.
- No universal formal verification of Go, SQL, the compiler or cryptographic implementation; the documented invariant proof is conditional and the executable model is finite.
- No independent penetration test, side-channel audit, clinical validation, external HSM validation, production workload capacity test or arbitrary-network-partition campaign.
- No official hidden evaluator/track-specific adapter contract was available; documented CLI/HTTP entrypoints are implementation contracts, not guessed organizer specifications.
- Witness checks were functionally tested locally. Real administrative independence requires separate custody/hosts.
- Audit records cover successful protected transitions and authority changes. Rejected requests are returned as errors, not immutable independently signed denial receipts. The history verifier checks recorded signatures/state transitions, not proof of executor honesty or unrecorded challenge issuance.
- The GitHub workflow is provided but has not run on GitHub; equivalent local commands were executed.

## Final dependency boundary

Application dependencies are pinned in `go.mod`, checked in `go.sum`, and included in `vendor/` with upstream licenses. Key direct versions: CIRCL 1.6.5, pgx 5.9.2, transparency-dev/merkle 0.0.2; updated x/text 0.41.0. Review the included license files before redistribution. CIRCL's library availability is not certification of this application. A release manifest and SHA-256 checksums accompany the generated binaries/source; keep operator secrets out of reviewer archives.
