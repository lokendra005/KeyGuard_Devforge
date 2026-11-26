# Offline reviewer runbook

## Source checkout

Install Node 24.11.1 using `scripts/install-node.sh` (verified official hashes), or provide that runtime yourself. Production/test code uses Node built-ins only. From the repository root:

```sh
./scripts/demo.sh
```

This runs the real core, HTTP/CLI delivery, independent-node leases, actual SIGKILL crash recovery, malformed-input and migration/rotation adversarial tests, 225 independent ML-DSA vectors, two independent synthetic detector holdouts (12,000 and 13,200 evaluation events) and performance measurements. It creates only disposable test state. No external API key is needed.

For the organizer's independently supplied toolkit and Python environment:

```sh
python3.12 /path/to/Track-4-Toolkit/validate.py --entry "$PWD/track4_service.cjs"
python3.12 track4/test/interop.py
```

The second command requires the organizer's `pqcrypto==0.4.0`. It generates 16 independent ML-KEM keypairs, decapsulates the actual adapter response and recomputes the exact HMAC. The toolkit is pinned at commit `8901dfbdbfe048853e0bfa25b60583d1e6617a63`; its public validator does not award scores or test all competition goals.

The root adapter accepts one JSON request and returns one JSON response per process. State persists under `TRACK4_STATE_DIR/keyguard-track4` (OS temp directory fallback). Trusted worker setup atomically resets that scenario; malformed setup leaves the prior scenario intact. Expected validation/policy errors return structured JSON with exit zero; unexpected internal/storage errors remain nonzero. CLI initialization never performs this scenario reset. SQLite's specific experimental notice is suppressed without suppressing unrelated warnings.

## Packaged offline runtime

Download `keyguard-reviewer.tar.gz` and `REVIEWER-SHA256SUMS` from the [review-v3 release](https://github.com/lokendra005/KeyGuard_Devforge/releases/tag/review-v3). Verify the archive, extract into an empty directory, then:

```sh
sha256sum -c SHA256SUMS
./scripts/demo.sh --docker
KIG_REVIEW_ARCH=amd64 ./scripts/demo.sh --docker
```

Docker must already be installed. Both Node 24.11.1 images are bundled; no pull or package installation occurs during review. The runner uses `--network none`, an unprivileged UID, a read-only root/source, dropped capabilities and writable tmpfs. Socket tests use container-local loopback. To run only regressions/vectors use `scripts/track4-review.sh --docker`.

`scripts/track4-container-adapter.cjs` contains no policy implementation; it transports stdin/stdout to the root adapter in a fresh Linux container. With the packaged image loaded, the external validator can use this path as `--entry`. Set `NODE="$PWD/scripts/track4-container-adapter.cjs"` for the Python oracle to use the same transport.

## Evidence and deliverables

[Committed evidence](../evidence/README.md) includes architecture-specific runs, the public validator, independent oracle and held-out detector metrics. `scripts/collect-evidence.sh --docker` regenerates the local checks; set `TOOLKIT_DIR` and `PYTHON` to include external toolkit/oracle checks. Each run uses fresh generated identities; no private keys or authority state are in Git or the bundle.

The [two-page brief](KeyGuard-brief.pdf) contains architecture, threat model and the accessible five-minute fallback video link. The [operator runbook](TRACK4_OPERATIONS.md) supplies initialization, real signed actions, messaging, recovery, TLS and independent-node deployment. [Design arguments](TRACK4_DESIGN.md) distinguish mathematical assumptions from empirical tests.

Session resumption is deliberately unsupported, and the isolated-access detector blind spot is measured. Synthetic metrics, public-validator results and local tests are not hidden-worker scores or security certification. Authenticate release checksums through an independent channel; replacing an archive and its checksum together defeats checksums alone.

Streaming walkthrough: [Google Drive video](https://drive.google.com/file/d/12ctCr6DAvSzDgRySdrr2QayL8FVswcMR/view). Anyone with the link can view; file discovery is disabled. The GitHub release also retains the downloadable MP4.
