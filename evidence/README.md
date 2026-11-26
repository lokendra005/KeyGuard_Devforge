# Reproducible review evidence

These are actual captured outputs, not mocked verdicts. Test identities, files and keys are generated in disposable state directories. No operator key or live database is committed.

| File | What it measures |
|---|---|
| `demo-arm64.log`, `demo-amd64.log` | Full offline Node 24.11.1 demo: real adapter workflow, regression suite, signature vectors, five independent nodes, detector holdout, benchmark and 12-goal evidence map. AMD64 is emulated on the ARM64 development host. |
| `official-validator.log`, `official-linux.log` | Unmodified public validator, pinned toolkit commit `8901dfb`; latter uses a fresh network-disabled Linux container per request. |
| `pqcrypto-interop.log`, `pqcrypto-linux.log` | Independent Python pqcrypto 0.4.0 decapsulation/HMAC oracle, 16 generated keypairs. |
| `detector-holdout.json`, `detector-renamed-holdout.json` | Disjoint 4k reference / 12k held-out synthetic evaluations, two seeds, renamed services/roles/actions and honest confusion matrices. |
| `tls.log` | Actual TLS 1.3 trust and refusal checks. |
| `docker-build.log`, `deployment-image.log` | Root source-only Docker build and tests from copied image content, without source bind mounts. |
| `deployment-cluster.log` | Real TLS authority + three separate-cache containers on an internal Docker network; reads before and denial after revocation. |
| `legacy-preservation.log` | Source relocation and existing key-file hash checks; no live migration. |
| `walkthrough.log` | Actual process-per-request adapter operations shown in the video. |
| `video-validation.json` | Actual video/audio stream check and 300-second duration. |

`./scripts/collect-evidence.sh --docker` regenerates the local evidence with the bundled runtime images. Set `TOOLKIT_DIR=/path/to/Track-4-Toolkit` and `PYTHON=/path/to/python3.12` to include the organizer/oracle checks; pqcrypto must already be available. No toolkit source or evaluation labels are built into the adapter.

`source-sha256.json` binds the application/tests/scripts/configuration used by these runs. Final extracted-archive and public-release checks are separate release assets to avoid a self-referential archive checksum. `scripts/build-deliverables.py --video` regenerates the PDF/video from these logs using optional reportlab, pypdf, Pillow, ffmpeg and local macOS system narration; those tools are not runtime/test dependencies.

Five-node latency uses one observer clock after authoritative revocation acknowledgement. It includes polling/scheduling delay and injected transport faults, with only five samples per architecture. The guarantee is about authorization/response queueing under the documented clock assumption, not a guarantee on receipt of buffered bytes. Synthetic detector scores are not production accuracy. The video is clearly labelled a narrated recorded-evidence walkthrough, not a real-time screen recording.
