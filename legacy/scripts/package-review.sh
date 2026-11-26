#!/bin/sh
set -eu
# Exclude macOS metadata sidecars from portable, checksummed reviewer archives.
export COPYFILE_DISABLE=1
cd "$(dirname "$0")/.."
stage=$(mktemp -d "${TMPDIR:-/tmp}/kig-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT INT TERM
tar -xzf dist/keyguard-source.tar.gz -C "$stage"
mkdir -p "$stage/dist" "$stage/validation"
cp dist/kig-linux-* dist/guard-tests-linux-* dist/spec-tests-linux-* dist/postgres-image-amd64.tar dist/postgres-image-arm64.tar dist/build-info.txt "$stage/dist/"
cp dist/validation/*.log "$stage/validation/"
(cd "$stage"
 find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file"; else shasum -a 256 "$file"; fi
 done > SHA256SUMS
)
tar -czf dist/keyguard-reviewer.tar.gz -C "$stage" .
(cd dist
 if command -v sha256sum >/dev/null 2>&1; then sha256sum keyguard-reviewer.tar.gz; else shasum -a 256 keyguard-reviewer.tar.gz; fi > REVIEWER-SHA256SUMS
)
