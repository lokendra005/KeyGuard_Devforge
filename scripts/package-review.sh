#!/bin/sh
set -eu
export COPYFILE_DISABLE=1
cd "$(dirname "$0")/.."
mkdir -p dist
stage=$(mktemp -d "${TMPDIR:-/tmp}/keyguard-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT INT TERM
# Explicit submission source only; no operator state, unrelated project or generated secrets.
tar -cf - track4 track4_service.cjs threat-model.json scripts docs evidence README.md Makefile Dockerfile Dockerfile.dockerignore compose.yaml compose.replicas.yaml .github .gitignore .dockerignore | tar -xf - -C "$stage"
mkdir -p "$stage/dist"
for arch in amd64 arm64; do cp "dist/track4-node-$arch.tar" "$stage/dist/"; done
(cd "$stage"
 find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file"; else shasum -a 256 "$file"; fi
 done > SHA256SUMS
)
tar -czf dist/keyguard-reviewer.tar.gz -C "$stage" .
(cd dist
 if command -v sha256sum >/dev/null 2>&1; then sha256sum keyguard-reviewer.tar.gz; else shasum -a 256 keyguard-reviewer.tar.gz; fi > REVIEWER-SHA256SUMS
)
