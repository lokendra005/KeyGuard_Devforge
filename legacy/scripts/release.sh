#!/bin/sh
set -eu
# Exclude macOS metadata sidecars from portable, checksummed reviewer archives.
export COPYFILE_DISABLE=1
cd "$(dirname "$0")/.."
export PATH="$PWD/../.cache/toolchain/bin:$PATH"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0
export GOCACHE="${GOCACHE:-$PWD/.cache/build}"
mkdir -p dist
for arch in amd64 arm64; do
  GOOS=linux GOARCH="$arch" go build -mod=vendor -trimpath -ldflags='-s -w' -o "dist/kig-linux-$arch" ./cmd/kig
  GOOS=linux GOARCH="$arch" go test -mod=vendor -c -trimpath -o "dist/guard-tests-linux-$arch" ./internal/guard
  GOOS=linux GOARCH="$arch" go test -mod=vendor -c -trimpath -o "dist/spec-tests-linux-$arch" ./spec
done
go version -m dist/kig-linux-amd64 > dist/build-info.txt
# Only explicit source paths: never package local keys, caches or generated operator state.
tar --exclude=docs/SECRET_WARDS_PLAN.md -czf dist/keyguard-source.tar.gz go.mod go.sum vendor cmd internal spec scripts deploy docs Makefile Dockerfile compose.yaml compose.witnessed.yaml README.md .github

(cd dist
 if command -v sha256sum >/dev/null 2>&1; then
  sha256sum kig-linux-* guard-tests-linux-* spec-tests-linux-* build-info.txt keyguard-source.tar.gz > SHA256SUMS
 else
  shasum -a 256 kig-linux-* guard-tests-linux-* spec-tests-linux-* build-info.txt keyguard-source.tar.gz > SHA256SUMS
 fi
)
