#!/bin/sh
# Initial online setup only. Checksums pinned from Node's official v24.11.1 release.
set -eu
cd "$(dirname "$0")/.."
case "$(uname -s)/$(uname -m)" in
 Linux/x86_64) platform=linux-x64; digest=58a5ff5cc8f2200e458bea22e329d5c1994aa1b111d499ca46ec2411d58239ca;;
 Linux/aarch64|Linux/arm64) platform=linux-arm64; digest=0dc93ec5c798b0d347f068db6d205d03dea9a71765e6a53922b682b91265d71f;;
 Darwin/arm64) platform=darwin-arm64; digest=b05aa3a66efe680023f930bd5af3fdbbd542794da5644ca2ad711d68cbd4dc35;;
 Darwin/x86_64) platform=darwin-x64; digest=096081b6d6fcdd3f5ba0f5f1d44a47e83037ad2e78eada26671c252fe64dd111;;
 *) echo 'Supported: Linux/macOS, ARM64/x64. See nodejs.org for other platforms.' >&2; exit 2;;
esac
mkdir -p .cache/node
file="node-v24.11.1-$platform.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 "https://nodejs.org/download/release/v24.11.1/$file" -o ".cache/node/$file"
(cd .cache/node
 if command -v sha256sum >/dev/null 2>&1; then printf '%s  %s\n' "$digest" "$file" | sha256sum -c -; else printf '%s  %s\n' "$digest" "$file" | shasum -a 256 -c -; fi
 tar -xzf "$file"
)
ln -sfn "node-v24.11.1-$platform" .cache/node/current
printf 'Installed exact Node 24.11.1. In this shell run: export PATH="$PWD/.cache/node/current/bin:$PATH"\n'
