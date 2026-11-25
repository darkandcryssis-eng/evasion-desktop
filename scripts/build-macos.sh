#!/bin/bash
# Собирает Evasion.app (Intel + Apple Silicon) и Evasion-macOS.zip.
# Запуск из корня репозитория на macOS: scripts/build-macos.sh [версия]
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-dev}"
build="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for arch in arm64 amd64; do
  GOOS=darwin GOARCH=$arch CGO_ENABLED=0 go build -trimpath -o "$tmp/evasion-$arch" ./cmd/evasion
done
lipo -create -output ui/payload/evasion "$tmp/evasion-arm64" "$tmp/evasion-amd64"
cp examples/config.json ui/payload/config.json

cd ui
wails build -clean -trimpath -platform darwin/universal -ldflags "-X main.appVersion=$version -X main.appBuild=$build"
cd build/bin
codesign --force --deep --sign - Evasion.app
rm -f Evasion-macOS.zip
ditto -c -k --keepParent Evasion.app Evasion-macOS.zip
shasum -a 256 Evasion-macOS.zip > Evasion-macOS.zip.sha256
cat Evasion-macOS.zip.sha256
