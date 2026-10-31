#!/usr/bin/env bash
# Installs a pinned OpenGrep release in /usr/local/bin/opengrep (path of SECREVIEW_OPENGREP_BINARY),
# for the OpenGrep engine of the Controller server. The binary is checked against its SHA-256
# digest before installation. To upgrade, change the version and both digests here and in the
# Dockerfile (field "digest" of the release assets on
# https://api.github.com/repos/opengrep/opengrep/releases).
set -euo pipefail

VERSION="v1.31.0"
case "$(uname -m)" in
  x86_64)
    ASSET="opengrep_manylinux_x86"
    SHA256="dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147"
    ;;
  aarch64 | arm64)
    ASSET="opengrep_manylinux_aarch64"
    SHA256="2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d"
    ;;
  *)
    echo "install-opengrep: unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' -o "$tmp/opengrep" \
  "https://github.com/opengrep/opengrep/releases/download/${VERSION}/${ASSET}"
echo "${SHA256}  $tmp/opengrep" | sha256sum --check --quiet
sudo install -m 0755 "$tmp/opengrep" /usr/local/bin/opengrep
opengrep --version
