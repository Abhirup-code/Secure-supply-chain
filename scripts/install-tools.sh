#!/usr/bin/env bash
# Install pinned security tools into ./bin, verifying each download against a SHA-256
# checksum recorded here. A changed or tampered download fails the build.
#
# Usage: scripts/install-tools.sh kyverno syft grype kube-linter
#
# To upgrade a tool, change its version and checksum together (the checksum is
# published on the tool's GitHub release page).
set -euo pipefail

BIN_DIR="${BIN_DIR:-$PWD/bin}"
mkdir -p "$BIN_DIR"

install_tool() {
  local name="$1" url sha archive_member=""
  case "$name" in
    kyverno)
      url="https://github.com/kyverno/kyverno/releases/download/v1.19.2/kyverno-cli_v1.19.2_linux_x86_64.tar.gz"
      sha="357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a"
      archive_member="kyverno" ;;
    syft)
      url="https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz"
      sha="bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d"
      archive_member="syft" ;;
    grype)
      url="https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_amd64.tar.gz"
      sha="64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519"
      archive_member="grype" ;;
    kube-linter)
      url="https://github.com/stackrox/kube-linter/releases/download/v0.8.3/kube-linter-linux"
      sha="618d299a3e2839c8ca9d86fce0db617be0fba41f0fecbbbfb7fbf1c04299fae1" ;;
    *)
      echo "unknown tool: $name" >&2
      exit 1 ;;
  esac

  local tmp
  tmp="$(mktemp)"
  curl -fsSL --retry 3 -o "$tmp" "$url"
  echo "${sha}  ${tmp}" | sha256sum -c --quiet -
  if [ -n "$archive_member" ]; then
    tar -xzf "$tmp" -C "$BIN_DIR" "$archive_member"
  else
    install -m 0755 "$tmp" "$BIN_DIR/$name"
  fi
  rm -f "$tmp"
  echo "installed $name (checksum verified)"
}

for tool in "$@"; do
  install_tool "$tool"
done
