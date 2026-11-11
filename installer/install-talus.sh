#!/usr/bin/env bash
# ── install-talus.sh — bootstrap the Talus Enterprise installer ───────────
#
# Downloads the release installer, verifies its SHA-256, and executes it with
# the arguments passed to this script.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Hartwell-Labs/talus-process-monitor/master/installer/install-talus.sh | sudo bash
#   curl -fsSL .../install-talus.sh | sudo bash -s -- --no-tui --license-key-stdin
#
# Environment:
#   TALUS_INSTALLER_TAG   Release tag to install (default: latest)

set -euo pipefail

REPO="Hartwell-Labs/talus-process-monitor"
GITHUB_API="https://api.github.com"
GITHUB_RELEASES="https://github.com"

die() { echo "[install-talus] error: $*" >&2; exit 1; }
info() { echo "[install-talus] $*"; }

detect_asset() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "talus-installer" ;;
        aarch64 | arm64) echo "talus-installer-aarch64" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

latest_tag() {
    curl -fsSL "${GITHUB_API}/repos/${REPO}/releases/latest" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])'
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

main() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

    for cmd in curl python3; do
        command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required"
    done

    local tag="${TALUS_INSTALLER_TAG:-}"
    [ -n "$tag" ] || tag="$(latest_tag)"
    [ -n "$tag" ] || die "could not determine the latest release"

    local asset
    asset="$(detect_asset)"
    local base_url="${GITHUB_RELEASES}/${REPO}/releases/download/${tag}"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT

    info "Installing Talus ${tag} (${asset})"
    curl -fsSL "${base_url}/${asset}" -o "${tmp_dir}/talus-installer" ||
        die "could not download ${base_url}/${asset}"

    curl -fsSL "${base_url}/checksums-sha256.txt" -o "${tmp_dir}/checksums.txt" ||
        die "release ${tag} has no checksums-sha256.txt"

    local expected actual
    expected="$(awk -v a="$asset" '($2==a || $2=="*"a) { print $1; exit }' "${tmp_dir}/checksums.txt")"
    [ -n "$expected" ] || die "no checksum for ${asset} in ${tag}"

    actual="$(sha256_of "${tmp_dir}/talus-installer")"
    [ "$expected" = "$actual" ] ||
        die "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"
    info "✓ checksum verified"

    chmod +x "${tmp_dir}/talus-installer"
    exec "${tmp_dir}/talus-installer" "$@"
}

main "$@"
