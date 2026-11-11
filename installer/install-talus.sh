#!/usr/bin/env bash
# ── install-talus.sh — thin bootstrap wrapper ──────────────────────────────
#
# Downloads the talus-installer binary from GitHub releases and executes it
# with the same arguments passed to this script.
#
# Usage:
#   curl -fsSL https://get.talus.sh | sudo sh
#   # or
#   curl -fsSL https://get.talus.sh | sudo sh -- --no-tui --license-key-stdin
#
# The installer requires root (writes to /usr/local/bin, /etc/talus, etc.).

set -euo pipefail

REPO="Hartwell-Labs/talus-process-monitor"
ASSET="talus-installer-x86_64-unknown-linux-gnu"
GITHUB_API="https://api.github.com"
GITHUB_RELEASES="https://github.com"

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)
            echo "error: unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac
}

# Fetch latest release tag
get_latest_tag() {
    local tag
    tag="$(curl -fsSL "${GITHUB_API}/repos/${REPO}/releases/latest" |
        python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])')"
    echo "$tag"
}

# Download and verify installer binary
download_installer() {
    local tag="$1"
    local arch="$2"
    local arch_suffix
    if [ "$arch" = "aarch64" ]; then
        arch_suffix="-aarch64"
    else
        arch_suffix=""
    fi
    local asset_name="talus-installer${arch_suffix}"
    local base_url="${GITHUB_RELEASES}/${REPO}/releases/download/${tag}"

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT

    echo "[install-talus.sh] Downloading installer from ${base_url}/${asset_name}..."

    curl -fsSL "${base_url}/${asset_name}" -o "${tmp_dir}/talus-installer"

    # Verify the download against the release checksums. Fail closed: a
    # missing checksum or a mismatch must never run the binary.
    if ! curl -fsSL "${base_url}/checksums-sha256.txt" -o "${tmp_dir}/checksums.txt"; then
        echo "[install-talus.sh] error: release has no checksums-sha256.txt" >&2
        exit 1
    fi
    local expected actual
    expected="$(awk -v a="$asset_name" -v b="$ASSET"         '($2==a || $2==b || $2=="*"a || $2=="*"b) { print $1; exit }'         "${tmp_dir}/checksums.txt")"
    if [ -z "$expected" ]; then
        echo "[install-talus.sh] error: no checksum for ${asset_name}" >&2
        exit 1
    fi
    actual="$(sha256sum "${tmp_dir}/talus-installer" | cut -d' ' -f1)"
    if [ "$expected" != "$actual" ]; then
        echo "[install-talus.sh] error: checksum mismatch for ${asset_name}" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
    echo "[install-talus.sh] ✓ checksum verified"

    chmod +x "${tmp_dir}/talus-installer"
    echo "$tmp_dir/talus-installer"
}

main() {
    # Check for root
    if [ "$(id -u)" -ne 0 ]; then
        echo "[install-talus.sh] error: must be run as root (use sudo)" >&2
        exit 1
    fi

    # Check for required tools
    for cmd in curl python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[install-talus.sh] error: $cmd is required but not installed" >&2
            exit 1
        fi
    done

    local tag="${TALUS_INSTALLER_TAG:-}"
    if [ -z "$tag" ]; then
        tag="$(get_latest_tag)"
    fi

    local arch
    arch="$(detect_arch)"

    echo "[install-talus.sh] Installing Talus (tag: ${tag}, arch: ${arch})"

    local binary_path
    binary_path="$(download_installer "$tag" "$arch")"

    echo "[install-talus.sh] Running installer with arguments: $*"

    # Remove the trap from download so the binary isn't deleted prematurely
    exec "$binary_path" "$@"
}

main "$@"
