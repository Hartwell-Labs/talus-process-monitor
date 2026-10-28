#!/usr/bin/env bash
# Talus Process Monitor - installer.
#
# Detects the Linux distribution, installs build dependencies with the
# distribution's own package manager, installs the Rust toolchain if missing
# (only after prompting), builds, and installs the monitor.
#
# Safety:
#   * never reads or echoes tokens/credentials/environment secrets
#   * makes no authenticated network requests
#   * installs packages only from the distro's official repositories
#   * the only downloads are the official rustup installer (with your consent)
#     and crates from crates.io
#   * user-local install by default (no sudo required); use --system for
#     /usr/local
#   * no eval, all variables quoted

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"
export CARGO_TARGET_DIR

SYSTEM=0
ASSUME_YES=0
NO_DEPS=0
UNINSTALL=0
PREFIX_USER_BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
PREFIX_USER_LIB="$HOME/.local/lib/talus"
SYSTEM_BIN=/usr/local/bin
SYSTEM_LIB=/usr/local/lib/talus

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --system        install to /usr/local (requires root/sudo)
  --prefix DIR    install userspace files under DIR (implies --system layout:
                  DIR/bin and DIR/lib/talus)
  --no-deps       skip installing distribution packages (deps must be present)
  --no-rust       skip installing the Rust toolchain (must be present)
  -y              assume yes to all prompts
  --uninstall     remove installed files
  -h, --help      show this help
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}
info() { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "root privileges required but 'sudo' was not found; run this script as root or install sudo"
    fi
}

confirm() {
    local prompt="$1"
    if [ "$ASSUME_YES" = "1" ]; then
        return 0
    fi
    local ans
    read -r -p "$prompt [y/N] " ans || return 1
    case "$ans" in
        y | Y | yes | YES) return 0 ;;
        *) return 1 ;;
    esac
}

# ---- argument parsing -------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --system) SYSTEM=1 ;;
        --prefix)
            [ "$#" -ge 2 ] || die "--prefix requires a directory"
            SYSTEM=1
            SYSTEM_BIN="$2/bin"
            SYSTEM_LIB="$2/lib/talus"
            shift
            ;;
        --no-deps) NO_DEPS=1 ;;
        --no-rust) SKIP_RUST=1 ;;
        -y) ASSUME_YES=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

# ---- distribution detection ------------------------------------------------
DISTRO_ID=unknown
DISTRO_NAME=unknown
ID_LIKE=""

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    ID_LIKE="${ID_LIKE:-}"
elif [ -f /etc/debian_version ]; then
    DISTRO_ID=debian
    DISTRO_NAME="Debian"
elif [ -f /etc/redhat-release ]; then
    DISTRO_ID=rhel
    DISTRO_NAME="Red Hat compatible"
elif [ -f /etc/alpine-release ]; then
    DISTRO_ID=alpine
    DISTRO_NAME="Alpine Linux"
elif [ -f /etc/arch-release ]; then
    DISTRO_ID=arch
    DISTRO_NAME="Arch Linux"
elif [ -f /etc/SuSE-release ]; then
    DISTRO_ID=opensuse
    DISTRO_NAME="openSUSE/SUSE"
fi

PM=""
DEPS=""
case " $DISTRO_ID $ID_LIKE " in
    *" ubuntu "* | *" debian "*) PM=apt ;;
    *" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "* | *" amzn "*) PM=dnf ;;
    *" arch "*) PM=pacman ;;
    *" opensuse "* | *" suse "*) PM=zypper ;;
    *" alpine "*) PM=apk ;;
    *" void "*) PM=xbps ;;
esac

case "$PM" in
    apt) DEPS="build-essential clang libclang-dev linux-libc-dev" ;;
    dnf) DEPS="gcc gcc-c++ clang kernel-devel elfutils-libelf-devel" ;;
    pacman) DEPS="base-devel clang" ;;
    zypper) DEPS="gcc gcc-c++ clang kernel-devel libelf-devel" ;;
    apk) DEPS="build-base clang linux-headers" ;;
    xbps) DEPS="base-devel clang" ;;
esac

install_deps() {
    # shellcheck disable=SC2086
    case "$PM" in
        apt) as_root apt-get update && as_root apt-get install -y $DEPS ;;
        dnf) as_root dnf install -y $DEPS ;;
        pacman) as_root pacman -Sy --noconfirm $DEPS ;;
        zypper) as_root zypper install -y $DEPS ;;
        apk) as_root apk add --update $DEPS ;;
        xbps) as_root xbps-install -y $DEPS ;;
    esac
}

# ---- environment checks ------------------------------------------------------
check_kernel() {
    local kver major minor
    kver="$(uname -r 2>/dev/null || echo 0.0)"
    major="${kver%%.*}"
    rest="${kver#*.}"
    minor="${rest%%.*}"
    if [ "${major:-0}" -lt 5 ] || { [ "${major:-0}" -eq 5 ] && [ "${minor:-0}" -lt 8 ]; }; then
        warn "kernel $kver is older than 5.8; eBPF tracepoints may not work"
    fi
    info "kernel: $(uname -r) ($(uname -m))"
}

check_btf() {
    if [ -e /sys/kernel/btf/vmlinux ]; then
        info "BTF: available (/sys/kernel/btf/vmlinux)"
    else
        warn "BTF (/sys/kernel/btf/vmlinux) not found; CO-RE features may be unavailable"
    fi
}

ensure_rust() {
    if command -v cargo >/dev/null 2>&1; then
        info "Rust: $(cargo --version)"
        return 0
    fi
    [ "${SKIP_RUST:-0}" = "1" ] && die "cargo not found (--no-rust given)"
    info "Rust toolchain not found."
    confirm "Install the official rustup.rs toolchain (downloads from static.rust-lang.org)?" ||
        die "cargo is required to build; see https://rustup.rs to install manually"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # rustup modifies $HOME/.cargo/env; source it if present
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
}

ensure_nightly() {
    if command -v rustup >/dev/null 2>&1; then
        if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
            info "Installing nightly toolchain (component: rust-src)..."
            rustup toolchain install nightly --profile minimal --component rust-src
        fi
    elif ! cargo +nightly --version >/dev/null 2>&1; then
        die "nightly Rust with rust-src is required (needed for -Z build-std); install rustup from https://rustup.rs"
    fi
}

ensure_bpf_linker() {
    if command -v bpf-linker >/dev/null 2>&1; then
        info "bpf-linker: present"
        return 0
    fi
    info "bpf-linker not found; installing via cargo (compiles against LLVM, may take a few minutes)..."
    cargo install bpf-linker
}

# ---- uninstall ----------------------------------------------------------------
if [ "$UNINSTALL" = "1" ]; then
    if [ "$SYSTEM" = "1" ]; then
        as_root rm -f "$SYSTEM_BIN/talus-monitor" "$SYSTEM_LIB/process-monitor-ebpf"
        as_root rmdir "$SYSTEM_LIB" 2>/dev/null || true
        info "removed: $SYSTEM_BIN/process-monitor, $SYSTEM_LIB/process-monitor-ebpf"
    else
        rm -f "$PREFIX_USER_BIN/talus-monitor" "$PREFIX_USER_LIB/process-monitor-ebpf"
        rmdir "$PREFIX_USER_LIB" 2>/dev/null || true
        info "removed: $PREFIX_USER_BIN/process-monitor, $PREFIX_USER_LIB/process-monitor-ebpf"
    fi
    echo "Done."
    exit 0
fi

# ---- main ---------------------------------------------------------------------
echo "=== Talus Process Monitor installer ==="
echo "Distribution: $DISTRO_NAME ($DISTRO_ID)"
echo "Package manager: ${PM:-none detected}"
echo ""

check_kernel
check_btf

if [ "$NO_DEPS" = "0" ]; then
    if [ -n "$PM" ]; then
        confirm "Install build dependencies with '$PM' ($DEPS)?" &&
            install_deps ||
            warn "continuing without installing dependencies"
    else
        warn "distribution '$DISTRO_ID' is not recognized; install build tools manually (gcc/clang/linux headers) or use --no-deps"
    fi
fi

for tool in cc clang; do
    command -v "$tool" >/dev/null 2>&1 || warn "$tool not found; a C compiler and clang are needed to build"
done

ensure_rust
ensure_nightly
ensure_bpf_linker

echo ""
info "Building (this uses CARGO_TARGET_DIR=$CARGO_TARGET_DIR)..."
"$SCRIPT_DIR/build.sh"

if [ "$SYSTEM" = "1" ]; then
    info "Installing to system locations..."
    as_root install -d "$SYSTEM_BIN" "$SYSTEM_LIB"
    as_root install -m 0755 "$CARGO_TARGET_DIR/release/talus-monitor" "$SYSTEM_BIN/talus-monitor"
    as_root install -m 0644 "$CARGO_TARGET_DIR/bpfel-unknown-none/release/process-monitor-ebpf" "$SYSTEM_LIB/process-monitor-ebpf"
    echo ""
    echo "Installed."
    echo "Run (eBPF requires root):"
    echo "  sudo talus-monitor monitor"
    echo "  sudo talus-monitor monitor --json"
else
    info "Installing to user locations..."
    install -d "$PREFIX_USER_BIN" "$PREFIX_USER_LIB"
    install -m 0755 "$CARGO_TARGET_DIR/release/talus-monitor" "$PREFIX_USER_BIN/talus-monitor"
    install -m 0644 "$CARGO_TARGET_DIR/bpfel-unknown-none/release/process-monitor-ebpf" "$PREFIX_USER_LIB/process-monitor-ebpf"
    echo ""
    echo "Installed."
    [ "${PATH#*"$PREFIX_USER_BIN"}" = "$PATH" ] &&
        echo "Note: add $PREFIX_USER_BIN to your PATH to run 'talus-monitor' directly."
    echo "Run (eBPF requires root):"
    echo "  sudo $PREFIX_USER_BIN/talus-monitor"
    echo "  sudo $PREFIX_USER_BIN/talus-monitor monitor --json"
fi

echo ""
echo "To remove later: $0 --uninstall [--system]"
echo ""
echo "── License ──────────────────────────────────────────"
echo "  Talus runs in Community mode by default (free)."
echo "  Enterprise features require a license:"
echo ""
echo "  Check status:   talus license show"
echo "  Activate:       talus license activate <KEY>"
echo "  30-day trial:   automatic on first run"
echo "  More info:      https://talus.io/enterprise"
echo "──────────────────────────────────────────────────────"
