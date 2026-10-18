#!/usr/bin/env bash
# Talus Process Monitor — build script (auto-installs dependencies)
#
# Usage:
#   ./build.sh          # Build TUI-only (default, 1.7MB)
#   ./build.sh --all    # Build every variant
#   ./build.sh --check  # Only check dependencies, don't build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}!${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
step() { echo "==> $*"; }

CHECK_ONLY=false
BUILD_TUI=true

for arg in "$@"; do
    case "$arg" in
        --all)   BUILD_TUI=true ;;
        --check) CHECK_ONLY=true ;;
        --help|-h)
            echo "Usage: ./build.sh [--all|--check]"
            echo ""
            echo "  (default)  Build TUI-only variant"
            echo "  --all      Build both TUI and web variants"
            echo "  --check    Only check if dependencies are installed"
            exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# ══════════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECKS & AUTO-INSTALL
# ══════════════════════════════════════════════════════════════════════════

echo "=== Talus Process Monitor ==="
echo ""

# ── Rust ───────────────────────────────────────────────────────────────
command -v cargo >/dev/null 2>&1 || die "Rust not found. Install from https://rustup.rs"

if ! cargo +nightly --version >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" = true ]; then
        die "Nightly not found. Run: rustup toolchain install nightly --profile minimal --component rust-src"
    fi
    echo "==> Installing nightly toolchain..."
    rustup toolchain install nightly --profile minimal --component rust-src
    ok "nightly installed"
fi

if ! rustup component list --toolchain nightly 2>/dev/null | grep -q "rust-src.*installed"; then
    if [ "$CHECK_ONLY" = true ]; then
        die "rust-src not found. Run: rustup component add rust-src --toolchain nightly"
    fi
    rustup component add rust-src --toolchain nightly
    ok "rust-src added"
fi

# ── bpf-linker ─────────────────────────────────────────────────────────
BPF_LINKER_OK=false
if command -v bpf-linker >/dev/null 2>&1; then
    BPF_LINKER_OK=true
fi

if [ "$BPF_LINKER_OK" = false ]; then
    if [ "$CHECK_ONLY" = true ]; then
        die "bpf-linker not found. Run: cargo install bpf-linker --git https://github.com/alessandrod/bpf-linker --force"
    fi
    echo "==> Installing bpf-linker from source (compiles LLVM, ~2-3 min)..."
    cargo install bpf-linker --git https://github.com/alessandrod/bpf-linker --force
    ok "bpf-linker installed"
fi

# ── libLLVM symlink fix ───────────────────────────────────────────────
RUSTLIB_DIR="$(rustc +nightly --print sysroot 2>/dev/null)/lib" || true
if [ -n "$RUSTLIB_DIR" ] && [ -d "$RUSTLIB_DIR" ]; then
    for script in "$RUSTLIB_DIR"/libLLVM-*-rust-*.so; do
        [ -f "$script" ] || continue
        FILE_SIZE=$(stat -c%s "$script" 2>/dev/null || stat -f%z "$script" 2>/dev/null || echo "999999")
        if [ "$FILE_SIZE" -lt 1024 ] 2>/dev/null; then
            REAL_LLVM=$(grep -oP '(?<=INPUT\()[^)]+' "$script" 2>/dev/null || true)
            if [ -n "$REAL_LLVM" ] && [ -f "$RUSTLIB_DIR/$REAL_LLVM" ]; then
                if [ "$CHECK_ONLY" = false ]; then
                    mv "$script" "${script}.script"
                    ln -s "$REAL_LLVM" "$script"
                    ok "Fixed LLVM symlink: $(basename "$script")"
                else
                    warn "LLVM linker script needs fix (run without --check)"
                fi
            fi
        fi
    done
fi

# ── LD_LIBRARY_PATH for bpf-linker ────────────────────────────────────
if [ -n "$RUSTLIB_DIR" ] && [ -d "$RUSTLIB_DIR" ]; then
    for real_llvm in "$RUSTLIB_DIR"/libLLVM.so.*; do
        [ -f "$real_llvm" ] || continue
        LLVM_DIR="$(dirname "$real_llvm")"
        if [ -z "${LD_LIBRARY_PATH:-}" ] || ! echo "$LD_LIBRARY_PATH" | grep -q "$LLVM_DIR"; then
            export LD_LIBRARY_PATH="${LLVM_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        fi
        break
    done
fi

if [ "$CHECK_ONLY" = true ]; then
    ok "All dependencies installed. Ready to build!"
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════
#  BUILD
# ══════════════════════════════════════════════════════════════════════════

echo ""
echo "Target dir: $CARGO_TARGET_DIR"
echo ""

step "Building eBPF program (bpfel-unknown-none)..."
cargo +nightly build --profile bpf \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --manifest-path "$SCRIPT_DIR/process-monitor-ebpf/Cargo.toml"
ok "eBPF built"

if [ "$BUILD_TUI" = true ]; then
    step "Building userspace binary (TUI-only)..."
    cargo build --release -p talus-process-monitor --manifest-path "$SCRIPT_DIR/Cargo.toml"
    cp "$CARGO_TARGET_DIR/release/process-monitor" "$CARGO_TARGET_DIR/release/process-monitor-tui"
    ok "TUI binary: $CARGO_TARGET_DIR/release/process-monitor-tui"
fi

if [ "$BUILD_TUI" = true ]; then
    cp "$CARGO_TARGET_DIR/release/process-monitor-tui" "$CARGO_TARGET_DIR/release/process-monitor"
fi

echo ""
echo "=== Build complete ==="
echo ""
echo "  eBPF:   $CARGO_TARGET_DIR/bpfel-unknown-none/bpf/build/process-monitor-ebpf/out/process_monitor_ebpf"
[ "$BUILD_TUI" = true ] && echo "  TUI:    $CARGO_TARGET_DIR/release/process-monitor-tui (1.7MB)"
echo ""
echo "Run (requires root for eBPF):"
echo "  sudo $CARGO_TARGET_DIR/release/process-monitor-tui"
