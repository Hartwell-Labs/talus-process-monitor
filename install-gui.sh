#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  TALUS — Graphical Installer                                     ║
# ║  eBPF Endpoint Security Agent for Linux                             ║
# ║  Beautiful zenity-based GTK installer                              ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────
INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib/talus"
EBPF_NAME="process-monitor-ebpf"
BINARY_NAME="talus"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_LOG="/tmp/talus-install.log"
DESKTOP_FILE="/usr/share/applications/talus.desktop"

# ── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Detect display ─────────────────────────────────────────────────────
HAS_DISPLAY=false
[ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] && HAS_DISPLAY=true

# ── Zenity wrapper ──────────────────────────────────────────────────────
z() {
    if $HAS_DISPLAY && command -v zenity &>/dev/null; then
        zenity "$@"
    else
        return 1
    fi
}

# ── Sudo password ──────────────────────────────────────────────────────
SUDO_PW=""

get_sudo() {
    [ -n "$SUDO_PW" ] && return 0
    sudo -n true 2>/dev/null && { SUDO_PW=""; return 0; }

    if $HAS_DISPLAY && command -v zenity &>/dev/null; then
        SUDO_PW=$(zenity --password --title="🔒 Root Access Required" \
            --width=360 --text="Enter your password to install Talus:" 2>/dev/null) || {
            z --error --width=340 --title="❌ Cancelled" \
                --text="Installation cancelled — root password required." 2>/dev/null
            exit 1
        }
    else
        echo -en "${BOLD}sudo password: ${NC}"
        read -rs SUDO_PW; echo ""
    fi

    if ! echo "$SUDO_PW" | sudo -S true 2>/dev/null; then
        z --error --width=340 --title="❌ Wrong Password" \
            --text="Incorrect password. Try again." 2>/dev/null || echo -e "${RED}Wrong password!${NC}"
        SUDO_PW=""
        get_sudo
    fi
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  FIND PRE-BUILT BINARIES                                            ║
# ╚══════════════════════════════════════════════════════════════════════╝

find_binaries() {
    TUI_BIN=""
    EBPF_OBJ=""

    # Find userspace binary
    TUI_BIN=$(find "$SOURCE_DIR/target/release" -maxdepth 1 -name "process-monitor" -type f 2>/dev/null | head -1)

    # Find eBPF object — look in multiple locations
    EBPF_OBJ=$(find "$SOURCE_DIR/target" -path "*/release/*" -name "*.bpf.o" -type f 2>/dev/null | head -1)
    if [ -z "$EBPF_OBJ" ]; then
        EBPF_OBJ=$(find "$SOURCE_DIR/target/bpfel-unknown-none" -name "process-monitor-ebpf" -type f 2>/dev/null | head -1)
    fi

    # Also check if already installed system-wide
    local SYS_BIN=""
    if [ -x "$INSTALL_DIR/$BINARY_NAME" ]; then
        SYS_BIN="$INSTALL_DIR/$BINARY_NAME"
    fi
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  STAGE 1: WELCOME + DETECT                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝

show_welcome() {
    find_binaries

    local STATUS_LINES=""
    local HAS_ALL=true

    if [ -n "$TUI_BIN" ]; then
        local SIZE
        SIZE=$(du -h "$TUI_BIN" | cut -f1)
        STATUS_LINES+="  <span foreground='#00ff64'>✓</span>  Binary found: <b>$(basename "$TUI_BIN")</b> ($SIZE)\n"
    else
        STATUS_LINES+="  <span foreground='#ff3232'>✗</span>  Binary NOT found — needs build\n"
        HAS_ALL=false
    fi

    if [ -n "$EBPF_OBJ" ]; then
        STATUS_LINES+="  <span foreground='#00ff64'>✓</span>  eBPF program found\n"
    else
        STATUS_LINES+="  <span foreground='#fab432'>!</span>  eBPF program not found (optional)\n"
    fi

    if [ -x "$INSTALL_DIR/$BINARY_NAME" ]; then
        local VER
        VER=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "installed")
        STATUS_LINES+="  <span foreground='#58a6ff'>ℹ</span>  Already installed: $VER\n"
    fi

    # Check Rust
    if command -v rustc &>/dev/null; then
        local RUST_VER
        RUST_VER=$(rustc --version | awk '{print $2}')
        STATUS_LINES+="  <span foreground='#00ff64'>✓</span>  Rust $RUST_VER\n"
    else
        STATUS_LINES+="  <span foreground='#ff3232'>✗</span>  Rust not found\n"
        HAS_ALL=false
    fi

    # Check kernel
    local KMAJOR KMINOR
    KMAJOR=$(uname -r | cut -d. -f1)
    KMINOR=$(uname -r | cut -d. -f2)
    if [ "$KMAJOR" -ge 5 ] && [ "$KMINOR" -ge 8 ]; then
        STATUS_LINES+="  <span foreground='#00ff64'>✓</span>  Kernel $(uname -r) (≥5.8)\n"
    else
        STATUS_LINES+="  <span foreground='#ff3232'>✗</span>  Kernel $(uname -r) — needs 5.8+\n"
        HAS_ALL=false
    fi

    # Check BTF
    if [ -f /sys/kernel/btf/vmlinux ]; then
        STATUS_LINES+="  <span foreground='#00ff64'>✓</span>  BTF available\n"
    else
        STATUS_LINES+="  <span foreground='#fab432'>!</span>  BTF not found\n"
    fi

    local MSG="<span size='x-large' foreground='#58A6FF'><b>⚡ Talus Installer</b></span>

<span size='large'>eBPF Endpoint Security Agent</span>

<span foreground='#8892a8'>System scan results:</span>

${STATUS_LINES}
<span foreground='#505064'>$(date '+%Y-%m-%d %H:%M')</span>"

    z --info --title="⚡ Talus Installer" --width=520 --height=400 \
        --text="$MSG" --ok-label="Install ⚡" 2>/dev/null || {
        echo -e "\n${BOLD}${CYAN}⚡ Talus Installer${NC}"
        echo -e "$STATUS_LINES" | sed 's/<[^>]*>//g'
        read -p "Press Enter to continue..."
    }
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  STAGE 2: BUILD (only if needed)                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝

build_if_needed() {
    find_binaries

    if [ -n "$TUI_BIN" ]; then
        # Already built — skip
        echo -e "  ${GREEN}✓${NC} Binary already built: $TUI_BIN"
        return 0
    fi

    # Need to build — check dependencies first
    echo -e "${BOLD}${CYAN}🔨 Building Talus from source...${NC}"
    echo -e "  ${DIM}This uses stable Rust (no nightly needed for userspace)${NC}"

    # Check clang
    if ! command -v clang &>/dev/null; then
        echo -e "  ${RED}✗ clang not found. Installing...${NC}"
        get_sudo
        echo "$SUDO_PW" | sudo -S pacman -S --noconfirm clang 2>>"$BUILD_LOG" || true
    fi

    echo -e "  ${DIM}→ Building userspace binary...${NC}"
    cd "$SOURCE_DIR"
    cargo build --release -p talus-process-monitor --target-dir target 2>>"$BUILD_LOG" || {
        echo -e "  ${RED}✗ Build failed. Check $BUILD_LOG${NC}"
        return 1
    }

    TUI_BIN=$(find "$SOURCE_DIR/target/release" -maxdepth 1 -name "process-monitor" -type f | head -1)
    echo -e "  ${GREEN}✓ Build successful${NC}"

    # Try to find eBPF object (might not exist if nightly not available)
    EBPF_OBJ=$(find "$SOURCE_DIR/target" -path "*/release/*" -name "*.bpf.o" -type f 2>/dev/null | head -1)
    if [ -n "$EBPF_OBJ" ]; then
        echo -e "  ${GREEN}✓ eBPF program found${NC}"
    else
        echo -e "  ${YELLOW}! eBPF program not found — TUI-only mode${NC}"
    fi
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  STAGE 3: INSTALL                                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝

install_files() {
    find_binaries
    get_sudo

    echo -e "${BOLD}${CYAN}📥 Installing to system...${NC}"

    # Install binary
    if [ -n "$TUI_BIN" ]; then
        echo "$SUDO_PW" | sudo -S cp "$TUI_BIN" "$INSTALL_DIR/$BINARY_NAME" 2>>"$BUILD_LOG"
        echo "$SUDO_PW" | sudo -S chmod +x "$INSTALL_DIR/$BINARY_NAME"
        echo -e "  ${GREEN}✓${NC} Binary → $INSTALL_DIR/$BINARY_NAME"
    else
        echo -e "  ${RED}✗ No binary to install${NC}"
        return 1
    fi

    # Install eBPF object
    if [ -n "$EBPF_OBJ" ]; then
        echo "$SUDO_PW" | sudo -S mkdir -p "$LIB_DIR" 2>>"$BUILD_LOG"
        echo "$SUDO_PW" | sudo -S cp "$EBPF_OBJ" "$LIB_DIR/$EBPF_NAME" 2>>"$BUILD_LOG"
        echo -e "  ${GREEN}✓${NC} eBPF   → $LIB_DIR/$EBPF_NAME"
    fi

    # Create icon
    echo "$SUDO_PW" | sudo -S mkdir -p /usr/share/icons/hicolor/256x256/apps 2>/dev/null
    local ICON_SVG="/tmp/talus-icon.svg"
    cat > "$ICON_SVG" << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a1a"/>
      <stop offset="100%" style="stop-color:#161636"/>
    </linearGradient>
    <linearGradient id="shield" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#58a6ff"/>
      <stop offset="100%" style="stop-color:#00ffff"/>
    </linearGradient>
  </defs>
  <rect width="256" height="256" rx="40" fill="url(#bg)"/>
  <path d="M128 30 L200 70 L200 140 C200 190 165 225 128 240 C91 225 56 190 56 140 L56 70 Z" fill="none" stroke="url(#shield)" stroke-width="6" opacity="0.9"/>
  <path d="M128 55 L180 85 L180 138 C180 178 155 208 128 220 C101 208 76 178 76 138 L76 85 Z" fill="url(#shield)" opacity="0.15"/>
  <text x="128" y="145" text-anchor="middle" font-family="monospace" font-size="64" font-weight="bold" fill="#00ffff">H</text>
  <text x="128" y="195" text-anchor="middle" font-family="monospace" font-size="16" fill="#58a6ff" letter-spacing="4">EBPF</text>
</svg>
SVGEOF
    if command -v rsvg-convert &>/dev/null; then
        rsvg-convert -w 256 -h 256 "$ICON_SVG" -o /tmp/talus-icon.png 2>/dev/null
        echo "$SUDO_PW" | sudo -S cp /tmp/talus-icon.png /usr/share/icons/hicolor/256x256/apps/talus.png 2>/dev/null || true
    fi

    # Desktop entry
    local DESKTOP_CONTENT="[Desktop Entry]
Name=Talus
Comment=eBPF Endpoint Security Agent
Exec=sudo $INSTALL_DIR/$BINARY_NAME
Icon=talus
Terminal=true
Type=Application
Categories=System;Security;Monitor;
Keywords=ebpf;security;monitor;edr;
StartupNotify=false"

    echo "$SUDO_PW" | sudo -S tee "$DESKTOP_FILE" >/dev/null 2>&1 <<< "$DESKTOP_CONTENT"
    echo "$SUDO_PW" | sudo -S chmod +x "$DESKTOP_FILE" 2>/dev/null || true
    echo "$SUDO_PW" | sudo -S update-desktop-database /usr/share/applications/ 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Desktop entry created"
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  STAGE 4: VERIFY + SUCCESS                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝

verify_and_show() {
    local VER
    VER=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "installed")

    local HELP_TEXT
    HELP_TEXT=$("$INSTALL_DIR/$BINARY_NAME" --help 2>/dev/null | head -20 || echo "")

    z --info --title="✅ Talus Installed!" --width=560 --height=420 \
        --text="<span size='x-large' foreground='#00ff64'><b>✅ Installation Complete!</b></span>

<span size='large'>Talus ${VER}</span>

<span foreground='#8892a8'>Installed files:</span>

  <span foreground='#58a6ff'>Binary:</span>  $INSTALL_DIR/$BINARY_NAME
  <span foreground='#58a6ff'>eBPF:</span>    $LIB_DIR/$EBPF_NAME  (if built)
  <span foreground='#58a6ff'>Desktop:</span> $DESKTOP_FILE

<span foreground='#8892a8'>Quick start:</span>

  <span foreground='#00ff64' font='monospace'>sudo talus</span>                    TUI mode
  <span foreground='#00ff64' font='monospace'>sudo talus --auto-kill</span>         EDR mode (detect + respond)
  <span foreground='#00ff64' font='monospace'>sudo talus --json | jq .</span>       JSON output
  <span foreground='#00ff64' font='monospace'>sudo talus --web 0.0.0.0:8080</span> Web dashboard

<span foreground='#505064'>Build log: $BUILD_LOG</span>" \
        --ok-label="Done ⚡" 2>/dev/null || {
        echo ""
        echo -e "${BOLD}${GREEN}✅ Talus installed successfully!${NC}"
        echo ""
        echo -e "  ${BOLD}Binary:${NC}  $INSTALL_DIR/$BINARY_NAME ($VER)"
        echo -e "  ${BOLD}eBPF:${NC}    $LIB_DIR/$EBPF_NAME"
        echo ""
        echo -e "  ${CYAN}Quick start:${NC}"
        echo -e "    sudo talus                    # TUI mode"
        echo -e "    sudo talus --auto-kill         # EDR mode"
        echo -e "    sudo talus --json | jq .       # JSON output"
        echo -e "    sudo talus --web 0.0.0.0:8080  # Web dashboard"
        echo ""
    }
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  MAIN                                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝

main() {
    echo "=== Talus Installer — $(date) ===" > "$BUILD_LOG"

    show_welcome

    build_if_needed

    install_files

    verify_and_show
}

main "$@"
