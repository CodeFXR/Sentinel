#!/usr/bin/env bash
# ==============================================================================
# Sentinel — Distribution Telemetry & Hardware Inspector
# ==============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}=== Sentinel: Distro Telemetry Report ===${RESET}"
date -u +"Timestamp (UTC): %Y-%m-%d %H:%M:%S"

echo -e "\n${BOLD}${YELLOW}[1. Operating System & Kernel]${RESET}"
if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "  OS Name:         ${PRETTY_NAME:-Unknown}"
    echo "  OS ID:           ${ID:-Unknown}"
    echo "  ID_LIKE:         ${ID_LIKE:-None}"
    echo "  Version ID:      ${VERSION_ID:-Unknown}"
else
    echo "  /etc/os-release: NOT FOUND"
fi
echo "  Kernel:          $(uname -r)"
echo "  Architecture:    $(uname -m)"
echo "  Session Type:    ${XDG_SESSION_TYPE:-unknown} (${XDG_CURRENT_DESKTOP:-unknown})"

echo -e "\n${BOLD}${YELLOW}[2. Smart Card Hardware & USB Devices]${RESET}"
if command -v lsusb >/dev/null 2>&1; then
    echo "  Detected USB Smart Card Readers:"
    lsusb | grep -Ei "(smart|card|ccid|gemalto|identiv|broadcom|alcor|hid|omnik)" | sed 's/^/    /' || echo "    (No readers found via lsusb filter)"
else
    echo "  lsusb: NOT INSTALLED"
fi

echo -e "\n${BOLD}${YELLOW}[3. PC/SC Daemon & Systemd Sockets]${RESET}"
for unit in pcscd.socket pcscd.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        echo -e "  $unit: ${GREEN}active (running)${RESET}"
    elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        echo -e "  $unit: ${YELLOW}inactive (enabled for socket activation)${RESET}"
    else
        echo -e "  $unit: ${RED}inactive / disabled / not installed${RESET}"
    fi
done

echo -e "\n${BOLD}${YELLOW}[4. OpenSC & Middleware Binary Verification]${RESET}"
for bin in opensc-tool pkcs11-tool pkcs15-tool pcsc_scan modutil certutil; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo -e "  $bin: ${GREEN}Installed${RESET} ($(command -v "$bin"))"
    else
        echo -e "  $bin: ${RED}Missing${RESET}"
    fi
done

echo -e "\n${BOLD}${YELLOW}[5. Shared PKCS#11 Library Paths]${RESET}"
LIB_CANDIDATES=(
    "/usr/lib64/opensc-pkcs11.so"
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    "/usr/lib/opensc-pkcs11.so"
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"
    "/usr/lib64/p11-kit-proxy.so"
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so"
    "/usr/lib/p11-kit-proxy.so"
)
FOUND_PKCS11=0
for lib in "${LIB_CANDIDATES[@]}"; do
    if [ -f "$lib" ]; then
        echo -e "  Found: ${GREEN}$lib${RESET}"
        FOUND_PKCS11=1
    fi
done
if [ "$FOUND_PKCS11" -eq 0 ]; then
    echo -e "  ${RED}WARNING: No OpenSC PKCS#11 library found in standard paths!${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[6. System CA Trust Store Paths & Commands]${RESET}"
if command -v update-ca-trust >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}update-ca-trust (Fedora/RHEL/CentOS)${RESET}"
    echo "  Anchor Dir:      /etc/pki/ca-trust/source/anchors/ (Exists: $([ -d /etc/pki/ca-trust/source/anchors ] && echo YES || echo NO))"
elif command -v update-ca-certificates >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}update-ca-certificates (Debian/Ubuntu/Zorin/Mint)${RESET}"
    echo "  Anchor Dir:      /usr/local/share/ca-certificates/ (Exists: $([ -d /usr/local/share/ca-certificates ] && echo YES || echo NO))"
elif command -v trust >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}trust extract-compat (Arch/openSUSE)${RESET}"
    echo "  Anchor Dir:      /etc/ca-certificates/trust-source/anchors/ (Exists: $([ -d /etc/ca-certificates/trust-source/anchors ] && echo YES || echo NO))"
else
    echo -e "  Trust Tool:      ${RED}UNKNOWN${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[7. Web Browser Installation & Sandbox Status]${RESET}"
# Firefox
if command -v firefox >/dev/null 2>&1; then
    FF_PATH=$(command -v firefox)
    if echo "$FF_PATH" | grep -q "snap"; then
        echo -e "  Firefox:         ${YELLOW}Snap Package${RESET} ($FF_PATH) -> AppArmor Sandbox Active"
    elif [ -f /.flatpak-info ] || echo "$FF_PATH" | grep -q "flatpak"; then
        echo -e "  Firefox:         ${YELLOW}Flatpak Package${RESET} -> Sandbox Active"
    else
        echo -e "  Firefox:         ${GREEN}Native RPM/DEB/Binary${RESET} ($FF_PATH)"
    fi
else
    echo "  Firefox:         Not Installed"
fi

# Chrome / Chromium
if command -v google-chrome >/dev/null 2>&1; then
    echo -e "  Chrome:          ${GREEN}Installed${RESET} ($(command -v google-chrome))"
elif command -v chromium >/dev/null 2>&1; then
    echo -e "  Chromium:        ${GREEN}Installed${RESET} ($(command -v chromium))"
else
    echo "  Chrome/Chromium: Not Installed"
fi

# NSS Database in Home
if [ -d "$HOME/.pki/nssdb" ]; then
    echo -e "  ~/.pki/nssdb:    ${GREEN}Present${RESET}"
else
    echo -e "  ~/.pki/nssdb:    ${YELLOW}Missing (will be created by Chrome or certutil)${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[8. Smart Card Live Query (if reader & CAC connected)]${RESET}"
if command -v opensc-tool >/dev/null 2>&1; then
    echo "  Connected Readers (opensc-tool -l):"
    opensc-tool -l 2>&1 | sed 's/^/    /' || true
    echo "  Card ATR (opensc-tool -a):"
    opensc-tool -a 2>&1 | sed 's/^/    /' || true
else
    echo "  opensc-tool not available for live query."
fi

echo -e "\n${BOLD}${YELLOW}[9. Native Rust Accelerator Status]${RESET}"
if command -v cargo >/dev/null 2>&1; then
    echo -e "  Cargo:           ${GREEN}Installed${RESET} ($(cargo --version))"
else
    echo -e "  Cargo:           ${YELLOW}Not Installed (Pure-Python fallback will be used)${RESET}"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if python3 -I -c "import sys; sys.path = [p for p in sys.path if p not in ('', '.')]; sys.path.insert(0, '${REPO_ROOT}'); from core.rust_bridge import is_rust_available; sys.exit(0 if is_rust_available() else 1)" 2>/dev/null; then
    RUST_V=$(python3 -I -c "import sys; sys.path = [p for p in sys.path if p not in ('', '.')]; sys.path.insert(0, '${REPO_ROOT}'); from core.rust_bridge import get_rust_version; print(get_rust_version())" 2>/dev/null || echo "Unknown")
    echo -e "  sentinel_core:   ${GREEN}Active & Operational${RESET} (v${RUST_V})"
else
    echo -e "  sentinel_core:   ${YELLOW}Not Compiled / Pure-Python Fallback Active${RESET}"
fi

echo -e "\n${BOLD}${CYAN}=== End of Telemetry Report ===${RESET}\n"
