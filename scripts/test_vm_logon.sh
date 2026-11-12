#!/bin/bash
# Sentinel - Workstation Smart Card Logon VM Test Harness
# This script validates smart card logon prerequisites and SSSD certmap configuration
# inside a disposable virtual machine or test container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${SCRIPT_DIR}"

echo "=========================================================="
echo " Sentinel - Workstation Logon Validation"
echo "=========================================================="

# 1. Environment Safety Check
echo "[*] Checking virtualization environment..."
IS_VM=false
if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT_OUT="$(systemd-detect-virt || true)"
    if [ "${VIRT_OUT}" != "none" ] && [ -n "${VIRT_OUT}" ]; then
        echo "[+] Virtualization detected: ${VIRT_OUT}"
        IS_VM=true
    fi
fi

if [ "${IS_VM}" = "false" ]; then
    for DMI_PATH in /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name; do
        if [ -f "${DMI_PATH}" ]; then
            if grep -Ei "qemu|kvm|vmware|virtualbox|xen|innotek" "${DMI_PATH}" >/dev/null 2>&1; then
                echo "[+] Virtualization detected via DMI"
                IS_VM=true
                break
            fi
        fi
    done
fi

if [ "${IS_VM}" = "false" ] && [ "${1:-}" != "--force" ]; then
    echo "[-] WARNING: Bare-metal host detected."
    echo "[-] Modifying PAM/SSSD on a bare-metal production workstation carries lockout risk."
    echo "[-] To test safely, run inside a disposable VM (KVM/QEMU, VirtualBox, UTM) or pass --force."
    exit 1
fi

# 2. Run Test Suite
echo "[*] Running Sentinel test suite..."
python3 -m unittest discover tests

# 3. Check System Packages
echo "[*] Checking SSSD and smart card packages..."
for PKG in pcscd opensc; do
    if command -v "${PKG}" >/dev/null 2>&1 || systemctl list-unit-files "${PKG}*" >/dev/null 2>&1; then
        echo "[+] ${PKG}: available"
    else
        echo "[-] ${PKG}: missing"
    fi
done

if command -v sssd >/dev/null 2>&1; then
    echo "[+] sssd: available"
else
    echo "[-] sssd: not installed"
fi

if command -v authselect >/dev/null 2>&1; then
    echo "[+] authselect: available (Fedora/RHEL profile manager)"
    authselect current || true
elif command -v pam-auth-update >/dev/null 2>&1; then
    echo "[+] pam-auth-update: available (Debian/Ubuntu PAM manager)"
fi

echo "=========================================================="
echo "[+] VM Preflight Validation Complete."
echo "=========================================================="
