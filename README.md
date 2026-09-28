# Sentinel Identity Manager

**Sentinel** is an enterprise-grade Terminal User Interface (TUI) application designed for the robust management and validation of DoD Common Access Cards (CAC) and PIV credentials on Linux systems. It serves as a comprehensive diagnostic dashboard, automated configuration tool, and security compliance validator.

## 🚀 Project Status: Stable Release (v1.0.0) - Gold Master

### ✅ Completed & Stable Features
1.  **System Compliance & Diagnostics**
    *   **Service Monitoring**: Real-time status tracking of `pcscd` with auto-remediation (auto-start via `pkexec`).
    *   **Middleware Detection**: Verifies presence of OpenSC and PKCS#11 modules.
    *   **Hardware Scanning**: Real-time card reader monitoring with advanced "gibberish" filtering for clean logs.

2.  **Identity Management**
    *   **Identity Mapping**: Robust extraction of User Principal Name (UPN) or Common Name (CN) from smart cards.
    *   **PIN Management**:
        *   **Status Check**: Non-destructive inspection of PIN retry counts.
        *   **Change PIN**: securely update user PINs via `pkcs15-tool`.
        *   **Unblock PIN**: Unlock blocked cards using a PUK code.

3.  **Enterprise Authentication & Signing**
    *   **SSH Integration**:
        *   **Key Export**: Automates extraction of the PIV Authentication public key to `~/.ssh/authorized_keys`.
        *   **Agent Setup**: Provides instructions and automation for adding the PKCS#11 provider to `ssh-agent`.
    *   **PDF Signing**:
        *   **Digital Signatures**: integrated `pyhanko` to sign standard PDF documents using the hardware token.
        *   **XFA Detection**: Automatically detects and warns users about Adobe proprietary "Dynamic Forms" (XFA) which cannot be signed by open-source tools.
    *   **Advanced Certificate Validation**:
        *   **AIA Chasing**: Automatically fetches missing intermediate certificates via AIA URLs (supports `.p7b` and `.cer`).
        *   **Authenticated Fetching**: Supports CAC PIN entry for fetching certs in restricted network environments.

4.  **Enterprise Configuration**
    *   **DoD Certificate Installation**:
        *   **Mega Bundle**: Auto-generates a comprehensive trust store from multiple sources (DoD v5.17 WCF, v5.6, ECA).
        *   **Installation**: Securely installs the chain to `/etc/pki/ca-trust/source/anchors/` and updates the system trust store.
    *   **Browser Integration**:
        *   **NSS DB**: Configures Chrome/Chromium (`~/.pki/nssdb`) and Firefox (`~/.mozilla/firefox`).
        *   **Flatpak Support**: Scans and updates Firefox Flatpak profiles (`~/.var/app/...`).

5.  **Security Compliance (STIG)**
    *   **Embedded Logic**: Built-in compliance engine with 10 critical checks mapped to DISA RHEL 9 STIG requirements.
    *   **Zero-Privilege Auditing**: Executes non-destructive, read-only audit commands.
    *   **Automated Reporting**: Real-time pass/fail status and SCAP report generation.

### 🔮 Roadmap: Future Enhancements

1.  **VPN Configuration Helper**:
    *   Generate configuration snippets for OpenVPN or StrongSwan to utilize smart card authentication.
2.  **Desktop Policy Enforcement**:
    *   "One-Click Fix" to enforce screen locking on card removal (currently only audits this).
3.  **YubiKey Specifics**:
    *   Dedicated tab for YubiKey management (OTP vs CCID modes) using `ykman` integration if available.
4.  **Log Export**:
    *   One-click export of system logs and Sentinel debug data for troubleshooting.

## Prerequisites

*   **OS**: Linux (Fedora/RHEL optimized, Debian/Ubuntu compatible).
*   **Python**: 3.10+
*   **System Tools**: `pcscd`, `opensc`, `openssl`, `nss-tools`, `curl`, `pkcs15-tool`.

## Installation

**The Easy Way (Recommended)**
Sentinel provides a secure installer script that handles dependencies, virtual environments, and shell aliases automatically.

```bash
curl -fsSL https://snl.codefxr.com/install | bash
```

After installation, simply restart your terminal and run:
```bash
snl
# or
sentinel
```

**Manual Installation (Dev Mode)**
```bash
git clone https://github.com/CodeFXR/Sentinel.git
cd Sentinel
pip install -r requirements.txt
python sentinel.py
```
