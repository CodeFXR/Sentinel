<div align="center">
<img width="1408" height="768" alt="sentinel_icon" src="https://github.com/user-attachments/assets/5976361f-624b-49f4-bf73-493c74796b4d" />


<h1>Sentinel Identity Manager</h1>

<p>
<strong>An enterprise-grade TUI for DoD CAC/PIV management, certificate validation, and STIG compliance on Linux.</strong>
</p>

<p>
<img src="https://img.shields.io/badge/Made%20with-Textual-orange?style=flat-square" alt="Textual" />
<img src="https://img.shields.io/badge/Security-STIG%20Compliant-red?style=flat-square" alt="STIG" />
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python" />
<img src="https://img.shields.io/badge/OS-Linux%20(RHEL/Fedora/Ubuntu)-lightgrey?style=flat-square&logo=linux" alt="Linux" />
</p>

<p>
<a href="#key-features"><strong>Features</strong></a> ·
<a href="#installation"><strong>Installation</strong></a> ·
<a href="#security--compliance"><strong>Security</strong></a> ·
<a href="https://github.com/yourusername/sentinel/issues"><strong>Report Bug</strong></a>
</p>
</div>

<br>

<p align="center">
<img width="1366" height="768" alt="sentinel_demo" src="https://github.com/user-attachments/assets/74476b31-a976-425a-afd9-dc580489507d" />
</p>

<br>

Why Sentinel?

Managing Smart Cards (CAC/PIV) on Linux has traditionally required a "Frankenstein" approach of CLI tools and manual configuration. Sentinel replaces complexity with a unified dashboard designed for system administrators and power users in secure environments.

Automated Remediation: Real-time monitoring of pcscd and middleware with one-click fixes for service failures.

The "Error 20" Fix: Advanced AIA Chasing automatically fetches missing intermediate certificates to resolve validation errors on newer DoD cards (e.g., CA-71).

Hardened Security: Built-in compliance engine with 10 critical checks mapped directly to DISA RHEL 9 STIG requirements.

Digital Signing: Native PDF signing via pyhanko with built-in detection for unsupported Adobe XFA forms.

Zero-Touch Config: Automated trust store generation (DoD Mega Bundle) and browser integration (NSS DB/Firefox/Flatpak).

Key Features
🛠️ System Diagnostics

Middleware Detection: Verifies OpenSC and PKCS#11 modules.

Hardware Scanning: Real-time card reader monitoring with advanced filtering for clean logs.

Service Repair: Auto-starts pcscd via secure pkexec escalation.

🆔 Identity & PIN Management

Identity Mapping: Extraction of UPN/CN from hardware tokens.

PIN Utilities: Non-destructive status checks, secure PIN updates, and PUK-based unblocking.

🛡️ Enterprise Integration

SSH Automation: Automated public key export to ~/.ssh/authorized_keys.

Trust Management: Auto-generates trust stores from DoD v5.17 WCF, v5.6, and ECA sources.

Browser Sync: Updates NSS databases for Chrome and Firefox (including Flatpak profiles).

Installation

Sentinel requires Python 3.10+ and standard PKCS#11 tools.

code
Bash
download
content_copy
expand_less
# Install system dependencies (RHEL/Fedora example)
sudo dnf install opensc openssl nss-tools pcsc-lite

# Clone and Install
git clone https://github.com/yourusername/sentinel.git
cd sentinel
pip install -r requirements.txt

# Launch Sentinel
python sentinel.py
Security & Compliance

Sentinel is designed for high-assurance environments:

Safe Execution: All backend operations use asyncio.create_subprocess_exec to prevent shell injection.

PIN Privacy: PINs are passed via environment variables or stdin; they are never logged, stored, or visible in process lists.

STIG Auditing: Includes a read-only compliance engine that checks 10 critical STIG IDs (e.g., SC-LINUX-001) without altering system state unless prompted.

Controls
Context	Shortcut	Action
Global	Ctrl + Q	Quit Application
Global	Tab	Switch Tabs (General/Security/Tools)
Forms	Enter	Submit / Execute Action
Navigation	Mouse	All buttons and fields are clickable
Architecture

Frontend: Textual (Python) for a reactive, async TUI.

Backend: AsyncIO subprocess management for non-blocking hardware interaction.

Validation: OpenSSL for AIA chasing and chain verification.

Signing: pyHanko integration for PKCS#11 digital signatures.

Roadmap

VPN Helper: Generate OpenVPN/StrongSwan snippets for smart card auth.

YubiKey Suite: Dedicated management tab for OTP/CCID mode switching.

Policy Enforcement: One-click "Lock on Card Removal" STIG enforcement.

<br>

<p align="center">
&copy; 2026 Sentinel Project. Released under the MIT License.
</p>
