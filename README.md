<div align="center">
<img width="516" height="489" alt="sentinel_icon" src="https://github.com/user-attachments/assets/ad6d18f0-05b1-40f7-8575-fc0d114ad8d1" />

<h1>Sentinel Identity Manager</h1>

<p>
<strong>Enterprise-grade TUI for DoD CAC/PIV management, certificate validation, and STIG compliance on Linux.</strong>
</p>

<p>
<img src="https://img.shields.io/badge/Made%20with-Textual-orange?style=flat-square" alt="Textual" />
<img src="https://img.shields.io/badge/Security-STIG%20Compliant-red?style=flat-square" alt="STIG" />
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python" />
<img src="https://img.shields.io/badge/OS-Linux-lightgrey?style=flat-square&logo=linux" alt="Linux" />
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
<img width="800" alt="sentinel_demo" src="https://github.com/user-attachments/assets/74476b31-a976-425a-afd9-dc580489507d" />
</p>

<br>

Key Features

Sentinel provides a unified interface for managing Smart Cards (CAC/PIV) in secure environments, replacing complex CLI workflows with automated diagnostic and configuration logic.

System Compliance and Diagnostics: Real-time monitoring of pcscd with auto-remediation via pkexec. Verifies OpenSC middleware and provides clean hardware scanning for card readers.

Identity Management: Robust extraction of User Principal Name (UPN) and Common Name (CN). Supports non-destructive PIN retry inspection, PIN updates, and PUK-based unblocking.

AIA Chasing and Certificate Validation: Automatically resolves validation errors (e.g., Error 20) by fetching missing intermediate certificates via AIA URLs, dynamically building a working chain for newer DoD certificates.

Enterprise Authentication: Automates PIV Authentication public key export for SSH and provides automated agent setup.

Digital Signatures: Integrated PDF signing via pyhanko and PKCS11. Includes automated detection and warnings for Adobe XFA (Dynamic) forms.

Browser Integration: One-click configuration for Chrome/Chromium NSS databases and Firefox profiles, including support for Flatpak installations.

Installation

Sentinel requires Python 3.10+ and standard PKCS#11 system tools.

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
Controls
Context	Shortcut	Action
Global	Ctrl + Q	Quit Application
Global	Tab	Switch Tabs
Forms	Enter	Submit / Execute Action
Navigation	Mouse	Select Fields and Buttons
Security and Compliance

Sentinel is architected for high-assurance environments with a focus on zero-privilege auditing and secure data handling.

STIG Compliance: Built-in engine with 10 critical checks mapped to DISA RHEL 9 STIG requirements (e.g., SC-LINUX-001).

Hardened Subprocesses: All critical backend calls utilize asyncio.create_subprocess_exec to pass arguments as lists, neutralizing shell injection vulnerabilities.

Secure PIN Handling: PINs are handled exclusively via Environment Variables or stdin. They are never passed as command-line arguments and never appear in system logs or process lists.

Privilege Minimalization: The application runs as a standard user, utilizing pkexec only for specific system-level repairs like starting pcscd or updating trust anchors.

Architecture

Frontend: Textual (Python) for a reactive, asynchronous Terminal User Interface.

Backend: AsyncIO for non-blocking hardware interaction and subprocess management.

Certificates: OpenSSL integration for AIA chasing and certificate chain verification.

Signatures: pyHanko and python-pkcs11 for hardware-token digital signatures.

<br>

<p align="center">
&copy; CodeFXR. All rights reserved.
</p>
