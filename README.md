<div align="center">
<img src="https://github.com/user-attachments/assets/ad6d18f0-05b1-40f7-8575-fc0d114ad8d1" alt="sentinel_icon" width="120" />

<h1>Sentinel Identity Manager</h1>

<p>
<strong>Enterprise-grade TUI for DoD CAC/PIV management, certificate validation, and STIG compliance on Linux.</strong>
</p>

<p>
<img src="https://img.shields.io/badge/Made%20with-Textual-orange?style=flat-square" alt="Textual" />
<img src="https://img.shields.io/badge/Security-STIG%20Compliant-red?style=flat-square" alt="STIG" />
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python" />
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" />
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

System Compliance: Real-time monitoring of pcscd with auto-remediation via pkexec. Verifies OpenSC middleware and provides clean hardware scanning for card readers.

Identity Management: Robust extraction of User Principal Name (UPN) and Common Name (CN). Supports non-destructive PIN retry inspection, PIN updates, and PUK-based unblocking.

Certificate Validation: Automatically resolves validation errors (Error 20) by fetching missing intermediate certificates via AIA URLs, dynamically building working chains for newer DoD certificates.

Enterprise Auth: Automates PIV Authentication public key export for SSH and provides automated agent setup.

Digital Signatures: Integrated PDF signing via pyhanko and PKCS11. Includes automated detection and warnings for unsupported Adobe XFA forms.

Browser Sync: One-click configuration for Chrome/Chromium NSS databases and Firefox profiles, including Flatpak support.

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

Sentinel is designed for high-assurance environments with a focus on zero-privilege auditing and secure data handling.

STIG Auditing: Built-in engine with 10 critical checks mapped to DISA RHEL 9 STIG requirements (e.g., SC-LINUX-001).

Hardened Subprocesses: All backend calls utilize asyncio.create_subprocess_exec to pass arguments as lists, neutralizing shell injection vulnerabilities.

PIN Privacy: PINs are handled exclusively via Environment Variables or stdin. They are never logged, stored, or visible in process lists.

Privilege Minimalization: The application runs as a standard user, utilizing pkexec only for specific system repairs like starting pcscd.

Architecture

Frontend: Textual (Python) for reactive, asynchronous TUI components.

Backend: AsyncIO for non-blocking hardware interaction and subprocess management.

Validation: OpenSSL integration for AIA chasing and chain verification.

Signatures: pyHanko and python-pkcs11 for hardware-token digital signatures.

<br>

<p align="center">
&copy; CodeFXR. All rights reserved.
</p>
