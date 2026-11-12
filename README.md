<div align="center">
  <img src="sentinel_cac_manager.png" alt="sentinel_icon" width="220" />

  <h1>Sentinel</h1>

  <p>
    <strong>Automated Common Access Card (CAC) identity, trust, and middleware manager for Linux.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Made%20with-GTK4%20%2F%20Libadwaita-00ADD8?style=flat-square" alt="GTK4 Libadwaita" />
    <img src="https://img.shields.io/badge/Language-Python%20%26%20Rust-00ADD8?style=flat-square" alt="Python & Rust" />
    <img src="https://img.shields.io/badge/Version-v2.0.3-blue?style=flat-square" alt="Version" />
    <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" />
  </p>

  <p>
    <a href="#why-sentinel"><strong>Why Sentinel</strong></a> ·
    <a href="#installation"><strong>Installation</strong></a> ·
    <a href="#usage"><strong>Usage</strong></a> ·
    <a href="#troubleshooting"><strong>Troubleshooting</strong></a> ·
    <a href="#limitations"><strong>Limitations</strong></a> ·
    <a href="https://github.com/CodeFXR/Sentinel/issues"><strong>Report Bug</strong></a>
  </p>
</div>

<br>
<br>

Configuring a Common Access Card on Linux usually requires orchestrating PC/SC daemons, compiling OpenSC drivers, modifying NSS security databases, installing root certificate stores across divergent distribution paths, and battling browser policy locks. One missed configuration step prevents mutual TLS authentication to military portals. Sentinel automates this entire pipeline into a single, verified workflow with an intuitive desktop interface and CLI.

> **Disclaimer:** Unofficial open-source utility; not affiliated with, sponsored by, or endorsed by the U.S. Department of Defense (DoD) or the Defense Information Systems Agency (DISA).

## Why Sentinel?

- **Cryptographic Trust Verification:** Every DoD certificate is verified against both a raw-file and canonical ASN.1 DER SHA-256 manifest, CA basic constraints, and validity window before installation.
- **PKI Trust Anchor Separation:** Installs only the 4 self-signed DoD Root CAs into the OS root trust store, while importing intermediate CAs into browser NSS databases for chain building.
- **Deep Browser Integration:** Registers PKCS#11 modules via non-destructive Firefox enterprise policies and Chrome NSS databases (`~/.pki/nssdb`).
- **Hardware Optimization:** Restricts OpenSC driver probing to eliminate 26-second Broadcom 58200 contactless initialization hangs.
- **Multi-Distribution Support:** Hardware-validated on Fedora and Ubuntu/Debian, with platform abstraction for Arch Linux and openSUSE.
- **Full Operational Rollback:** Non-destructive `--uninstall` mode reverts Sentinel-installed certificates, browser policy keys, NSS modules, and desktop shortcuts while preserving third-party enterprise settings.

## Installation

### Quick Install (Recommended)

Install Sentinel directly using the verified one-liner installer:

```bash
curl -fsSL https://snl.codefxr.com/install | bash
```

### Requirements

| Component | Minimum Version | Notes |
|---|---|---|
| Linux Kernel | 5.4+ | USB CCID smart card support enabled |
| Python | 3.10+ | Standard runtime with PyGObject and `cryptography` |
| PC/SC Daemon | 1.8+ | `pcscd` service and socket |
| OpenSC | 0.20+ | PKCS#11 middleware provider |

### Manual Installation Options

<details>
<summary><strong>Option 1: Release Archive</strong></summary>

Download the pre-packaged offline release archive (`Sentinel-CAC-Manager.tar.gz`) from [GitHub Releases](https://github.com/CodeFXR/Sentinel/releases):

```bash
# Verify the archive SHA-256 against the published release digest
echo "cd788e44603bd669468f5c82d33417ae1f75324a48e01aa70b1a746cc8bdbbe3  Sentinel-CAC-Manager.tar.gz" | sha256sum -c -
tar -xzf Sentinel-CAC-Manager.tar.gz
cd Sentinel-CAC-Manager
./install
```
</details>

<details>
<summary><strong>Option 2: Clone from Repository</strong></summary>

```bash
git clone --branch v2.0.3 https://github.com/CodeFXR/Sentinel.git
cd Sentinel
./install
```
</details>

<details>
<summary><strong>Unattended & Headless Installation</strong></summary>

For server or automated container provisioning without graphical display:

```bash
curl -fsSL https://snl.codefxr.com/install | bash -s -- --cli
```

Or from a cloned repository checkout:

```bash
./install --cli
```
</details>

## Usage

Sentinel provides both a Libadwaita desktop application and an unattended command-line interface.

### Command-Line Interface

| Command | Description |
|---|---|
| `sentinel` | Launch the graphical user interface |
| `sentinel --status` | Display full system diagnostics, middleware health, and card status |
| `sentinel --setup-all` | Run complete automated configuration (services, CAs, browsers) |
| `sentinel --card-info` | Display details, EDIPI, holder name, and validity of inserted CAC |
| `sentinel --pin-status` | Display PIV PIN verification retry counter and lock state |
| `sentinel --change-pin` | Interactively change PIV smart card PIN (zeroizes native Rust APDU buffers) |
| `sentinel --lock-on-removal` | Enable automatic desktop screen lock when card is removed |
| `sentinel --no-lock-on-removal` | Disable automatic desktop screen lock on card removal |
| `sentinel --agent` | Run background event daemon for desktop insert/removal notifications |
| `sentinel --install-agent` | Install and enable user systemd service for card monitoring |
| `sentinel --browsers` | Configure Firefox and Chrome/Chromium NSS databases only |
| `sentinel --certs` | Install verified DoD Root CAs into operating system trust only |
| `sentinel --reader-fix` | Apply OpenSC Broadcom reader driver hang fix |
| `sentinel --check-update` | Check GitHub Releases for a newer SHA-256 verified version |
| `sentinel --update` | Download and apply SHA-256 verified update with transactional rollback |
| `sentinel --uninstall` | Revert Sentinel-managed trust anchors, policies, and browser modules |

### Desktop Interface

Launch Sentinel from your application menu or run `sentinel`. The interface provides four primary workspaces:

1. **Dashboard:** Live status overview of reader hardware, inserted card status, EDIPI, and middleware daemon.
2. **Card Inspector:** Detailed inspection of on-card PIV Authentication, Email Signature, and Encryption certificates with cryptographically verified OCSP checks.
3. **Browser Health:** Profile-by-profile verification of Firefox, Chrome, Chromium, Brave, and Edge security devices.
4. **System Diagnostics:** Distribution detection, package verification, and one-click repair actions.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No smart card readers found` | `pcscd` daemon inactive or CCID driver missing | Run `sentinel --setup-all` to install `ccid` and enable `pcscd.socket`. |
| Broadcom reader takes 30s to detect card | OpenSC probing SetCOS and older card drivers | Run `sentinel --reader-fix` to restrict OpenSC drivers to PIV/CAC. |
| Firefox fails to prompt for PIN | Profile `user.js` or `policies.json` missing | Run `sentinel --browsers` and restart Firefox. |
| Chrome/Edge does not detect CAC | `~/.pki/nssdb` lacks OpenSC module | Run `sentinel --browsers` while Chrome is closed to release DB lock. |
| Certificate untrusted in browser | DoD root CA chain missing from NSS/system | Run `sentinel --certs` to deploy verified DoD Root CAs. |
| `pkexec` dialog fails to open | Polkit agent not running in minimal desktop | Run command via `sudo ./install` in terminal. |

## Limitations

| Limitation | Status | Details |
|---|---|---|
| On-Card PIN Change | PIV Applet Only | Uses NIST SP 800-73-4 `CHANGE REFERENCE DATA` APDUs in an exclusive PC/SC transaction; zeroizes native Rust APDU buffers (caller Python `str` objects remain managed by CPython); requires confirmation at 2 retries and blocks at 1 retry. |
| OCSP Revocation Check | Network Dependent | Verifies leaf signature against DoD CA, `.mil` OCSP host, responder signature, `id-kp-OCSPSigning` EKU, CertID hashes, and freshness window; some DoD OCSP responders require NIPRNet/VPN access. |
| Firefox Enterprise Policy | Installs Chain Bundle | Sets `ImportEnterpriseRoots: true` and loads `DoD_Full_Chain.pem` into Firefox so `.mil` servers omitting intermediate CAs still chain to DoD Roots. |
| Distribution Validation | Hardware Tested on Fedora & Ubuntu | Arch Linux and openSUSE are supported via platform abstraction but have not been tested with physical CAC hardware in a VM. |
| Workstation Login (PAM/SSSD) | Experimental / Archived | Hardened PAM/SSSD logon logic is archived in `archive/future_workstation_logon.py` pending multi-distro VM validation. |
| macOS / Windows Support | Unsupported | Linux only by design. |

## License

[MIT](LICENSE) © 2026 CodeFXR
