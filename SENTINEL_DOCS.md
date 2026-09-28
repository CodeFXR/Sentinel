# Sentinel
### Enterprise Identity Manager for Linux
![Python](https://img.shields.io/badge/Python-3.10%2B-yellow) ![Type](https://img.shields.io/badge/Type-TUI-blue) ![Security](https://img.shields.io/badge/Security-DoD%20PKI-red)

**Sentinel** is a terminal-based interface (TUI) designed to simplify the complex world of DoD Smart Cards (CAC/PIV) on Linux. It replaces obscure CLI commands with a modern, visual dashboard for diagnostics, certificate validation, and digital signing.

---

## Features

### 🛡️ System Diagnostics & Compliance
*   **Real-time Monitoring:** Instantly visualize the status of your PC/SC service (`pcscd`), Middleware (`OpenSC`), and Card Reader.
*   **Auto-Remediation:** Detects if the Smart Card service is dead and offers a one-click fix (requires `sudo` only for this action).
*   **STIG Compliance:** Built-in RHEL 9 STIG checks ensure your system meets security baselines (e.g., locking screen on card removal).

### 🪪 Identity Management
*   **Visual Dashboard:** See your Cardholder Name, Agency, and Token Info at a glance.
*   **PIN Management:** Securely check PIN retry counts, change your PIN, or unblock a locked card using a PUK.
*   **Identity Mapping:** Automatically extracts Principal Names (UPN) for mapping to local Linux users.

### 🔐 Certificate Validation (Enterprise Grade)
*   **AIA Chasing:** The "Magic Fix" for Error 20. Sentinel dynamically fetches missing intermediate certificates from DoD servers using your cached credentials.
*   **Authenticated Fetch:** Supports fetching certificates even in restricted network environments by using your CAC PIN for mutual TLS.
*   **Mega-Bundle Installation:** One-click download and installation of the complete DoD Trust Chain (Root CA v5.x, WCF v5.17, ECA) to your system trust store.

### 🖊️ Digital Signing & Operations
*   **PDF Signing:** Digitally sign PDF documents using your hardware token. Compatible with standard PDFs (Note: Adobe XFA forms are detected and skipped).
*   **SSH Integration:** Automates the export of your SSH Public Key and provides instructions for adding your CAC to `ssh-agent`.
*   **Browser Config:** Auto-configures Firefox (Snap/Flatpak/Native) and Chrome/Chromium databases to recognize your smart card.

---

## Prerequisites

Before installing, ensure you have a standard Linux environment.

*   **OS:** Fedora, RHEL, Ubuntu, Debian, or Arch Linux.
*   **Hardware:** A USB Smart Card Reader and a valid ISO 7816 Smart Card (CAC/PIV).
*   **System Tools:**
    *   `pcscd` (PC/SC Smart Card Daemon)
    *   `opensc` (Middleware)
    *   `python3` (3.10 or newer)
    *   `git` & `curl`

---

## Installation

We provide a streamlined installer that sets up a sandboxed environment and shell aliases.

### The One-Liner (Recommended)
Copy and paste this into your terminal:

```bash
curl -fsSL https://snl.codefxr.com/install | bash
```

### What does this do?
1.  **Clones** the repository to `~/.sentinel`.
2.  **Creates** a Python virtual environment (so it doesn't mess with your system packages).
3.  **Installs** dependencies (`textual`, `pyhanko`, `cryptography`).
4.  **Adds** the `snl` alias to your shell config (`.bashrc`, `.zshrc`).

---

## Usage

After installation, simply restart your terminal and type:

```bash
snl
```

### Keyboard Navigation
Sentinel is built for speed. You can use your mouse or keyboard.

| Key | Action |
| :--- | :--- |
| `Tab` | Cycle through inputs and buttons. |
| `Enter` | Activate a button or submit a form. |
| `Ctrl+C` | Force Quit (Safe Exit). |

### Common Workflows

#### 1. Fixing "Certificate Not Trusted" in Browsers
1.  Launch Sentinel (`snl`).
2.  Go to the **"Config"** tab.
3.  Click **"Install DoD Mega Bundle"**.
4.  Click **"Configure Browsers"**.
5.  Restart Chrome/Firefox.

#### 2. Signing a PDF
1.  Go to the **"Signing"** tab.
2.  Enter the full path to your PDF (e.g., `/home/user/docs/contract.pdf`).
3.  Enter your **PIN**.
4.  Click **"Sign PDF"**.
5.  The signed file is saved as `contract_signed.pdf`.

---

## Troubleshooting

### ⚠️ "Card Reader Not Detected"
*   Ensure your USB reader is plugged in **before** starting the app.
*   Run `lsusb` in a separate terminal to verify the Linux kernel sees the device.
*   If the "Service" LED in Sentinel is red, click the "Fix Service" button.

### ⚠️ "Error 20: Unable to get local issuer"
This means your system is missing an Intermediate CA certificate.
1.  Go to the **"Validation"** tab.
2.  Enter your PIN (optional, but recommended for network access).
3.  Click **"Validate & Fix"**. Sentinel will attempt to fetch the missing certificate via AIA.

### 🗑️ Uninstalling
To remove Sentinel completely:

```bash
rm -rf ~/.sentinel
# Then remove the 'alias snl=...' line from your .bashrc/.zshrc
```
