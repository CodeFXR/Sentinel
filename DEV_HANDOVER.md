# Sentinel Development Handover

**Date:** February 4, 2026
**Version:** v1.0.0 (Gold Master)
**Stack:** Python 3.10+, Textual (TUI), asyncio, pyHanko, OpenSC

## 1. Project Overview
Sentinel is a Linux TUI application for managing DoD Smart Cards (CAC/PIV). It replaces complex CLI commands with a user-friendly interface for diagnostics, certificate validation, and configuration.

## 2. Architecture & Logic

### Frontend (`sentinel.py`)
*   **Framework:** Built with `textual`.
*   **Layout:**
    *   **Sidebar:** Permanent status LEDs (Service, Middleware, Hardware, Certs, etc.).
    *   **Main Panel:** Tabbed interface (`TabbedContent`) for context switching.
*   **Design Philosophy:** "Compact & Efficient". Input fields are height-1, buttons height-3. Horizontal layouts used to save vertical space.
*   **Event Handling:** `on_button_pressed` maps UI events to `sentinel_backend` methods.

### Backend (`sentinel_backend.py`)
*   **AsyncIO:** All heavy operations (subprocesses) are asynchronous to prevent UI freezing.
*   **Subprocess Management:**
    *   Uses `asyncio.create_subprocess_exec` for **all** critical command executions (Certificate validation, PIN checks, Browser config) to prevent shell injection.
    *   Uses `asyncio.create_subprocess_shell` only where absolutely necessary for simple non-input pipe chains.
*   **Logging:** Writes to both a visual `Log` widget (passed as a callback) and a system log (`sentinel.log`).

### specialized Modules
*   **`sentinel_stig.py`**: Embedded compliance engine.
    *   **Logic:** Contains a list of rule dictionaries with `check_func` callbacks.
    *   **Safety:** All checks are read-only (e.g., `rpm -q`, `systemctl is-active`).
    *   **Coverage:** 10 critical checks mapped to RHEL 9 STIGs (e.g., `SC-LINUX-001`).
*   **`sentinel_pdf_signer.py`**: Helper script for `pyhanko`.
    *   **Purpose:** Bypasses missing `pyhanko` CLI by importing the library directly.
    *   **Logic:** Detects Adobe XFA (unsupported) before attempting to sign. Uses `PKCS11Signer` with `key_id=0x01` (PIV Auth).

## 3. Key Features & Implementation Details

### A. Certificate Validation (The "Error 20" Fix)
*   **Problem:** Newer DoD cards (e.g., CA-71) are signed by intermediates NOT in the standard v5.x bundles.
*   **Solution:** **AIA Chasing**.
    1.  Extract `Authority Information Access` URL from the user cert.
    2.  Download the missing cert (handling both `.p7b` and `.cer` formats).
    3.  Dynamically build a `working_chain.pem`.
    4.  Verify using `openssl verify -partial_chain`.

### B. PDF Signing
*   **Library:** `pyhanko` + `python-pkcs11`.
*   **Workflow:**
    1.  User provides PDF path + PIN.
    2.  App calls `sentinel_pdf_signer.py` via the **virtual environment python**.
    3.  Script opens PKCS#11 session, finds PIV key, and appends a visual signature (`Signature1`).
*   **Caveat:** Does **NOT** support Adobe XFA (Dynamic) forms. Use "Print to PDF" to flatten them first.

### C. SSH Integration
*   **Key Export:** Runs `pkcs15-tool --read-ssh-key 01` to get the pubkey.
*   **Agent:** Displays instructions for `ssh-add -s /usr/lib64/opensc-pkcs11.so`. We do *not* run this automatically because it blocks for user input on the TTY, freezing the TUI.

### D. Security Hardening
*   **Shell Injection Prevention:** All critical backend calls now use `asyncio.create_subprocess_exec` which passes arguments as a list, neutralizing shell injection attacks.
*   **Secure PIN Handling:**
    *   PINs are passed exclusively via Environment Variables (`OPENSC_PIN` for OpenSC, `SENTINEL_PIN` for helper scripts).
    *   PINs never appear in command-line arguments or process lists (`ps aux`).

## 4. Security & Safety

*   **PIN Handling:** PINs are passed via environment variables (`OPENSC_PIN`) or stdin. They are never logged or passed as command-line arguments.
*   **Privilege Escalation:** `pkexec` is used *only* for specific repair commands (`systemctl start pcscd`, `update-ca-trust`). The app runs as standard user.
*   **Input Sanitization:** File paths are handled via python libraries or quoted strings.

## 5. Known Issues / "Don'ts"

*   **Don't** assume `pyhanko` has a CLI. Use the library wrapper.
*   **Don't** try to interact with `ssh-agent` prompts from within `asyncio`. It captures stdin/stdout and makes the prompt invisible.
*   **XFA Support:** Adobe XFA forms are detected and rejected gracefully with a warning. This is a library limitation.

## 6. Next Steps (Roadmap)

1.  **VPN Config:** Generate OpenVPN profiles using the PKCS#11 provider.
2.  **YubiKey Tab:** Add specific toggles for YubiKey interfaces (OTP/CCID) using `ykman`.
3.  **Desktop Policy:** Button to `gsettings set ... removal-action 'lock-screen'` to enforce the STIG rule.
