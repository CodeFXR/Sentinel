# Sentinel Debug Report: Validation & Configuration

**Date:** February 3, 2026
**Status:** RESOLVED

## 1. Certificate Validation Issue (SOLVED)

### Final Status
**Result:** SUCCESS
**Target Identity:** `VAZQUEZ.JUAN.ANTONIO.1402448950 (CN)`
**Validation Method:** Dynamic AIA Fetching with Authenticated Access.

### Issue Summary
Validation failed with `error 20: unable to get local issuer certificate`. The root cause was that the static certificate bundles (DoD v5.6/v5.17) did not contain the newer intermediate certificate `DOD ID CA-71`. While AIA fetching was attempted, it failed due to file format assumptions and potential access restrictions.

### Successful Resolution Steps
1.  **Dynamic File Type Handling (Critical Fix):**
    *   *Problem:* The AIA URL for CA-71 (`http://crl.disa.mil/sign/DODIDCA_71.cer`) returned a DER-encoded X.509 certificate (`.cer`). The original code blindly assumed all AIA URLs returned PKCS#7 bundles (`.p7b`) and tried to parse them with `openssl pkcs7`. This caused the conversion to fail silently.
    *   *Solution:* Implemented logic to check the URL extension.
        *   If `.p7b`: Use `openssl pkcs7 -print_certs`.
        *   If `.cer`: Use `openssl x509 -inform DER -outform PEM`.

2.  **PIN-Authenticated Access (User Request):**
    *   *Problem:* Users suspected that fetching or validating the AIA URL might require authentication (client certificate access).
    *   *Solution:* Added a "CAC PIN" input field to the validation UI.
        *   **Token Access:** Passed the PIN to `pkcs11-tool --login -O` to ensure all protected objects/certificates on the card are visible.
        *   **Network Access:** Passed the PIN as the `OPENSC_PIN` environment variable to `curl`. This supports environments where the client might need to negotiate mutual TLS using the smartcard to fetch the intermediate certificate.

3.  **Robust Regex:**
    *   Updated the AIA URL extraction regex to prioritize `CA Issuers - URI:` over generic `URI:` entries (which often point to OCSP responders, not certificates).

### Lessons Learned
*   **Never assume AIA formats:** DoD PKI uses a mix of `.p7b` and `.cer`. Parsers must handle both.
*   **Authentication matters:** Even public CRL/AIA endpoints can sometimes behave better or require context when accessed from a machine with a smartcard present. Allowing the user to provide a PIN unlocks the full capability of the token.

## 2. Browser Configuration Status

### Current Status
**Result:** STABLE (No Freezes)
**Observations:**
*   The application successfully scans standard NSS databases (`~/.pki/nssdb`) and Firefox profiles (`~/.mozilla/firefox`).
*   Timeout logic prevents the UI from freezing during database locks.
*   **Flatpak Support:** Logic added to scan `~/.var/app/org.mozilla.firefox` paths.

### Potential Issues
*   **Flatpak Sandbox Access:** While we configure the DB on the *host* filesystem, the Firefox running *inside* the Flatpak sandbox might not have read access to the `/usr/lib64/opensc-pkcs11.so` library path we injected.
*   **Fix:** The user may need to use `Flatseal` to grant Firefox read access to `/usr/lib64/`, or we should copy the library to a shared location (like `~/.local/lib/`) and point the DB there.

## 3. UI & UX

### Improvements Implemented
*   **Animations:** Braille spinners now active during long-running tasks.
*   **State Persistence:** Sidebar LEDs do not reset to "Idle" after running checks, preserving the "Success" state.
*   **Input Handling:** Added `Input` widget with password masking for secure PIN entry.

### Missing Functionalities
*   **PIN Check Details:** Currently dumps raw `pkcs15-tool` output; could be parsed into a cleaner "Retries Remaining: X" display.
*   **SCAP Report:** Basic text generation implemented; could be enhanced with specific CVE checks or STIG compliance rules.