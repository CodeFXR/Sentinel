# Omnissa Horizon Client: Certificate Troubleshooting & Fix on Fedora

## Overview
During the setup of the Omnissa (formerly VMware Horizon) Client on Fedora Linux 43, the application failed to connect to the VDI server (`vdi.ccoelearning.net`). It threw a certificate validation error specifically highlighting a failure to verify the `DigiCert Global G2 TLS RSA SHA256 2020 CA1` certificate.

This document details the troubleshooting process, the root causes identified, the attempted fixes (what didn't work), and the final working solution. This information is crucial for integrating the Omnissa client into the **Sentinel** project environment securely and reliably.

## Root Cause Analysis
The failure was a combination of two distinct issues compounding on each other:

1. **Server Misconfiguration:** The VDI server (`vdi.ccoelearning.net`) is misconfigured. During the TLS handshake, it only serves the leaf certificate and fails to provide the intermediate certificate (`DigiCert Global G2 TLS RSA SHA256 2020 CA1`).
2. **Client OS Incompatibility (Hardcoded Paths):** The Linux Omnissa client ships with its own bundled version of OpenSSL (`/usr/lib/omnissa/libcrypto.so.3`). Binary string analysis revealed that this library is compiled with hardcoded paths to look for trusted certificates in `/usr/lib/ssl/certs` and `/usr/lib/ssl/cert.pem`. These are standard paths on Debian/Ubuntu systems, but they **do not exist** on Fedora (which uses `/etc/pki/tls/certs`). Consequently, the client could not fall back on the host OS's root trust store to complete the broken certificate chain.

---

## The Troubleshooting Process

### 1. Verification of the Server Chain
We used OpenSSL to simulate the client's connection attempt:
```bash
openssl s_client -connect vdi.ccoelearning.net:443 -showcerts < /dev/null
```
**Result:** The output confirmed error 20 (`unable to get local issuer certificate`) and error 21 (`unable to verify the first certificate`). The chain stopped at the leaf certificate, proving the intermediate CA was missing from the server's payload.

### 2. Attempted Fixes (What Didn't Work / Dead Ends)
* **System-Wide CA Trust Update:** We downloaded the missing DigiCert Root and Intermediate CAs and attempted to copy them to `/etc/pki/ca-trust/source/anchors/` to update the system trust (`update-ca-trust`).
  * *Why it failed:* Lack of immediate `sudo` access halted the command. However, even if successful, the Omnissa client's hardcoded `/usr/lib/ssl` paths meant it would have ignored Fedora's updated system trust store anyway.
* **NSS Database Update:** We imported the certificates into the user's local NSS database (`~/.pki/nssdb`) using `certutil`.
  * *Why it failed:* While Chromium/Electron-based sub-components of the app use NSS, the primary connection protocol in Omnissa relies on its bundled OpenSSL (`libcrypto`), which ignores the NSS DB entirely.
* **Legacy VMware Cert Paths:** We created `~/.vmware/view/certs` and symlinked the certificates there.
  * *Why it failed:* Newer versions of the Omnissa client no longer rely on this legacy fallback path for primary TLS verification.

### 3. Binary Analysis
To understand exactly where the client was looking for certificates, we ran `strings` against the client and its libraries:
```bash
strings /usr/lib/omnissa/libcrypto.so.3 | grep -E "(/etc|/usr|/opt|/ssl|/certs)"
```
**Result:** This explicitly revealed `OPENSSLDIR: "/usr/lib/ssl"`, confirming the client was blind to Fedora's native certificate store.

---

## The Working Solution

To bypass both the server's missing intermediate certificate and the client's hardcoded Debian paths, we dynamically injected a custom certificate bundle into the application at runtime using environment variables.

### Step 1: Create a Custom CA Bundle
We downloaded the missing certificates, converted them to PEM format, and concatenated them with Fedora's default system CA bundle to ensure full global coverage plus our specific fix.

```bash
# Download Missing Certs
curl -o /tmp/DigiCertGlobalRootG2.crt http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
curl -o /tmp/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt

# Convert to PEM
openssl x509 -in /tmp/DigiCertGlobalRootG2.crt -inform DER -out /tmp/DigiCertGlobalRootG2.pem -outform PEM
openssl x509 -in /tmp/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt -inform DER -out /tmp/DigiCertGlobalG2TLSRSASHA2562020CA1-1.pem -outform PEM

# Combine with Fedora's System Bundle
mkdir -p ~/.omnissa/certs
cat /etc/pki/tls/certs/ca-bundle.crt /tmp/DigiCertGlobalRootG2.pem /tmp/DigiCertGlobalG2TLSRSASHA2562020CA1-1.pem > ~/.omnissa/ca-bundle.pem
```

### Step 2: Runtime Environment Variable Injection
OpenSSL respects the `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables, which take precedence over the hardcoded `/usr/lib/ssl` paths. We wrapped the application execution to enforce these variables.

**For GUI Launches (.desktop files):**
We copied the system `.desktop` files to the user's local directory (taking precedence over system ones) and modified the `Exec` lines:
```bash
mkdir -p ~/.local/share/applications
cp /usr/share/applications/horizon-client*.desktop ~/.local/share/applications/
sed -i 's|Exec=horizon-client|Exec=env SSL_CERT_FILE=/home/jvm/.omnissa/ca-bundle.pem SSL_CERT_DIR=/home/jvm/.omnissa/certs horizon-client|g' ~/.local/share/applications/horizon-client*.desktop
```

**For CLI Launches:**
We created a wrapper script in the user's local path (`~/.local/bin`):
```bash
mkdir -p ~/.local/bin
cat << 'EOF' > ~/.local/bin/horizon-client
#!/bin/bash
export SSL_CERT_FILE=/home/jvm/.omnissa/ca-bundle.pem
export SSL_CERT_DIR=/home/jvm/.omnissa/certs
exec /usr/bin/horizon-client "$@"
EOF
chmod +x ~/.local/bin/horizon-client
```

---

## Secondary Issue: Smart Card (CAC) Authentication Failure

### Overview
After resolving the initial certificate validation errors, another issue presented itself: the client failed to request a PIN or read the CAC certificate for authentication. Instead, it fell back to prompting for standard username/password credentials.

### Root Cause
The Omnissa client relies on a PKCS#11 module to interface with smart cards (specifically `/usr/lib/omnissa/horizon/pkcs11/libopenscpkcs11.so`, which is a symlink to Fedora's `/usr/lib64/opensc-pkcs11.so`). 

By examining the application logs (`/tmp/omnissa-jvm/horizon-client-*.log`), the following critical error was discovered:
```
Could not open module /usr/lib/omnissa/horizon/pkcs11/libopenscpkcs11.so: /usr/lib/omnissa/libcrypto.so.3: version `OPENSSL_3.4.0` not found
```

**What this means:**
The Fedora-provided `opensc-pkcs11.so` library is dynamically linked against the system's newer OpenSSL 3.4+ (`libcrypto.so.3`). However, the Omnissa application ships with an older bundled version of OpenSSL (3.0.x) inside `/usr/lib/omnissa/` and forces its path using `LD_LIBRARY_PATH` during launch. 

When the client attempts to `dlopen()` the system's smart card library, the older bundled `libcrypto` cannot satisfy the newer symbol requirements. This causes the smart card module loading to abort silently and forces the client to fall back to username/password authentication.

### Attempted Fixes (What Didn't Work / Dead Ends)
*   **Adding OpenSC to the NSS DB:** Trying to manually register the OpenSC PKCS#11 module to the user's `~/.pki/nssdb` using `modutil` did not alter the client's behavior. The client uses its own direct `dlopen()` loading mechanism for its primary authentication sequence rather than relying on the NSS database layer.
*   **Checking `pcscd` and Token Recognition:** We verified `pcscd` was active and correctly detecting the smart card token using `opensc-tool` and `pkcs11-tool`. The hardware and OS-level smart card infrastructure was functioning perfectly; the failure was strictly an application library conflict.

### The Working Solution
To force the Omnissa client to use the system's newer OpenSSL libraries—thereby satisfying the dependencies of `opensc-pkcs11.so`—we utilized the `LD_PRELOAD` environment variable.

We updated our execution wrappers and aliases to inject `LD_PRELOAD`:

```bash
# Example of the updated wrapper script (~/.local/bin/horizon-client)
#!/bin/bash
export SSL_CERT_FILE=/home/jvm/.omnissa/ca-bundle.pem
export SSL_CERT_DIR=/home/jvm/.omnissa/certs
export LD_PRELOAD="/usr/lib64/libcrypto.so.3:/usr/lib64/libssl.so.3"
exec /usr/bin/horizon-client "$@"
```

### Verification
When launched with `LD_PRELOAD`, the application log confirms successful loading:
```
horizon-client | Attempting to load cryptoki module /usr/lib/omnissa/horizon/pkcs11/libopenscpkcs11.so
horizon-client | Loaded 1 modules from /usr/lib/omnissa/horizon/pkcs11
```
The client now successfully identifies the PIV/CAC certificate and prompts for a smart card PIN, bypassing the legacy username/password fallback.

---

## Integration Notes for Sentinel

When packaging or configuring Omnissa within the Sentinel ecosystem, we **cannot rely on the host OS's default execution path** due to the hardcoded Debian paths and bundled library versions in Omnissa.

**Implementation Recommendations for Sentinel:**
1. **Application Wrapper:** Sentinel should launch the Omnissa binary via a dedicated Python or Bash wrapper that explicitly sets `SSL_CERT_FILE`, `SSL_CERT_DIR`, and `LD_PRELOAD`.
2. **Sentinel Mega Bundle:** Since Sentinel already implements a "Mega Bundle Cert Installation (v5.17)" and "Certificate Validation (OCSP/CRL)" features, it should maintain a dedicated `ca-bundle.pem` within the Sentinel directory structure (e.g., `~/.synapxis/certs/`). This bundle must include:
   * The host OS's native certificates.
   * DoD / ECA Root and Intermediate certificates.
   * Common commercial intermediates (like DigiCert G2) to compensate for poorly configured target endpoints.
3. **Smart Card / `LD_PRELOAD` Requirement:** It is strictly required to launch the Omnissa binary with `LD_PRELOAD` pointing to the host OS's native `libcrypto.so.3` and `libssl.so.3` files. This ensures the smart card middleware provided by the underlying Linux OS remains fully functional and bypasses library incompatibilities.
4. **Environment Isolation:** Do not attempt to rely on `update-ca-trust` or system-level modifications, as Sentinel aims to operate in userspace (avoiding containerization but maintaining clean configuration). Use the `env` injection strategy outlined above.
## Update: UI Freezing & Omnissa Client (Next) Stability

### 1. Omnissa Client (Next) Crashing
With the release of `horizon-client-next` (built on .NET Core 8 & Avalonia UI), injecting `LD_PRELOAD="/usr/lib64/libcrypto.so.3"` causes immediate segmentation faults due to symbol clashing with the .NET `libSystem.Security.Cryptography.Native.OpenSsl.so` module.

**The Fix:** We permanently backed up the bundled OpenSSL instead (`sudo mv /usr/lib/omnissa/libcrypto.so.3 /usr/lib/omnissa/libcrypto.so.3.bak`). This allows both the classic C++ client and the new .NET client to natively resolve `/lib64/libcrypto.so.3` through `LD_LIBRARY_PATH` fallback without needing the dangerous `LD_PRELOAD` hack.

### 2. UI Freezing / Hanging (The "26-Second Freeze" Bug)
When attempting to connect to a server, the UI would completely freeze if a CAC was inserted into the **Broadcom Corp 58200** reader.
*   **Root Cause:** OpenSC`s default behavior is to sequentially probe the inserted smart card with every known card driver to identify it. During this probe, the `setcos` driver transmits a specific APDU (`00 CA DF 30 05`). The firmware on the Broadcom 58200 reader fundamentally crashes/hangs when receiving this APDU, causing a hard timeout of exactly **26 seconds** before returning `SCARD_E_NOT_TRANSACTED` (0x80100016). Because the Omnissa Client (Next) interrogates the PKCS#11 module on the main UI thread, the entire application interface hangs for the duration of the timeout.
*   **The Fix:** We modified `/etc/opensc.conf` to restrict OpenSC exclusively to the PIV/CAC drivers, completely bypassing the fatal `setcos` probe. This reduced the smart card initialization time from 28+ seconds down to **0.2 seconds**.
