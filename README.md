# Sentinel

**Terminal UI for configuring a DoD CAC (PIV) smart card on Linux.**

Sentinel installs and verifies the smart-card stack, drops the DoD root CAs into your
system trust store, registers the PKCS#11 module with your browsers, and shows you a
live status panel while you work. It runs as your normal user and only escalates for
the two operations that genuinely need root.

```
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) /
  /___/\__/_//_/\__/_/_//_/\__/_/
```

## Status: v2.0.0 — post-scope-reduction

**This is not a finished product. Read [Known limitations](#known-limitations) before
you rely on it.** It is a working tool on Fedora/RHEL and untested everywhere else.

v2.0.0 removed certificate validation, SSH integration, PDF signing, PIN management,
STIG auditing, and SCAP reporting. Those features were removed because they were
incomplete, in several cases unsafe, and all of them blocked the tool's actual job.
See [`ROADMAP.md`](ROADMAP.md) for the reasoning and [`CRITICAL_ASSESSMENT.md`](CRITICAL_ASSESSMENT.md)
for the full review.

## What it does

Three things, and only three things:

1. **Checks the stack** — is `pcscd` running, is OpenSC installed, does the card
   reader enumerate, are the DoD roots in the trust store.
2. **Installs the DoD roots** — writes `DoD_Mega_Chain.pem` into your distribution's
   trust-anchor directory and refreshes the trust store via `pkexec`.
3. **Configures browsers** — registers the OpenSC PKCS#11 module as "DoD CAC" in
   every NSS database it finds: `~/.pki/nssdb` (Chromium), native Firefox profiles,
   and Flatpak Firefox profiles.

Plus a **Scan** tab that streams `pcsc_scan` output so you can see card insert and
removal events live.

## What it does NOT do

Read this list before assuming otherwise. Every item was either removed in v2.0.0 or
never worked.

- It does **not** install `opensc`, `pcscd`, or `nss-tools` for you. If they are
  missing, it tells you so and you install them yourself. Automating this is the
  top item in the roadmap.
- It does **not** validate certificates, check revocation, or report your identity.
  Removed in v2.0.0. The previous implementation printed `OCSP/CRL Check: PASSED`
  without performing any revocation check; that is worse than no check.
- It does **not** manage your PIN, sign PDFs, or export SSH keys. Removed in v2.0.0.
- It does **not** run STIG or SCAP audits. Removed in v2.0.0.
- It does **not** work on Debian/Ubuntu/Zorin yet. The certificate install and
  browser configuration still use Fedora-only paths. See
  [Known limitations](#known-limitations).

## Requirements

| | |
|---|---|
| **OS** | Linux. **Only Fedora/RHEL paths are implemented and tested.** |
| **Python** | 3.10+ |
| **Python packages** | `textual`, `distro` (installed by the setup script) |
| **System packages you must install yourself** | `pcscd`, `opensc`, `openssl`, `nss-tools` |

Fedora/RHEL:

```bash
sudo dnf install pcscd opensc openssl nss-tools
sudo systemctl enable --now pcscd
```

## Install

```bash
git clone https://github.com/CodeFXR/Sentinel.git
cd Sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python sentinel.py
```

The `install` script in this repository is provided for convenience, but see
[Known limitations](#known-limitations) — it requires `git` and `python3` to be
present already, it does not install system packages, and it does not yet handle the
Debian/Ubuntu `python3-venv` split.

## Usage

Two tabs.

**Config**

| Button | What it does | Needs root? |
|---|---|---|
| `RUN CHECKS` | Probes `pcscd`, checks for `pcsc_scan`/`pkcs11-tool`/`opensc-tool`, enumerates PKCS#11 slots, tries to start `pcscd` if it is down | Only to start `pcscd` |
| `INSTALL CERTS` | Copies `DoD_Mega_Chain.pem` to the trust-anchor directory and runs the trust-store refresh | Yes, via `pkexec` |
| `CONFIG BROWSERS` | Adds the `DoD CAC` PKCS#11 module to every NSS database found | No |

**Scan**

Runs `pcsc_scan` and streams reader/card events. Press `RUN` again to stop.

The sidebar LEDs show live state for the service, middleware, hardware, certificates,
and browser integration.

### Keyboard

There are no key bindings yet. The interface is mouse-driven. Keyboard navigation is
on the roadmap.

## Known limitations

These are real, current, and not hypothetical.

**Portability — the big one.** The certificate install writes to
`/etc/pki/ca-trust/source/anchors/` and runs `update-ca-trust`. The browser config
looks for the OpenSC module at `/usr/lib64/opensc-pkcs11.so`. Both are Fedora/RHEL
paths. On Debian, Ubuntu, or Zorin OS the certificate install fails and the browser
config aborts immediately. The tool currently detects nothing about your distribution
beyond printing its name. This is being fixed next.

**The trust store is over-populated.** `DoD_Mega_Chain.pem` contains 197
entries covering 69 unique certificates, of which only **15 are verified self-signed
roots**. The other 54 are intermediates and cross-certificates, and installing
them all as trust anchors grants far more trust than a DoD workstation needs. Rebuilding the bundle to contain
self-signed roots only is on the roadmap. Until then, know what you are installing.

**The installer needs `git` and `python3` already present.** It exits with an error
if they are missing rather than installing them.

**`python3 -m venv` fails on Debian/Ubuntu/Zorin** unless `python3-venv` is installed
first. The setup script does not detect this and may report success when the virtual
environment was never created.

**Browser configuration is silently lost if Firefox is running.** Firefox rewrites
`prefs.json` on exit and will discard a module added while it was open. Close
Firefox first, then run `CONFIG BROWSERS`, then restart it.

**`BROADCOM 58200 readers hang for 26 seconds on first card insert.** OpenSC's
default driver probe sends an APDU that crashes this reader's firmware. Workaround:

```
# /etc/opensc.conf
card_drivers = piv-II, cac, cac1
```

The Broadcom 58200 is a common issued DoD reader. Sentinel does not apply this fix
for you yet.

**`RUN CHECKS` may freeze the interface briefly.** It calls `systemctl` and
`pkcs11-tool` synchronously on the event loop. Being made properly asynchronous is on
the roadmap.

**`RUN CHECKS` will not offer to start a missing `pkexec` prompt you cannot see.**
If `pcscd` is stopped and no polkit agent is available, the prompt is invisible and
the tool appears to hang. Start the service manually instead.

## Logs

Writes `sentinel.log` in the current working directory. It contains cardholder
identities and certificate details, so it is not committed to this repository and
should be treated as sensitive.

## Uninstall

```bash
rm -rf ~/.sentinel
# then remove the "alias snl=" line from your shell config
```

To remove the installed DoD roots, delete `DoD_Full_Chain.pem` from your trust-anchor
directory and re-run the trust-store refresh command for your distribution.

## Documentation

| File | Purpose |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Full code review, security findings, and the fix plan |
| [`CRITICAL_ASSESSMENT.md`](CRITICAL_ASSESSMENT.md) | Honest assessment and scoring |
| [`SENTINEL_DOCS.md`](SENTINEL_DOCS.md) | How it works, and troubleshooting |
| [`DEV_HANDOVER.md`](DEV_HANDOVER.md) | Architecture and developer notes |
| `omnissa_fedora_cert_fix.md` | Field notes on Omnissa/OpenSSL/smart-card conflicts |
