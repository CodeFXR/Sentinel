# Sentinel — Technical Documentation

How the tool works, what each part does, and how to debug it. User-facing
documentation is in [`README.md`](README.md).

---

## 1. Architecture

Three modules, about 470 lines total.

```
sentinel.py           257 lines   Textual UI. Widgets, CSS, event wiring. No subprocesses.
sentinel_backend.py   226 lines   All subprocess orchestration. No Textual imports.
sentinel_utils.py      58 lines   StatusLED widget, terminal detection, service probing.
```

The UI never touches a subprocess. The backend never imports Textual. Backend methods
take a `log_writer` callback and an `update_led` callback rather than holding a widget
reference, which keeps the backend testable in isolation.

### Data flow

```
button press  ->  SentinelApp.on_button_pressed
              ->  SentinelBackend.<method>(log_writer, update_led)
              ->  asyncio.create_subprocess_*  ->  system tool  ->  log_writer / update_led
```

Every backend method is `async`. Subprocesses use `asyncio.create_subprocess_exec`
(argument lists) rather than `create_subprocess_shell`, so paths and arguments are
never re-parsed by a shell.

### The two privileged operations

Only two things need root, and both go through `pkexec`:

| Operation | Where |
|---|---|
| `systemctl start pcscd` (only if the service is down) | `check_services` |
| Copy the CA bundle + refresh the trust store | `install_certs` |

Everything else — probing, browser configuration, card scanning — runs as your normal
user.

---

## 2. The three operations in detail

### 2.1 `check_services`

1. `systemctl is-active pcscd`. If not active, tries `pkexec systemctl start pcscd`,
   then re-checks.
2. Checks for `pcsc_scan`, `pkcs11-tool`, and `opensc-tool` in `PATH`. If any are
   missing it prints a warning naming them. **It does not install them.**
3. Runs `pkcs11-tool -L` and looks for the string `Slot` in the output. If found, the
   middleware LED turns green; if the output mentions `piv_II`, `CAC`, or `PIV` it also
   reports a PIV/CAC-compatible token.

**Known issue:** steps 1 and 2 call `subprocess.run` synchronously from inside an
`async def`, which blocks Textual's event loop. On a slow or wedged systemd the
interface freezes until the call returns.

**Known issue:** if `pkcs11-tool` is not installed at all, the middleware LED is never
assigned a state and stays blank rather than showing an error. If no card is inserted,
that LED is set to `loading` and spins indefinitely.

### 2.2 `install_certs`

Copies `DoD_Mega_Chain.pem` to `/etc/pki/ca-trust/source/anchors/DoD_Full_Chain.pem`
and runs `update-ca-trust`, both under a single `pkexec`.

**This path is Fedora/RHEL only.** The trust-anchor directory does not exist on
Debian/Ubuntu/Zorin, and `update-ca-trust` is not the command there. The copy fails,
the error is surfaced, and the LED turns red. Nothing is installed.

**Known issue:** the command is built as a `pkexec sh -c "cp ... && update-ca-trust"`
string. A checkout path containing a single quote breaks the quoting and yields root
command execution. It should be two `create_subprocess_exec` calls
(`pkexec install -m 0644 <src> <dst>`, then `pkexec update-ca-trust`) with no shell.

**Known issue:** `pkexec` has no timeout. With no polkit agent available the prompt is
invisible and `await proc.communicate()` blocks forever.

**Read this before running it.** `DoD_Mega_Chain.pem` holds 197 certificates of which
entries covering 69 unique certificates, of which only 15 are verified self-signed roots.
The other 54 — DoD issuing CAs, WCF intermediates, and cross-certificates — get
installed as trust anchors. See §4.

### 2.3 `configure_browsers`

Collects candidate NSS databases:

- `~/.pki/nssdb` (Chromium / Electron default on Linux)
- `~/.mozilla/firefox/*default*` (native Firefox profiles)
- `~/.var/app/org.mozilla.firefox/.mozilla/firefox/*default*` and the capitalised
  `org.mozilla.Firefox` variant (Flatpak)

For each, runs `modutil -dbdir sql:<path> -list "DoD CAC"`. If the module is absent,
runs `modutil -force -dbdir sql:<path> -add "DoD CAC" -libfile <opensc-pkcs11.so>` with
a 10-second timeout.

**Known issue:** the PKCS#11 module path is hardcoded to `/usr/lib64/opensc-pkcs11.so`.
On Debian/Ubuntu/Zorin that is
`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`, so the function returns at the
existence check having configured nothing.

**Known issue:** Firefox rewrites `prefs.json` on exit. Adding a module while Firefox
is running is silently discarded. Nothing detects or warns about this.

**Known issue:** the "Browser configuration complete" message and the green LED are
emitted unconditionally after the loop, even if every database failed.

**Known issue:** `modutil -add` registers the module but no certificates are imported
into the NSS database, so the device can appear with nothing usable in it.

### 2.4 Card scanning

Spawns `pcsc_scan`, reads stdout line by line, strips ANSI escape sequences, and
filters to lines that look like reader/card events before writing them to the log.
Card insert and removal flip the hardware LED and write to the syslog.

**Known issue:** the filter is a hardcoded list of string prefixes
(`Reader`, `Event`, `Card`, `ATR`, `Scanning`, `Using`) plus two regexes. Most real
`pcsc_scan` output does not match and is discarded, so the Scan tab is largely empty.
The right fix is to pass the stream through with a rate limit rather than guess at
another program's output format.

**Known issue:** the subprocess is started with `create_subprocess_shell` using a path
from `shutil.which`, and `terminate()` on an already-exited process raises an
unhandled `ProcessLookupError`.

---

## 3. The certificate bundle

`DoD_Mega_Chain.pem` is generated from three official DoD PKCS#7 bundles plus the
externally-approved PKI set, using `tools/create_mega_chain.py`. That script is
maintenance-only — run it by hand when DoD publishes a new version, then commit the
regenerated file.

It verifies every input against the SHA-256 manifest that ships inside each bundle's
`.sha256` file before parsing anything, and aborts the whole build if any digest
fails. Two details make that verification non-obvious:

- The `.sha256` files are **binary containers** with the manifest embedded as ASCII,
  not plain text. `sha256sum -c` on them directly does not work.
- Digest case is inconsistent: lowercase in the v5.12 ECA bundle, **uppercase** in the
  v5.17 WCF and v5.6 DoD bundles. A lowercase-only pattern silently matches nothing in
  two of the three bundles.

All 17 manifest-covered files currently verify clean.

**Composition problems, unfixed:**

| Property | Value |
|---|---|
| Total entries | 197 |
| Unique certificates | 69 (128 are duplicates) |
| Verified self-signed roots | 15 |
| **Not self-signed (unique)** | **54** |
| File size | 355 KB |

Only the 15 self-signed roots belong in a trust-anchor directory. The other 54 unique ones are
intermediates, cross-certificates, and material from the
`DoD_Approved_External_PKIs_Trust_Chains_v11.4/` set — which includes the Australian
Defence Organisation, the Netherlands Ministry of Defence, the US State Department and
Treasury, and commercial SSP chains (DigiCert, Entrust, Verizon, IdenTrust). Installing
those as roots on a DoD workstation grants a much broader trust surface than intended.
Rebuilding the bundle roots-only is on the roadmap.

---

## 4. Troubleshooting

### `pcscd` is not detected

```bash
systemctl status pcscd
sudo systemctl enable --now pcscd
```

The tool attempts this itself via `pkexec` but cannot show you the polkit prompt from
inside a TUI. Start it manually.

### "No PKCS#11 slots found"

The daemon is up but no card. Check the reader is inserted before starting the tool,
then:

```bash
pcsc_scan          # should list a reader
opensc-tool --list-readers
```

### Reader hangs for ~26 seconds on card insert

Broadcom 58200 firmware bug. OpenSC's `setcos` driver probe sends APDU
`00 CA DF 30 05`, which this reader's firmware cannot handle. Fix in
`/etc/opensc.conf`:

```
card_drivers = piv-II, cac, cac1
```

Reduces first-insert latency from ~28s to ~0.2s. Full analysis in
`omnissa_fedora_cert_fix.md`. Sentinel does not apply this automatically.

### Browser still does not offer the CAC

In order: close Firefox before running `CONFIG BROWSERS`; confirm the module landed
with `modutil -dbdir sql:~/.mozilla/firefox/<profile> -list`; confirm
`modutil -dbdir sql:~/.pki/nssdb -list`; check the `DoD CAC` module is enabled in
Firefox's Certificate Manager under *Authentication Decisions* / *Modules*.

### `INSTALL CERTS` fails on Debian/Ubuntu/Zorin

Expected. The trust-anchor path and refresh command are hardcoded for Fedora. Manual
equivalent on Debian/Ubuntu:

```bash
sudo cp DoD_Mega_Chain.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

Read §3 first — you are about to install 54 non-root certificates as trust anchors.

### `No module named textual`

The setup script reported success but the virtual environment was never created or
populated. `python3 -m venv` needs the `python3-venv` package on Debian/Ubuntu/Zorin,
and the script does not check for it. Recreate manually:

```bash
sudo apt install python3-venv      # Debian/Ubuntu/Zorin
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

### Interface freezes during `RUN CHECKS`

Known. `systemctl` and `pkcs11-tool` are called synchronously on the event loop. Wait
it out, or run the commands manually in another terminal.

---

## 5. What was removed in v2.0.0

Deleted, with the reason:

| Removed | Why |
|---|---|
| Certificate validation | Reported `OCSP/CRL Check: PASSED` without performing any revocation check, and built its trust store from a certificate downloaded over plaintext HTTP from a URL inside the on-card AIA extension — so an on-path attacker controlled the verdict. |
| PIN management | The PIN **and the PUK** were passed as command-line arguments, readable by any local user via `ps aux`. Previous documentation claimed this had been fixed. It had not. |
| SSH integration | Exported the PIV public key into `~/.ssh/authorized_keys`, which grants inbound SSH to the machine to anyone holding the card. |
| PDF signing | Worked in principle; required `pyhanko`, `cryptography`, and `python-pkcs11` for a peripheral feature. |
| STIG auditing | 10 checks, of which 6 used Fedora/RHEL-only paths and 2 tested for `sssd` and `authselect` that a desktop user will never have. |
| SCAP report | `rpm`-only, wrote a system inventory to `$HOME` with default permissions. |

`pyhanko`, `cryptography`, and `python-pkcs11` were dropped from `requirements.txt`.
`pyhanko-certvalidator` was never declared and was imported but unused.
