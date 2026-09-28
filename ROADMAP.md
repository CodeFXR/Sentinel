# Sentinel — Code Review & Fix Roadmap

**Review date:** 2026-09-28
**Reviewed tree:** `/home/jvm/projects/sentinel` (~1,380 LOC across 5 Python files + 1 installer)
**Headline:** Sentinel is a Fedora/RHEL tool wearing a "Debian/Ubuntu compatible" label. Every privileged
path in the codebase is hardcoded to Fedora. It fails on Zorin OS by construction, not by bug.

---

## 0. TL;DR — Why it failed on Zorin OS

Zorin OS is Ubuntu-based. Sentinel contains **zero** Debian/Ubuntu code paths. `distro` is imported
(`sentinel.py:2`) and used for exactly two `write_line` calls (`sentinel.py:221,226`) — it is never
branched on anywhere in the backend. Six independent Fedora-only assumptions each cause a hard failure:

| # | Fedora-only assumption | Location | Zorin result |
|---|---|---|---|
| 1 | Installer requires pre-existing `git` + `python3`, no install path | `install:71-79` | `exit 1` — "Git is not installed." No remediation offered |
| 2 | `python3 -m venv` assumed to work | `install:108` | Fails — Debian/Ubuntu split `ensurepip` into `python3-venv`, not installed by default |
| 3 | Trust store = `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust` | `sentinel_backend.py:111,119,442` | `cp` fails → no DoD certs installed |
| 4 | PKCS#11 module = `/usr/lib64/opensc-pkcs11.so` | `sentinel_backend.py:150,352,377` | Path does not exist (Ubuntu: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`) → browser config aborts at the guard, nothing configured |
| 5 | Package manager = `dnf` / `rpm` | `sentinel_backend.py:63,437`, `sentinel_stig.py:211-241` | Suggests `dnf` to a Zorin user; every `rpm -q` check silently returns "not found" |
| 6 | `/usr/lib64/engines-3/`, `/usr/lib64/libpcsclite.so.1` | `sentinel_stig.py:206,238` | All STIG checks fail permanently |

**Corroborating evidence:** `sentinel.log` contains 8 months of runs, every single one on
`Fedora Linux 43` or `Fedora Linux 44`. There is not one Zorin/Ubuntu/Debian entry. The tool has never
been run successfully on anything but the maintainer's machine.

**Second-order failure:** even if the installer completed, `sentinel` would start and every LED would
read error/idle, because the "missing packages" path is a *log line of advice*, not an action. There is
no `install_packages()` function anywhere in the codebase. For a tool whose stated mission is
"autoconfig my CAC," installing `opensc`/`pcscd`/`nss-tools` **is** the autoconfig, and it is not
implemented. This is the single largest scope gap in the project.

---

## 1. Security Findings

Ordered by severity. **S1 and S2 must be fixed before this tool touches another machine.**

### S1 — CRITICAL: PIN and PUK passed as command-line arguments
> **Closed by Phase 0.4 — delete PIN management.** Do not fix; remove the code.
`sentinel_backend.py:271` and `sentinel_backend.py:291`

```python
cmd = ["pkcs15-tool", "--change-pin", "--auth-id", "01", "--pin", current, "--new-pin", new]
cmd = ["pkcs15-tool", "--unblock-pin", "--auth-id", "01", "--puk", puk, "--new-pin", new]
```

Any local user on the box reads these with `ps aux` for the process lifetime. **The PUK is worse than
the PIN** — possession of the PUK plus any value permanently unblocks a locked card.

This is a direct regression against the project's own security posture. `SESSION_WORK_LOG.md:18-23`
and `DEV_HANDOVER.md:60-62` both explicitly claim "PINs are passed exclusively via Environment
Variables… never appear in command-line arguments or process lists." That claim is **false**; these
two call sites were missed during the hardening pass. It also violates the workspace's own mandatory
Pipeline Hygiene Rule 2 (`AGENTS.md`).

**Fix:** both `pkcs15-tool` invocations must read the secret from `OPENSC_PIN` / `OPENSC_PUK` in a
sanitized `env`, and `--pin`/`--puk`/`--new-pin` must be dropped from `argv`. Because this module is
being deleted entirely (see §4), deletion is the fix.

### S2 — CRITICAL: "Certificate validation" fetches trust material over unauthenticated HTTP
> **Closed by Phase 0.5 — delete cert validation.** Do not fix; remove the code.
`sentinel_backend.py:585-592, 603-650, 672-677`

The AIA URL is read out of the on-card certificate and the scheme regex **explicitly permits plaintext**:

```python
aia_match = re.search(r"CA Issuers - URI:(http[s]?://[^\s\n]+)", cert_details)   # line 585
if not aia_match:
    aia_match = re.search(r"URI:(http[s]?://[^\s\n]+)", cert_details)            # line 587
...
dl_cmd = [curl_path, "-s", "-L", "-o", temp_aia, aia_url]                       # line 609
```

The real DoD AIA extension is `http://crl.disa.mil/sign/DODIDCA_71.cer` — **HTTP, not HTTPS** (visible
in `sentinel.log`). The downloaded bytes are then appended to `working_chain.pem`, which is passed as
`-CAfile` to `openssl verify` (line 674). Therefore:

> An attacker on the path can inject an arbitrary certificate into the trust file, and Sentinel will
> print `SUCCESS: Certificate chain is valid.`

A validation function whose verdict an on-path attacker controls is not a validation function. It is
worse than no validation, because it manufactures false assurance.

Aggravating factors: `curl` has no `--max-time` (infinite hang on a hostile/blackholed endpoint), no
`--max-filesize` (unbounded disk write), and inherits the `env` containing `OPENSC_PIN` for no reason
(line 613).

### S3 — HIGH: Revocation is reported as PASSED without ever being checked
> **Closed by Phase 0.5 — delete cert validation.** This is the most serious line in the file; deletion removes it.
`sentinel_backend.py:689`

```python
if "OK" in verify_out:
    log_writer("SUCCESS: Certificate chain is valid.")
    update_led("led-identity", "success")
    self.logger.info(f"Certificate Validated for {final_upn}")
    log_writer("OCSP/CRL Check: PASSED")
```

`openssl verify` performs **no** OCSP and **no** CRL checking. Nothing in this code path contacts
`ocsp.disa.mil` or any CRL distribution point. The line `OCSP/CRL Check: PASSED` is a hardcoded string
literal that fires unconditionally on any successful chain build.

A soldier reads that line, sees green, and concludes their card is not revoked. This is the most
dangerous single line in the codebase because it is a false statement about a security property, and
it is what the whole feature is trusted for. `README.md:30` compounds it by advertising
"Authenticated Fetching: Supports CAC PIN entry for fetching certs in restricted network environments."

### S4 — HIGH: `-partial_chain` + mega-chain = the validation is near-vacuous
> **Closed by Phase 0.5 — delete cert validation.**
`sentinel_backend.py:672-677`

```python
verify_cmd = [openssl_path, "verify",
              "-CAfile", working_chain,       # 200+ roots AND intermediates
              "-untrusted", working_chain,    # the same file again
              "-partial_chain", temp_pem]
```

Three compounding problems:
1. `-partial_chain` instructs OpenSSL to treat **non-self-signed** certificates in the CAfile as trust
   anchors. `DoD_Mega_Chain.pem` contains ~150 intermediates. Every one of them becomes a root.
2. The AIA-fetched intermediate is written into the same file (line 630-642), so the fetched cert is
   promoted to its own trust anchor — it validates itself.
3. The identical file is passed as both CAfile and `-untrusted`.

The result passes for a very large set of chains, including many that should not pass. A "valid"
result from this code carries almost no information.

### S5 — HIGH: The mega-chain over-trusts the system trust store
`sentinel_backend.py:111-119`, `create_mega_chain.py`

`DoD_Mega_Chain.pem` is written as a single `.pem` into the **trust anchors** directory, and
`update-ca-trust` / `update-ca-certificates` ingests **every** certificate in that file as a root.

**Measured composition (197 entries, 69 unique certificates):**

| | Count |
|---|:---:|
| Unique certificates | 69 |
| Verified self-signed (true trust anchors) | 15 |
| **NOT self-signed — installed as anchors anyway** | **54** |
| Duplicate entries | 128 |

> **Correction to the original review (2026-09-28):** an earlier draft of this finding claimed the
> bundle included foreign government and commercial SSP roots (Australian Defence Organisation,
> Netherlands Ministry of Defence, US State Department, US Treasury, DigiCert, Entrust, Verizon,
> IdenTrust). **That was wrong.** Those `.cer` files live in
> `DoD_Approved_External_PKIs_Trust_Chains_v11.4/`, which `create_mega_chain.py` never reads — it only
> walks for `*.p7b`, and that directory contains no `.p7b` files. Every certificate in the bundle has
> `O = U.S. Government`. The system trust bundle contains zero ADO/Netherlands/State/Treasury certs
> from this source. The finding stands on the self-signed ratio, not on foreign roots.

The real problem is the 54 non-self-signed certificates — DoD ID/EMAIL/SW/DERILITY issuing CAs, WCF
intermediates, and cross-certificates — being promoted to trust anchors. A trust-anchor directory must
contain only self-signed roots. As written, a compromised, retired, or re-keyed issuing CA that should
be reachable only through a chain can also be treated as a root of trust, and old root generations
(DoD Root CA 2/3/4) that have been superseded remain active.

Supporting problems, all real:
- `AGENTS.md:26` notes the `.sha256` verification files ship alongside every bundle
  (`Certificates_PKCS7_v5.17_WCF.sha256`, etc.) and `create_mega_chain.py` **never checked a single
  one**. *Now fixed* — `tools/create_mega_chain.py` verifies all three bundles and aborts on mismatch;
  all 17 manifest-covered files verify clean. The manifests are binary containers with the manifest
  embedded as ASCII, and digest case is inconsistent (lowercase in the v5.12 ECA bundle, uppercase in
  the v5.17 and v5.6 bundles), which is likely why nobody wired this up originally.
- 128 of 197 entries are duplicates of the same 69 certificates.
- No expiry filtering and no self-check of the assembled chain.


### S6 — MEDIUM: Predictable filenames in world-writable `/tmp`
`sentinel_backend.py:597, 606, 657, 658`

```python
working_chain = "/tmp/sentinel_working_chain.pem"
temp_aia      = "/tmp/sentinel_aia_temp.dat"
temp_der      = "/tmp/sentinel_cert.der"
temp_pem      = "/tmp/sentinel_cert.pem"
```

Fixed, guessable paths in sticky-bit `/tmp`, opened with `open(..., "w"/"ab")`. A local attacker
pre-creates any of these as a symlink and the victim process writes through it to an arbitrary path it
has permission to write — and if Sentinel is ever run as root, that is arbitrary root file overwrite.
Two concurrent Sentinel runs also corrupt each other's state.

Cleanup is also unreliable: the removals at lines 701-704 sit outside the `try` but inside a branch, so
an exception anywhere in lines 656-700 leaks all four files, and `os.remove` on a symlink the attacker
swapped in deletes the attacker's file instead.

**Fix:** `tempfile.TemporaryDirectory()` / `NamedTemporaryFile(delete=False)`, or better, drop
`/tmp` entirely (this code is being deleted).

### S7 — MEDIUM: `pkexec sh -c` with interpolated paths
`sentinel_backend.py:119`

```python
cmd = f'pkexec sh -c "cp \'{chain_file}\' \'{target_file}\' && update-ca-trust"'
```

`create_subprocess_shell` → `sh -c` → `pkexec` (root) → `sh -c`. Four levels of nesting, and
`chain_file` is derived from `__file__`. A clone path containing a single quote breaks out of the
quoting and yields **root command execution**. This also violates Pipeline Hygiene Rule 1
(`AGENTS.md`): never `shell=True` for anything handling paths.

**Fix:** `pkexec install -m 0644 <src> <dst>` and `pkexec update-ca-trust` as two `exec` calls, or one
`pkexec /usr/bin/install …` — no shell at any level.

### S8 — MEDIUM: SSH key export appends to `authorized_keys` (authorization escalation)
> **Closed by Phase 0.3 — delete SSH integration.**
`sentinel_backend.py:333-343`

```python
key_file = os.path.join(ssh_dir, "id_rsa_cac.pub")
auth_file = os.path.join(ssh_dir, "authorized_keys")
with open(auth_file, "a") as f:
    f.write(f"\n# Added by Sentinel\n{pub_key}\n")
```

`authorized_keys` governs **inbound** SSH logins *to this host*. `README.md:22` markets this as
"Automates extraction of the PIV Authentication public key to `~/.ssh/authorized_keys`." The effect is
that anyone holding the corresponding private key (i.e. anyone with the physical card) can now SSH
into this machine as this user. That is an authorization grant, not a convenience feature. It is also
appended unconditionally with no deduplication, so repeated runs grow the file.

**Fix:** delete the module (see §4). If ever restored, write only the `.pub` file and never touch
`authorized_keys`.

### S9 — MEDIUM: Unconditional silent `set -e` bypass in the installer
`install:93, 108, 118`

```bash
git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR" > /dev/null 2>&1 &
spinner $!
echo -e " Done"
```

Every heavy step is backgrounded with `&` and has its output sent to `/dev/null`, then the script
prints ` Done` **unconditionally**. Background job failures are not caught by `set -e`, so a failed
clone, a failed `venv`, or a failed `pip install` all print "Done" and the installer continues. The
user is told the install worked; `sentinel` then dies on `import textual`.

This is the mechanism that turns a missing `python3-venv` (fatal on every Debian/Ubuntu/Zorin system)
into a silent, confusing failure instead of a clear error.

### S10 — LOW/MEDIUM: Unpinned dependencies, undeclared transitive import
`requirements.txt`, `sentinel_pdf_signer.py:9`

```
textual>=0.27.0     # no upper bound
distro
pyhanko
cryptography
python-pkcs11
```

- Zero version pins except a lower bound on Textual. Textual's widget API (`Static.label`,
  `set_interval`, `TabbedContent`) has broken across majors. The installer self-updates from GitHub
  and pulls whatever PyPI serves, so installs are not reproducible.
- `sentinel_pdf_signer.py:9` does `from pyhanko_certvalidator import ValidationContext`.
  `pyhanko-certvalidator` is **not** in `requirements.txt` — it only resolves as a transitive
  dependency of `pyhanko`, and the import is **never used**. If pyHanko ever stops vendoring it, the
  signer dies at import time.
- `python-pkcs11` and `cryptography` are pulled in for a feature (PDF signing) being removed.

### S11 — LOW: Committed PII and build artifacts
`sentinel.log`, `.venv/`, `__pycache__/`

`sentinel.log` is checked in and contains **67 occurrences** of a real service member's identity
(a real service member's name and EDIPIN) plus DoD CA-71 certificate serial numbers and full `pkcs11-tool -O`
dumps. `.venv/` (with `cpython-314` bytecode) and `__pycache__/` are also in the tree. This violates
Pipeline Hygiene Rule 5 (`AGENTS.md`) and, more seriously, publishes a service member's EDIPIN-linked
name in a public repository. **Treat as a disclosure incident: purge from history, rotate nothing but
confirm the repo was not public.**

### S12 — LOW: Log injection / markup injection
`sentinel_backend.py:695, 409`

```python
self.logger.warning(f"Validation FAILED. Details: {verify_err}")   # line 695 — OpenSSL stderr
log_writer(output)                                                 # line 409 — child stdout
```

Untrusted strings (attacker-influenced AIA responses, PDF filenames, certificate subjects/CNs) are
written to both `logging` and a Textual `Log` widget. `Log.write_line` interprets `[...]` markup, so a
crafted value renders as formatting; embedded newlines forge log lines in `sentinel.log`.

**Fix:** `log_writer(escape(value))` or `Log.write_line(..., markup=False)`.

### S13 — LOW: Unbounded, world-readable log with a default umask
`sentinel.py:131`, `sentinel_backend.py:422-425`

`logging.FileHandler("sentinel.log")` is **CWD-relative** and never rotates. `sentinel.log` already
carries 44 KB of identity data after 8 months of development use; on a daily-use fleet machine it grows
without bound and retains PII indefinitely. `generate_scap_report` writes a full system inventory to
`~/sentinel_scap_report.txt` with default 0644 permissions.

**Fix:** `RotatingFileHandler(maxBytes=1_000_000, backupCount=3)`, resolve the path against
`Path(__file__).parent`, and `os.umask(0o077)` before writing the report.

---

## 2. Correctness / Bug Findings

### B1 — `update_led` called with the wrong arity (guaranteed crash on one branch)
`sentinel_backend.py:707`

```python
update_led("led-identity").status = "loading"
```

`update_led` **is** `SentinelApp.update_led(self, led_id, status)` (`sentinel.py:275-276`). Calling it
with one argument raises `TypeError`, which is caught by the outer handler at line 714 and surfaced as
`Execution Error: missing 1 required positional argument: 'status'`. The "trust chain not found" branch
can never report its own state correctly. Every other call site in the file uses the two-argument form.

### B2 — The UPN extraction regex has never matched anything
`sentinel_backend.py:544`

```python
san_match = re.search(r"othername:UPN<([^>]+)>", cert_text)
```

OpenSSL does not print `othername:UPN<...>`. The actual output, captured in your own `sentinel.log`
(identity redacted), is:

```
X509v3 Subject Alternative Name:
    othername: 2.16.840.1.101.3.6.6:<unsupported>, othername: UPN:<REDACTED>@mil, URI:urn:uuid:<REDACTED>
```

The pattern expects no space and angle brackets; the real format is `othername: UPN:` followed by the
value. **This match has never succeeded and never will.** The code silently falls through to the CN
branch, which is why every log entry reads `Identity Mapped: <NAME>.<EDIPIN> (CN)` — including the runs
labelled as successful validation.

The user-visible consequence is serious: the sidebar shows a Common Name where the UI promises
"Identity Mapping → User Principal Name," and no local-user mapping ever occurs. Fix:
`re.search(r"othername:\s*UPN:([^\s,\]]+)", cert_text)`.

### B3 — `re.DOTALL` makes the PIN-status dump useless
`sentinel_backend.py:249-251`

```python
pin_blocks = re.findall(r"(Auth object.*?Flags:[^\n]*)", output, re.DOTALL)
clean_block = re.sub(r'\n\s+', ' ', block)
log_writer(f"- {clean_block[:100]}...")
```

With `re.DOTALL`, `.` matches newlines, so `Auth object` on the first object bleeds all the way to the
**last** `Flags:` line in the output. The result is one 100-character truncated blob, not per-object
status. Remove the `re.DOTALL` flag. Separately, `tries left: (\d+)` (line 255) misses pkcs15-tool's
actual `PIN tries left:` format on older versions, and `--dump` is invoked with no PIN so a locked card
yields nothing — the user cannot distinguish "wrong PIN" from "no card."

### B4 — Browser config writes to a running Firefox and reports success unconditionally
`sentinel_backend.py:186-229`

- Firefox rewrites `prefs.json` on exit, so a `modutil -add` performed while Firefox is running is
  **silently discarded**. Nothing in the code detects or warns about this. The user is told it worked.
- `modutil -add` registers the module but never imports the DoD certificates via `certutil -A`, and
  never sets cert order — so the device appears in Firefox with no usable certs.
- `log_writer("Browser configuration complete...")` and `update_led("led-browsers", "success")` at
  lines 228-229 run **unconditionally**, even if every database in the loop failed. A fully failed
  operation reports success and a green LED.
- Profile matching uses `"default" in item` (line 166) with no `cert9.db` check, so any unrelated
  subdirectory containing that substring is added to the work list.

### B5 — LEDs never resolve when the middleware is absent (the Zorin symptom)
`sentinel_backend.py:71-95`

```python
p11_path = shutil.which("pkcs11-tool")
if p11_path:
    ... update_led("led-opensc", ...)          # all LED updates are inside the guard
```

There is **no `else` branch.** On a machine without OpenSC — precisely the Zorin case — `led-opensc`
is never assigned and stays permanently `idle`. Line 90 has the mirror problem: when no card is
inserted, the LED is set to `"loading"` and left there, spinning forever next to a warning that says
"Card missing?" Both make the dashboard lie about state.

### B6 — Blocking `subprocess` inside async functions freezes the TUI
`sentinel_utils.py:18-23`, called from `sentinel_backend.py:28, 58, 431`

```python
class LinuxStrategy:
    def is_service_running(self, service="pcscd"):
        result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
```

`check_services` is `async`, but its very first action is a **synchronous** `subprocess.run` on the
event loop thread. On a slow or hung systemd that blocks the entire Textual event loop — no repaint, no
input, no Ctrl+C. `generate_scap_report` compounds it with three `subprocess.getoutput("rpm -qa | grep …")`
calls (line 437), each of which can take seconds.

The `await asyncio.sleep(...)` calls scattered through the backend (lines 27, 192, 758) are
band-aids over this. They add 0.5–1.5 s of pure latency and mask the real problem. Delete the sleeps
and make the subprocesses actually async.

### B7 — `pkexec` with no timeout hangs the TUI indefinitely
`sentinel_backend.py:36-41, 121-126`

`pkexec` prompts via polkit. Inside a TUI with no controlling terminal or agent, that prompt is
unrenderable and invisible. `await proc.communicate()` has no `timeout=`, so the app deadlocks with no
error and no way out but killing the process externally. `configure_browsers` does use
`asyncio.wait_for` (lines 199, 210) — so the correct pattern is already in the file, just not applied
to the privileged calls.

### B8 — `pcsc_scan` output filter discards nearly everything
`sentinel.py:335-341`

```python
valid_prefixes = ["Reader", "Event", "Card", "ATR", "Scanning", "Using"]
is_date = re.match(r'^[A-Z][a-z]{2} [A-Z][a-z]{2} \d+', line)
is_device_line = re.match(r'^\d+: .*', line)
if not (is_date or is_known_prefix or is_device_line):
    continue
```

Real `pcsc_scan` output does not match these shapes. Typical lines
(`00:00:00:00 0100000000 reader-0 00 00:00:00:00  CCID event 0 [1]`, `Card detected: …`,
`Using T=0 protocol …`, `piv_II: Reading …`) are dropped. Hardcoded string allowlists against another
program's human-readable output are unmaintainable by construction. The Scan tab is largely empty as a
result. Pass the stream through with a rate limit instead.

### B9 — GUI-state bugs in the scan lifecycle
`sentinel.py:284-292, 305-308, 317-319`

- `self.scan_process.terminate()` on line 285 raises `ProcessLookupError` if the process already exited; it is unhandled and prints a traceback into the TUI.
- `create_subprocess_shell(cmd_path)` where `cmd_path` came from `shutil.which` — a shell with a PATH-derived string, violating Hygiene Rule 1. Use `create_subprocess_exec`.
- The ANSI-stripping regex is recompiled on **every line** of output (line 319). Hoist to a module constant.
- `log_widget.write_line(...)` and `self.query_one(...)` are called directly from a bare `asyncio.Task` created outside Textual's worker/refresh discipline, racing with screen teardown.

### B10 — Minor code-quality defects
- `sentinel.py:298` and `sentinel.py:335` — f-strings with no placeholders.
- `sentinel_utils.py:23` — bare `except:` swallows `KeyboardInterrupt`/`SystemExit`.
- `sentinel.py:126-141` — `setup_logging` re-adds handlers on every construction with no dedup and no `propagate = False`.
- `sentinel_pdf_signer.py:9` — dead import of `ValidationContext`.
- `test_sentinel.sh` is a 2-line file (`source ~/.bash_profile`). **There are zero tests**, including for `install_certs` — the single most privileged operation in the codebase.

---

## 3. Code Quality — Shorter, Cleaner, Faster

The architecture is sound (UI / backend / helpers cleanly separated, async throughout, `create_subprocess_exec`
used in most places). The problems are concentrated in three patterns.

### 3.1 The 45-line `if/elif` button dispatcher — `sentinel.py:228-273`
Twelve branches, each re-querying widgets and re-packing arguments. Replace with a dispatch table and
Textual `Action`s:

```python
BINDINGS = [("c", "checks"), ("i", "install_certs"), ("b", "browsers"), ("s", "scan"), ("q", "quit")]

async def action_checks(self): await self.backend.run_checks()
async def action_install_certs(self): await self.backend.install_certs()
```

Buttons get `id` → `Action` bindings or a `{btn_id: coroutine}` map. ~70 lines → ~20, and the actions
become keyboard-reachable (the app currently has **no key bindings at all**; `SENTINEL_DOCS.md:76-81`
advertises "Keyboard Navigation" for a TUI that requires the mouse).

### 3.2 The triple-callback signature duplicated 10 times
Every backend method is `async def f(self, log_writer, update_led, update_label=None, ...)`. This is the
single largest source of boilerplate and the reason the backend is coupled to a UI abstraction it doesn't
understand. Collapse to one event sink:

```python
def emit(self, kind, payload): ...   # "log" | "led" | "label"
```

or better, have methods **return** a list of `(level, message)` tuples and let the UI render them. This
removes ~30 callback parameters, makes the backend unit-testable without Textual, and turns the
`update_led("led-identity")` arity bug (B1) into a compile error instead of a runtime `TypeError`.

### 3.3 Fake strategy pattern and fake progress
`sentinel_utils.py:25-26`

```python
def get_strategy():
    return LinuxStrategy()
```

A factory with exactly one implementation, one platform. This is YAGNI — collapse `LinuxStrategy` into
two module-level `async def` functions (`service_is_active(name)`, `have(binary)`) and delete the
factory. Also rename `check_installed` → `have`: it checks `shutil.which` (a binary in `PATH`), which has
nothing to do with package installation.

Delete all `asyncio.sleep()` calls at `sentinel_backend.py:27, 192, 758` — they add latency and exist only
to disguise B6. Once the subprocesses are genuinely async, the UI updates from real completions.

### 3.4 The `pcsc_scan` monitor — 40 lines to filter a stream
`sentinel.py:317-353`. See B8. A `for line in proc.stdout` loop with a module-level ANSI constant is
~10 lines and shows more information.

### 3.5 Unbounded LED timers
`sentinel_utils.py:37-38` runs `set_interval(0.1, self.update_frame)` on **all 8** LEDs from mount, for
the life of the app — 80 callbacks/sec doing nothing for the 7 that are not "loading." Register the
interval lazily on the `loading` transition and cancel it on exit.

### 3.6 `create_mega_chain.py` — verify what you build
Unpinned, unverified, walks the **current directory** recursively (it will happily ingest `.p7b` files
from `.venv/` or anywhere else if invoked from the wrong CWD), never checks the `.sha256` files that
ship with every bundle, and writes output to the CWD. Since the DoD bundles are already in the repo and
`DoD_Mega_Chain.pem` is a committed 355 KB artifact, the generator is a maintenance-only script: move it
to `tools/`, make it verify checksums, output to an explicit path, and skip expired certs.

---

## 4. Scope Reduction (requested)

The request is to remove **cert validation, SSH, PDF signing, PIN management, and STIGs**. This is the
correct call. Those five features are ~55% of the backend, 100% of the security findings S1–S4 and S8,
and most of the distro-lock-in that caused the Zorin failure.

> **This is Phase 0 of the roadmap — it goes first, before any bug fix.** See §5.0 for the sequencing
> argument and the one guardrail that has to be in place before you start deleting.

**Estimated deletion:** ~400 of ~1,380 lines, plus `pyhanko`, `cryptography`, `python-pkcs11` from
`requirements.txt` (faster, lighter install), and `sentinel_stig.py` (241 lines) deleted outright.

| Action | Files / lines | Removes |
|---|---|---|
| Drop cert validation tab + `validate_cert` | `sentinel.py:175-180, 233-240`; `sentinel_backend.py:454-717` (264 lines) | S2, S3, S4, S12; B1, B2 |
| Drop SSH tab + methods | `sentinel.py:182-186, 246-250`; `sentinel_backend.py:305-364` (60 lines) | S8 |
| Drop PDF signing | `sentinel.py:188-193, 252-256`; `sentinel_backend.py:366-418` (53 lines); delete `sentinel_pdf_signer.py` (103 lines) | S10, 3 heavy pip deps |
| Drop PIN management | `sentinel.py:195-209, 258-268`; `sentinel_backend.py:231-303` (73 lines) | **S1 (PIN/PUK in argv)** |
| Drop STIG tab, LED, SCAP report | `sentinel.py:155, 211-215, 270-273`; `sentinel_backend.py:420-452, 719-772`; delete `sentinel_stig.py` (241 lines) | 6 `create_subprocess_shell` sites, all `rpm` calls, B6, B10 |
| Drop SCAP report | `sentinel_backend.py:420-452` | S13 (0644 inventory file) |

**Resulting app:** 3 tabs (Config / Scan / Log), ~600 lines, 2 hard dependencies (`textual`, `distro`).
Its entire job becomes the thing it should have done all along:

> install `pcscd` + `opensc` + `nss-tools` → enable the service → install DoD root CAs to the correct
> per-distro trust store → register the PKCS#11 module in every browser NSS DB → confirm the card is
> readable → done.

**Reconsideration on STIG removal:** the one check with real user value is screen-lock-on-card-removal
(`sentinel_stig.py:121-140`, GNOME `removal-action`). `DEV_HANDOVER.md:80` already has it on the roadmap
as a one-click action. Consider keeping **that single check** as a plain "Lock screen on card removal"
toggle, and dropping the other nine plus the SCAP/RHEL framing entirely. Your call — the roadmap below
assumes full removal.

---

## 5. Roadmap

**Sequencing principle: delete first, then fix.** The five features being removed contain 9 of the 13
security findings, every one of the confirmed correctness bugs that users actually hit, and most of the
Fedora hardcoding. Deleting them is not "cleanup before the real work" — for those findings, deletion
*is* the fix, and it is the cheapest possible one. Every P1 item that touches removed code should be
deleted from the backlog, not scheduled.

### 5.0 Phase 0 — Cut (do this before anything else)

**Guardrail, non-negotiable:** `sentinel/` is **not a git repository** (`git status` →
`fatal: not a git repository`). You have no revert. Run `git init && git add -A && git commit -m
"pre-cut baseline v1.0.0"` and tag it `pre-cut` **before** touching a line. Two reasons: the cut
should be one reviewable revertible diff, and the Fedora install that currently works is your only
regression check — if Phase 1 breaks it, you need a way back.

Then execute §4 top to bottom:

| Step | Action | Deletes |
|---|---|---|
| 0.1 | `sentinel_stig.py` (241 lines) + `run_stig_scan` (`sentinel_backend.py:719-772`) + `generate_scap_report` (`:420-452`) + the STIG tab (`sentinel.py:211-215`) and `led-stig` sidebar entry (`:155`) | 6 `create_subprocess_shell` sites, all `rpm` calls, 5 more Fedora hardcodes |
| 0.2 | `sentinel_pdf_signer.py` (103 lines) + `sign_pdf` (`:366-418`) + PDF tab (`sentinel.py:188-193`) | 3 heavy pip deps |
| 0.3 | `export_ssh_key` / `setup_ssh_agent` (`:305-364`) + SSH tab (`sentinel.py:182-186`) | **S8** (authorized_keys escalation) |
| 0.4 | `check_pin_status` / `change_pin` / `unblock_pin` (`:231-303`) + PIN Mgmt tab (`sentinel.py:195-209`) | **S1** (PIN/PUK in `argv`) |
| 0.5 | `validate_cert` (`:454-717`, 264 lines) + Cert Validation tab (`sentinel.py:175-180,233-240`) + `led-identity` (`:158-159`) | **S2, S3, S4**, B1, B2, S12 |
| 0.6 | Prune `requirements.txt` to `textual`, `distro`. Delete `create_mega_chain.py` or move to `tools/` (§3.6). | 3 deps, unverified-cert generator |
| 0.7 | Rewrite `README.md`, `SENTINEL_DOCS.md`, `DEV_HANDOVER.md` to describe the 3-tab tool that now exists. Delete the "Gold Master" framing. | 9 false claims |

**Guard against scope creep in the other direction:** after 0.7 the tool has 3 tabs (Config / Scan /
Log) and 2 dependencies. That is the whole product. Resist adding anything back until Phase 1 ships
on a second distribution.

**Exit criterion:** ~600 lines, no `pkcs15-tool`, no `openssl x509 -text`, no `pyhanko`, no `rpm`, no
`sh -c` under `pkexec`. S1, S2, S3, S4, S8 and B1/B2/B3 are closed **by deletion** and drop out of the
backlog below.

---

### P0 — Make it run anywhere (blocks all testing)

> Nothing else matters until Sentinel launches and completes a config on a non-Fedora box.

| # | Task | File:line |
|---|---|---|
| P0.1 | **Stop auto-updating on launch.** The self-update block at `install:4-17` runs `git fetch` on *every* `snl` invocation, before `set -e`, before any prerequisite check, and can `exec` itself in a loop. Delete it; add an explicit `sentinel --update` action. | `install:4-17` |
| P0.2 | **Install the prerequisites.** Detect the package manager (`apt-get`/`dnf`/`pacman`/`zypper`) and install `git python3 python3-venv` + the runtime set (`pcscd opensc opensc-pkcs11 nss-tools openssl curl`). Replace the `exit 1` at `install:71-79` with a real remediation path, printing the exact command it is about to run. | `install:71-79` |
| P0.3 | **Handle the Debian/Ubuntu `python3-venv` split.** `python3 -m venv` fails without `python3-venv` on every Zorin/Ubuntu/Debian system. Either install it (P0.2) or detect the failure and report it precisely instead of printing "Done". | `install:104-111` |
| P0.4 | **Stop swallowing installer failures.** Remove every `cmd &` + `>/dev/null 2>&1` + unconditional `echo " Done"`. Run in the foreground, stream output, check exit codes. `set -e` is currently a no-op for all three heavy steps. | `install:93, 108, 118` |
| P0.5 | **Introduce a distribution/platform abstraction.** One `platform.py` owning: distro id + family, package manager + install command, trust store dir + refresh command, PKCS#11 module path (discovered via `ctypes.util.find_library` / `ldconfig -p` / glob, **not** hardcoded), service name, and browser profile locations. One place to add a distro instead of six. | new `sentinel_platform.py` |
| P0.6 | **Ship a real trust-store install.** Fedora: `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`. Debian/Ubuntu/Zorin: `/usr/local/share/ca-certificates/` + `update-ca-certificates`. Arch: `/etc/ca-certificates/trust/source/anchors/` + `trust extract-compat`. Use `pkexec install -m 0644` + `pkexec <refresh>` via `exec` — no `sh -c` at any level. | replaces `sentinel_backend.py:111-119` |
| P0.7 | **Only install self-signed roots.** Verify each certificate in the bundle (`openssl verify -CAfile <self> -partial_chain <self>` per file) and refuse anything that is not self-signed. Drop the external-PKI (ADO / Netherlands / commercial SSP) directory entirely — a DoD CAC tool has no business installing Australian or Dutch government roots on a US workstation. | `create_mega_chain.py` |
| P0.8 | **Verify the bundled trust material.** The `.sha256` files ship with every bundle and are never checked. Verify them at build time (offline) and record the verification in the release notes. | `create_mega_chain.py` |
| P0.9 | **Add a `--dry-run` / `--json` headless mode.** A tool that installs root CAs must be scriptable and testable. Today the only way to trigger the most privileged operation in the codebase is to click a button in a TUI. *Elevated from P1 after an incident on 2026-09-28: a smoke test of `install_certs` invoked the real `pkexec` path and modified the host's system trust store, because there was no way to exercise the code without root. Dry-run is a correctness requirement, not a convenience.* |
| P0.10 | **Write actual tests.** `test_sentinel.sh` is 2 lines. Minimum: a fake-distro fixture matrix (fedora / ubuntu / arch) asserting the trust-store path, refresh command, and PKCS#11 path resolve correctly; plus a test that the installer detects missing `python3-venv` and exits non-zero with a clear message. | new `tests/` |

**Exit criterion:** a clean Zorin OS VM, with **no** git, python3, opensc, or pcscd preinstalled, goes
from `curl | bash` to a working card read.

### P1 — Correctness and security debt

| # | Task |
|---|---|
| ~~P1.1~~ | ~~Delete the PUK/PIN argv code paths (S1)~~ — **CLOSED by Phase 0.4.** Do not reschedule. |
| ~~P1.2~~ | ~~Delete or hard-gate `validate_cert` (S2, S3, S4)~~ — **CLOSED by Phase 0.5.** Do not reschedule. |
| P1.3 | Purge `sentinel.log` from the repo and from git history. Add `.gitignore` covering `sentinel.log`, `__pycache__/`, `.venv/`, `*.pyc`, `sentinel_scap_report.txt`. `git rm -r --cached .venv __pycache__` (Hygiene Rule 5). Treat the EDIPIN in the log as a disclosure: confirm the repository was never public. |
| P1.4 | Make every subprocess async and add `asyncio.wait_for` timeouts, including the `pkexec` calls (B6, B7). Delete the `asyncio.sleep()` band-aids. |
| P1.5 | Fix the LED state machine: add the missing `else` on the `pkcs11-tool` guard (B5); stop leaving LEDs in `"loading"`; introduce a real tri-state (`unknown` / `ok` / `fail`) so "not checked" is visually distinct from "failed". |
| P1.6 | Browser config: refuse to modify a profile whose browser is running (or shut it down first and say so); import the DoD certs with `certutil -A`; verify with `modutil -list` **after** writing; set the LED from the actual result, not unconditionally (B4). |
| P1.7 | Make the scan output filter pass-through with a rate limit (B8); handle `ProcessLookupError` on terminate; hoist the ANSI regex (B9). |
| P1.8 | `RotatingFileHandler` + `Path(__file__).parent` for the log; `os.umask(0o077)` for any generated report; drop the syslog handler or strip identity data from it (S13). |
| P1.9 | **Automate the `/etc/opensc.conf` fix you already know about.** `SESSION_WORK_LOG.md:63` and `omnissa_fedora_cert_fix.md:154-157` document that OpenSC's default sequential driver probe sends APDU `00 CA DF 30 05` via the `setcos` driver, which hangs the **Broadcom 58200** reader firmware for exactly 26 seconds. The documented fix — `card_drivers = piv-II, cac, cac1` — was applied by hand to one Fedora machine and is **not in the codebase**. The Broadcom 58200 is a standard issued DoD reader, so every unconfigured machine in a fleet hits a 26-second freeze on first card insert, and Sentinel is the natural place to fix it once, portably. This is a small change with an outsized effect. |

### P2 — Maintainability

| # | Task |
|---|---|
| P2.1 | Collapse the three-callback signature into a single event sink; make the backend testable without Textual (§3.2). This also eliminates B1 structurally. |
| P2.2 | Replace the `if/elif` dispatcher with `Action` bindings + a dispatch map; add real key bindings (the TUI currently has none despite the docs claiming otherwise) (§3.1). |
| P2.3 | Delete the single-implementation strategy factory; rename `check_installed` → `have` (§3.3). |
| P2.4 | Pin every dependency with `==` and add upper bounds. Drop `pyhanko`, `cryptography`, `python-pkcs11` (removed features). |
| P2.5 | Move the 85-line inline CSS to `sentinel.tcss`; move `create_mega_chain.py` to `tools/`. |
| P2.6 | Delete the three docs that now misdescribe the tool: `README.md` ("Gold Master", "Debian/Ubuntu compatible", feature list), `SENTINEL_DOCS.md` (same, plus a nonexistent "Fix Service" button and a nonexistent `snl` uninstall), `DEV_HANDOVER.md` (the security claims that S1/S2/S3 contradict). A document that asserts a security property the code does not have is itself a finding. |

### P3 — After it works

Package integrity (`apt`/`dnf` package instead of `curl | bash`); a headless/unattended mode for
fleet provisioning; a `--verify` mode that proves the config is still intact; card-reader diagnostics
that actually help (`lsusb`, udev rules, CCID driver conflicts).

### Appendix — if removed code ever comes back

This is an appendix, not a backlog. Do not schedule against it.

The `validate_cert` rewrite must use HTTPS-only AIA with `--max-time` and `--max-filesize`, put all
scratch files in a `TemporaryDirectory` instead of fixed `/tmp` paths, never write fetched material
into the CAfile used for verification, and **delete the `OCSP/CRL Check: PASSED` line** unless a real
revocation check actually runs. The PIN/PUK paths must read `OPENSC_PIN`/`OPENSC_PUK` from a sanitized
env with no secret in `argv`. The SSH path must never write to `authorized_keys`.

---

## 6. What Was Done Well

Worth preserving through the refactor, because a rewrite would lose it:

- The UI/backend split is genuinely clean. Textual never touches a subprocess; the backend never
  imports Textual.
- The async-throughout design is right. Moving the bulk off the event loop was the correct instinct
  (it just wasn't finished — see B6).
- The February hardening pass was real work: `create_subprocess_exec` is used at 11 of 17 call sites,
  and the `SENTINEL_PIN`/`OPENSC_PIN` env-var pattern for `sign_pdf`/`validate_cert` is the correct
  approach. It was just applied inconsistently (S1) and extended into territory it can't secure (S2).
- The ASCII logo, the LED sidebar, and the compact `Log` layout are a real, usable TUI. The UI is
  better than the backend deserves.
- The Omnissa/Broadcom post-mortems in `omnissa_fedora_cert_fix.md` and `SESSION_WORK_LOG.md` are
  excellent field documentation. The finding that OpenSC's `setcos` driver probe hangs the Broadcom
  58200 for 26 seconds is a genuinely valuable piece of institutional knowledge — **and it is a
  mandatory config step that Sentinel does not perform.** See P3.
