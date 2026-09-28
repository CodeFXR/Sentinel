# Sentinel — Developer Handover

**Version:** v2.0.0 (post-scope-reduction)
**Stack:** Python 3.10+, Textual, asyncio, OpenSC
**Size:** ~470 lines of application code, 2 runtime dependencies

---

## 1. State of the code

This is a **small tool with a large amount of unfinished business.** Read
`ROADMAP.md` before starting work — it is the authoritative plan and this document is
only orientation.

`CRITICAL_ASSESSMENT.md` scores the project 4/10. The score is about the product
promising things it does not do, not about the code being hard to read. The code is
clean; the feature set was wrong and the distribution support was never real.

**Validated on:** one machine, Fedora Linux 43 and 44. Nothing else. The historical
`sentinel.log` contains runs from exactly two Fedora versions and no other
distribution. Do not assume a change works anywhere until it has been run on a second
distribution family.

---

## 2. Module map

| File | Lines | Responsibility |
|---|---|---|
| `sentinel.py` | 257 | Textual UI: widgets, CSS, event dispatch, card scan loop. Contains no subprocess calls. |
| `sentinel_backend.py` | 226 | All subprocess orchestration in three methods: `check_services`, `install_certs`, `configure_browsers`. Contains no Textual imports. |
| `sentinel_utils.py` | 58 | `StatusLED` widget, `get_terminal_name()`, `LinuxStrategy` (service probing). |
| `tools/create_mega_chain.py` | 100 | Maintenance script to rebuild `DoD_Mega_Chain.pem`. Never invoked at runtime. |
| `install` | 164 | Setup script. See §5. |

### Conventions

- Backend methods are `async` and take `log_writer` and `update_led` callbacks. The
  backend never holds a widget reference; this is what keeps it testable.
- Subprocesses use `asyncio.create_subprocess_exec` with argument lists. Two
  exceptions survive and are both bugs: `check_services` uses
  `create_subprocess_shell` for `pkexec systemctl start pcscd` and `sentinel.py` uses
  it for `pcsc_scan`.
- Secrets are never passed in `argv`. This rule is now trivially satisfied — no code
  path handles a PIN any more, which is the point of the v2.0.0 cut.
- Logging goes to both the TUI `Log` widget and `sentinel.log` + syslog.

---

## 3. Deliberate removals (v2.0.0)

Six features were deleted to make the tool small enough to be correct. The rationale
and the full finding list are in `ROADMAP.md` §4. Summary of why each went:

- **Certificate validation** — the most dangerous code in the project's history. It
  printed `OCSP/CRL Check: PASSED` as an unconditional string literal, having
  performed no revocation check whatsoever, and it constructed the trust store it
  validated against by downloading a certificate over plaintext HTTP from a URL read
  out of the on-card AIA extension (`http://crl.disa.mil/...`). An on-path attacker
  controlled the verdict. It also used `openssl verify -partial_chain` with a
  197-certificate mega-chain, which promotes every intermediate to a trust anchor and
  makes the result near-meaningless.
- **PIN management** — `pkcs15-tool --change-pin` and `--unblock-pin` were called with
  `--pin` and `--puk` in `argv`. `DEV_HANDOVER.md` and `SESSION_WORK_LOG.md` from the
  previous release both asserted that PINs were passed only via environment variables.
  That claim was false for exactly these two call sites, and a leaked PUK is worse
  than a leaked PIN.
- **SSH integration** — `export_ssh_key` appended the PIV public key to
  `~/.ssh/authorized_keys`. That file controls *inbound* SSH to the host, so the
  feature granted anyone holding the card the ability to log into the machine.
- **PDF signing** — worked, but dragged in `pyhanko`, `cryptography`, and
  `python-pkcs11` for a peripheral feature. `pyhanko-certvalidator` was imported
  without being declared in `requirements.txt`; it only ever resolved as a transitive
  dependency.
- **STIG auditing** — 10 rules, 6 of which used RHEL-only paths (`rpm`,
  `/usr/lib64/engines-3/`, `/etc/pki/ca-trust/`, `authselect`), and 2 of which tested
  for `sssd` and `authselect` packages a desktop user will not have. The
  "SC-LINUX-XXX" identifiers implied DISA mapping that the rules did not implement.
- **SCAP report** — `rpm`-only inventory written to `$HOME/sentinel_scap_report.txt`
  with default 0644 permissions.

Net effect: 1,380 → 470 lines, 5 → 2 dependencies, 13 → 4 security findings, and the
two CRITICAL findings are gone rather than mitigated.

**If any of this comes back**, the constraints are in `ROADMAP.md` §5 Appendix. Do not
re-add a revocation check that does not actually perform one.

---

## 4. The certificate bundle problem

`DoD_Mega_Chain.pem` is 197 certificates, 69 unique, of which only **19 are
self-signed**. `install_certs` writes all of them into a trust-**anchor** directory,
which means 178 intermediates and cross-certificates — including Australian Defence
Organisation, Netherlands Ministry of Defence, US State Department, US Treasury, and
several commercial SSP chains — are installed as roots.

`tools/create_mega_chain.py` now verifies all three input bundles against their
embedded SHA-256 manifests before parsing, and aborts on mismatch. All 17
manifest-covered files verify clean. Two non-obvious details, both now handled:

- The `.sha256` files are binary containers with the manifest embedded as ASCII.
  `sha256sum -c` does not work on them.
- Hex case is inconsistent — lowercase in the v5.12 ECA bundle, uppercase in v5.17 WCF
  and v5.6 DoD. A lowercase-only pattern finds nothing in two of three bundles.

**The roots-only rebuild is still open.** Filtering `install_certs` to self-signed
certificates only, and dropping the external-PKI directory from the build, is roadmap
item P0.7.

---

## 5. The installer is the weakest file

`install` is 164 lines of shell and is the least trustworthy code in the repository.
It is not the subject of the v2.0.0 cut and it has not been improved. Known problems,
all roadmap items in P0:

1. **Requires `git` and `python3` to already exist.** Exits with an error otherwise.
   Installs no system packages at all, despite the README claiming it "handles
   dependencies."
2. **`python3 -m venv` fails on Debian/Ubuntu/Zorin** because `ensurepip` is in the
   separate `python3-venv` package, which the script does not check for or install.
3. **Every heavy step is backgrounded with `&`, silenced to `/dev/null`, and followed
   by an unconditional `echo "Done"`.** `set -e` therefore never fires for `git clone`,
   `python3 -m venv`, or `pip install`. All three can fail and the user is told
   everything worked.
4. **Auto-updates from GitHub on every launch.** The block at the top of the file
   `cd`s into `~/.sentinel` and `git pull`s before any sanity check, and can `exec`
   itself in a loop. On a network-restricted site that is a hang; against a
   compromised repository it is silent code execution on a machine holding a CAC.
5. **`install_certs` builds `pkexec sh -c "cp ... && update-ca-trust"`.** A checkout
   path containing a single quote breaks the quoting into root command execution.

---

## 6. Immediate next steps

In order. Full detail in `ROADMAP.md` §5.

1. **P0.1 — delete the auto-update block from `install`.** Smallest change with the
   largest risk reduction.
2. **P0.5 — add a platform abstraction.** One module owning distro detection, package
   manager, trust-store path and refresh command, PKCS#11 module path (discovered, not
   hardcoded), and browser profile locations. The `distro` dependency is already there
   and is currently used for a single `write_line` call. This is the root cause of the
   tool failing entirely on Zorin OS.
3. **P0.2 / P0.3 / P0.4 — make `install` install its prerequisites** (including
   `python3-venv` on Debian-family), stop swallowing failures, and check exit codes.
4. **P0.7 — rebuild the bundle roots-only.**
5. **P1 — fix `pkexec sh -c`, add timeouts to both `pkexec` calls, make the service
   probes async, fix the LED state machine, stop reporting browser config success
   unconditionally, apply the `/etc/opensc.conf` Broadcom 58200 fix.**
6. **P0.10 — write tests.** There are none. `test_sentinel.sh` is two lines. At
   minimum, a fake-distro fixture matrix asserting that trust-store path, refresh
   command, and PKCS#11 path resolve correctly for fedora / ubuntu / arch, plus a test
   that the installer detects a missing `python3-venv` and exits non-zero.

---

## 7. Things worth preserving

If this gets rewritten, do not lose these.

- **The UI/backend split.** Textual never touches a subprocess; the backend never
  imports Textual. Backend methods take callbacks rather than widget references, which
  is why the backend is testable at all.
- **Async throughout.** Moving work off the event loop was the right instinct, even
  though two blocking `subprocess.run` calls were left behind in `sentinel_utils.py`.
- **The compact TUI.** The sidebar LEDs, the ASCII logo, and the dense log layout are
  the best part of the project and are well suited to a non-technical user base.
- **The Omnissa and Broadcom 58200 post-mortems** in `omnissa_fedora_cert_fix.md` and
  `SESSION_WORK_LOG.md`. The finding that OpenSC's `setcos` driver probe hangs the
  Broadcom 58200 for 26 seconds via APDU `00 CA DF 30 05` is genuinely valuable
  institutional knowledge, and it is a mandatory config step that Sentinel still does
  not perform.
- **Field validation on real hardware.** The tool was developed against a real CAC and
  a real reader. That is rarer than it should be and worth keeping.
