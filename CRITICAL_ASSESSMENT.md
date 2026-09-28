# Sentinel — Critical Assessment

**Date:** 2026-09-28
**Artifact under review:** `sentinel` v1.0.0 "Gold Master" (`/home/jvm/projects/sentinel`)
**Claimed status:** "Enterprise-grade", "Stable Release", "Gold Master" (`README.md:3-5`)
**Stated mission:** help soldiers automatically configure their CAC against their system
**Test evidence:** 8 months of `sentinel.log`. Every entry: `Fedora Linux 43` or `Fedora Linux 44`.
Zero entries for any other distribution.

---

## Score: **4 / 10**

| Dimension | Score | Note |
|---|:---:|---|
| Correctness on stated mission | 1 / 10 | Failed completely on Zorin OS; no dependency installation exists anywhere in the codebase |
| Portability | 2 / 10 | Six hardcoded Fedora assumptions; `distro` is imported and never branched on |
| Security | 2 / 10 | PIN/PUK in `argv`; trust material fetched over HTTP; revocation reported PASSED without being checked |
| Reliability | 4 / 10 | Blocking `subprocess` in async paths; `pkexec` with no timeout; installer prints "Done" on failure |
| Code quality / architecture | 7 / 10 | Clean UI/backend split, async throughout, correct `exec`-over-`shell` instincts |
| Testability / verification | 1 / 10 | `test_sentinel.sh` is 2 lines. Zero tests, including for the root-privileged code path |
| Scope discipline | 2 / 10 | 12 features, 5 of them unfinished or actively harmful; the 3 that matter are the 3 that are broken |
| Documentation honesty | 2 / 10 | Claims of "Debian/Ubuntu compatible" and "PINs never appear in process lists" are both verifiably false |
| UI / UX craft | 8 / 10 | Genuinely good TUI. The best part of the project |
| Operational readiness | 2 / 10 | No packaging, no headless mode, no logging hygiene, committed PII |

**Weighted: 4 / 10.**

---

## The one-sentence version

Sentinel is a well-designed TUI shell wrapped around a Fedora-only backend that never does the one
thing the tool exists to do — install the software the tool depends on — and whose most prominent
security feature reports a result it did not actually compute.

---

## What the marketing says vs. what the code does

| Claim | Reality |
|---|---|
| `README.md:5` "v1.0.0 Gold Master" | No test suite, one distribution ever validated, two documented silent-failure paths. This is alpha software with a release tag. |
| `README.md:57` "Debian/Ubuntu compatible" | Zero Debian/Ubuntu code paths. `distro` appears twice, both times as a display string (`sentinel.py:221,226`). |
| `SENTINEL_DOCS.md:37` "Fedora, RHEL, Ubuntu, Debian, or Arch Linux" | Fedora/RHEL only. Arch has one incidental mention in a doc line. |
| `README.md:64` "installer script that handles dependencies" | It handles **pip** dependencies only. It installs zero system packages and `exit 1`s when `git` is absent. |
| `DEV_HANDOVER.md:60-62` / `SESSION_WORK_LOG.md:18-23` "PINs… never appear in command-line arguments or process lists (`ps aux`)" | The PIN **and the PUK** are in `argv` at `sentinel_backend.py:271,291`. A local user reads the PUK with `ps aux`. |
| `README.md:30` "AIA Chasing… Authenticated Fetching" | Fetches over **plaintext HTTP** from a URL taken out of the card's AIA extension, with no timeout and no size cap, then feeds the result to the trust store that produces the verdict. An on-path attacker controls the output. |
| `sentinel_backend.py:689` `OCSP/CRL Check: PASSED` | A string literal. `openssl verify` does not do OCSP or CRL checking. Nothing in the code contacts a revocation endpoint. |
| `sentinel_backend.py:544` "Identity Mapping: extracts UPN" | The regex `othername:UPN<...>` does not match OpenSSL's actual output (`othername: UPN:`). It has never matched. Every result silently falls back to the CN — visible in your own log. |
| `SENTINEL_DOCS.md:76-81` "Keyboard Navigation" | The app has zero key bindings. |
| `sentinel_backend.py:228-229` "Browser configuration complete" | Printed unconditionally after the loop, even if every database failed. Green LED either way. |

Nine verifiable claims, zero accurate. This is the most serious problem in the project, and it is worse
than the missing features: a soldier who reads "OCSP/CRL Check: PASSED" makes a decision on a false
statement. **Documented security properties the code does not have are findings in their own right.**

---

## Why Zorin failed — the diagnosis

Zorin OS is Ubuntu-based. The code has no concept of "Ubuntu" outside of one docstring
(`sentinel_stig.py:99`). Six independent hard failures, each sufficient on its own:

1. **`install:71-79`** — `command -v git` fails on a stock Zorin install (Ubuntu ships no git), script
   prints "[!] Error: Git is not installed." and `exit 1`s. The user is told the problem and given no
   fix. Same for `python3` if absent.
2. **`install:108`** — even with git/python3, `python3 -m venv` fails, because Debian/Ubuntu split
   `ensurepip` out into `python3-venv`, which is not installed by default. The failure is backgrounded
   (`&`), so `set -e` never sees it, output goes to `/dev/null`, and the script prints **"Done."**
3. **`install:113`** — `source .venv/bin/activate` then fails on a nonexistent/empty venv.
4. **`sentinel_backend.py:119`** — cert install runs `update-ca-trust`, which does not exist on Debian/Ubuntu (it is `update-ca-certificates`). Wrong trust directory too: `/etc/pki/ca-trust/source/anchors/` is Fedora-only; Ubuntu uses `/usr/local/share/ca-certificates/`.
5. **`sentinel_backend.py:150`** — the PKCS#11 path guard `os.path.exists("/usr/lib64/opensc-pkcs11.so")` fails (Ubuntu: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`). `configure_browsers` returns at the guard having done nothing.
6. **`sentinel_backend.py:63`** — the only remediation the tool offers for missing packages is the log line `Install via: dnf install pcsc-tools opensc`. Fedora's package manager, printed to a Zorin user. There is no install action anywhere in the codebase.

The tool did not partially work on Zorin. It could not have worked. Every privileged path was
Fedora-hardcoded, and the tool has never been executed on a second machine in its life — the log proves
the test matrix is a single Fedora workstation.

---

## The scope problem

The tool attempts 12 features. Assess each honestly:

| Feature | State | Verdict |
|---|---|---|
| Service check / auto-start | Works on Fedora; blocking `subprocess`; `pkexec` can hang forever | Fixable, keep |
| Dependency detection | Detects gaps, offers a Fedora one-liner, installs nothing | **Broken by design** |
| Card scan | Filters out nearly all real output (hardcoded string allowlist against another program's output) | Broken, cheap to fix |
| DoD cert install | Writes 200+ unverified certs — including ~150 intermediates and foreign government/commercial roots — into the system **trust anchors** directory | **Harmful, rebuild** |
| Browser config | Silently discarded if Firefox is running; reports success on total failure | Broken |
| Cert validation | Revocation is faked; trust material comes over HTTP; `-partial_chain` on a mega-chain makes the verdict meaningless | **Delete** |
| PIN status / change / unblock | PUK in `ps aux`; `re.DOTALL` bug renders the output useless | **Delete** |
| SSH export | Writes a public key into `authorized_keys` — grants inbound SSH to the card holder | **Delete** |
| SSH agent | Prints instructions; executes nothing | **Delete** |
| PDF signing | Works in principle; 3 heavy pip deps; 103 lines of helper for a peripheral feature | **Delete** |
| STIG (10 checks) | 6 RHEL-only paths, 2 rules check packages the user cannot install (`sssd`, `authselect`), calls itself "SC-LINUX-XXX" while claiming RHEL 9 mapping | **Delete** |
| SCAP report | `rpm`-only, 0644 inventory file in `$HOME` | **Delete** |

Three of the twelve — the ones that constitute the tool's actual mission — are the three that do not
work. Everything that "works" works only on the author's laptop, and the highest-severity findings
(S1, S2, S3, S5, S8) are all concentrated in features that add no value to the stated mission.

**Cutting cert validation, SSH, PDF signing, PIN management, and STIGs removes ~400 lines, 3 heavy
dependencies, 9 of the 13 security findings, and most of the distro-lock-in.** It is the right decision
and it converts this from an unmaintainable 12-feature tool into a 3-tab installer that could actually
be correct.

---

## The unforced errors

These are not feature-scope problems. They are avoidable process failures, and they are what make 4/10
generous rather than harsh.

1. **Committed PII.** `sentinel.log` is in the tree with 67 occurrences of a real service member's
   name and EDIPIN, plus DoD CA-71 serials and full `pkcs11-tool -O` dumps. `.venv/` and
   `__pycache__/` (cpython-314 bytecode) are also committed, in direct violation of the workspace's own
   written rule. **Confirm the repository was never public.** If it was, this is an incident, not a
   cleanup task.
2. **Zero tests** on ~1,380 lines of subprocess orchestration — including `install_certs`, the single
   most privileged operation in the codebase, which builds a root shell command. `test_sentinel.sh`
   contains `source ~/.bash_profile`.
3. **The installer lies by construction.** All three heavy steps are backgrounded with `&`, silenced to
   `/dev/null`, and followed by an unconditional `echo "Done"` — so `set -e` is a no-op for exactly the
   operations that can fail. A failed `pip install` produces a working-looking install and a
   `ModuleNotFoundError: textual` on first launch.
4. **Silent auto-update on every launch.** `install:4-17` runs `git fetch` and can `exec` itself before
   any sanity check, on every `snl` invocation. On a network-restricted DoD site that is a hang; against
   a compromised or force-pushed repository it is silent code execution as the user, on a machine that
   handles a CAC.
5. **`distro` imported and never used for control flow.** The one dependency that exists to make the
   tool portable was wired to a print statement. That single missed `if` is the root cause of the Zorin
   failure, and it is the whole failure in one line.
6. **A known, documented 26-second freeze was never fixed in code.** `SESSION_WORK_LOG.md:63` and
   `omnissa_fedora_cert_fix.md:154-157` identify the `setcos` driver APDU that hangs the Broadcom 58200
   — a standard issued DoD reader. The `card_drivers = piv-II, cac, cac1` fix was hand-applied to one
   Fedora machine and left as tribal knowledge. Every unconfigured machine in a fleet still hangs.
7. **A 355 KB trust bundle with unauthenticated provenance.** The `.sha256` verification files ship
   alongside every DoD bundle and are never checked by `create_mega_chain.py`, which blindly
   concatenates every `.p7b` it finds by walking the current directory.

---

## The strongest case for the project

The problem is real, the users are real, and the TUI is good. Replacing
`pkcs11-tool -O` / `modutil` / `pkcs15-tool --dump` / `openssl x509` archaeology with a visual status
dashboard is a genuine service to a non-technical user base. The sidebar LEDs, the compact log layout,
and the read-only-by-default posture are all correct instincts for a tool that runs as a normal user and
escalates only through `pkexec`.

And the February 2026 hardening session was real engineering: `create_subprocess_exec` at 11 of 17 call
sites, env-var secret passing, dynamic AIA format detection instead of extension guessing. The instinct
is right. It was applied inconsistently (missed the PIN/PUK call sites) and then pushed into a
territory it cannot secure (using an attacker-controllable HTTP fetch to build a trust store). Knowing
*which* instinct to keep and where to stop is the actual skill gap, not the coding.

The project is not far from good. It is far from *correct*, and the gap between those is roughly one
focused sprint: a platform abstraction, a real dependency installer, a trust store that contains only
self-signed roots, and the deletion of five features.

---

## Path to a passing grade

| Grade | Requires |
|:---:|---|
| **5 / 10** | **Phase 0 — the cut.** Cert validation, SSH, PDF signing, PIN management, STIGs and SCAP removed; `requirements.txt` down to 2 deps; docs rewritten to stop asserting properties the code doesn't have. Closes 9 of 13 security findings, including both CRITICALs, by deletion rather than by fix. |
| **6 / 10** | P0. A clean Zorin VM with nothing preinstalled goes from `curl` to a working card read. `sentinel.log` and `.venv/` purged. |
| **7 / 10** | P0 + P1. Browser config verifiable and non-destructive. Every `pkexec` call has a timeout. LEDs reflect real state. |
| **8 / 10** | P0 + P1 + P2. Tests over a fake-distro fixture matrix. Pinned dependencies. The backend has no UI coupling. A headless `--dry-run` mode so the privileged paths are testable and scriptable. |
| **9 / 10** | Packaged for `apt` and `dnf`. Runs unattended in a fleet provisioning pipeline. Proven on three distribution families by someone other than the author. |
| **10 / 10** | Not achievable for a tool whose input is physical hardware and whose user base is non-technical. The tail risk is always a reader firmware, a distro repack, or a card the author has not seen. |

---

## Why the cut comes first

The instinct to remove before repairing is correct here, and not just because it reduces surface area.
Three specific reasons:

1. **For 9 of the 13 security findings, deletion *is* the fix.** The PIN/PUK in `argv` (S1) is closed by
   deleting PIN management. The HTTP trust-material fetch (S2), the faked `OCSP/CRL Check: PASSED`
   (S3), and the vacuous `-partial_chain` verdict (S4) are closed by deleting cert validation. The
   `authorized_keys` escalation (S8) is closed by deleting SSH. Fixing these properly is 200+ lines of
   careful crypto work on features that do not serve the mission. Deleting them is 15 minutes and a
   smaller attack surface than a correct implementation would have.
2. **The bugs users actually hit are concentrated in the code being removed.** The Zorin failure is
   downstream of `/usr/lib64` hardcoding, which appears in `configure_browsers`, `sign_pdf`, and
   `setup_ssh_agent` — all removed — plus the trust-store path, which survives. The UPN regex that never
   matched (B2) and the `update_led` arity crash (B1) are both inside `validate_cert`, which is removed.
   After the cut the confirmed-bug list shrinks from 10 items to 5.
3. **Everything that remains is small enough to get right.** ~600 lines and 2 dependencies can be tested
   over a fake-distro fixture matrix by one person. ~1,380 lines and 5 dependencies cannot — which is
   the actual reason this project shipped to v1.0 with zero tests.

The one precondition: `sentinel/` is not a git repository, so there is no revert. Initialize and tag a
baseline commit before deleting anything, both so the cut is one reviewable diff and so the working
Fedora install remains available as a regression check.

---

## Bottom line

**4 / 10.** The TUI deserves the 7 in the architecture column; the backend deserves the 1 in the
correctness column. The gap between them is the project.

The single highest-leverage action is not any individual bug fix — it is deleting five features
(cert validation, SSH, PDF signing, PIN management, STIGs), which removes 9 of 13 security findings
and most of the distro-lock-in, and leaves a tool small enough to make actually correct. The second is
writing the ~60-line platform abstraction that `distro` should have been driving from day one.

Fix the tool's honesty before fixing its feature set. A tool that prints `OCSP/CRL Check: PASSED`
without checking revocation is worse than no tool, and that is the line to fix first.
