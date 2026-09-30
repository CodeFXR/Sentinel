"""Subprocess orchestration.

Nothing in this module imports Textual. Methods take a single `emit` callback
and return a structured `Outcome`, which is what makes them testable: the test
suite drives every path including the privileged one, with `dry_run=True`, on a
machine with no card and no root.

Three rules hold throughout:

* Every subprocess has a timeout. A `pkexec` prompt that cannot be rendered
  inside a TUI otherwise blocks the event loop forever with no error.
* Every subprocess uses `create_subprocess_exec` with an argument list. No
  `sh -c` anywhere, including under `pkexec`, so a path containing a quote or a
  space cannot become root command execution.
* `dry_run=True` performs every check and prints every command it would run,
  and changes nothing. That is the only supported way to exercise the
  privileged paths.
"""

from __future__ import annotations

import asyncio
import os
import shutil

from dataclasses import dataclass, field
from typing import Callable

import sentinel_browser
import sentinel_certs
import sentinel_diag
import sentinel_platform as platform_mod
from sentinel_platform import (
    BROADCOM_WORKAROUND,
    LEGACY_ANCHOR_NAMES,
    TRUST_ANCHOR_NAME,
    detect,
    nss_databases,
    opensc_conf_path,
)

# Long enough for a human to read a polkit dialog and type a password. Short
# enough that a wedged or agentless system does not hang the app forever.
POLKIT_TIMEOUT = 120.0
# Ordinary probes should be near-instant; a wedged pcscd must not stall the UI.
PROBE_TIMEOUT = 15.0
NSS_TIMEOUT = 10.0

MODULE_NAME = "DoD CAC"


@dataclass
class Event:
    """A single thing that happened, for the caller to render.

    kind is "log" for a line of console output, or "led" for a status change.
    """

    kind: str
    payload: str
    status: str = ""


@dataclass
class Outcome:
    """The result of an operation, in a form both the TUI and --json can use."""

    action: str
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "ok": self.ok,
            "detail": self.detail,
            **self.data,
        }


Emit = Callable[[Event], None]


def _noop(_event: Event) -> None:
    pass


async def run(
    argv: list[str],
    timeout: float = PROBE_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a command, always with a timeout. Never raises for a failed command.

    Returns (returncode, stdout, stderr). A timeout is reported as returncode
    124 with the reason in stderr, so callers have one error path instead of
    two. The child is killed and reaped on timeout so it cannot outlive the
    call.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, ValueError) as exc:
        return 127, "", f"could not execute {argv[0]}: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except ProcessLookupError:
            pass
        return 124, "", f"timed out after {timeout:g}s"

    return (
        proc.returncode if proc.returncode is not None else 1,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


class SentinelBackend:
    def __init__(self, logger, platform=None):
        self.logger = logger
        self.platform = platform or detect()
        self.SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    # --- helpers ------------------------------------------------------------

    def _pkexec_prefix(self, emit: Emit) -> bool:
        """Whether a privileged step can run at all.

        Refuses rather than degrading: running the step unprivileged would
        produce a confusing permission error instead of an honest one.
        """
        if shutil.which("pkexec"):
            return True
        emit(Event("log", "ERROR: 'pkexec' not found, cannot request privileges."))
        emit(Event("log", "Install polkit, or run the equivalent commands by hand."))
        return False

    def _legacy_anchors(self) -> list[str]:
        """Earlier Sentinel versions installed these. They contain non-roots."""
        if not self.platform.trust_anchor_dir:
            return []
        return [
            os.path.join(self.platform.trust_anchor_dir, name)
            for name in LEGACY_ANCHOR_NAMES
            if name != self.platform.trust_anchor_name
        ]

    # --- operations ---------------------------------------------------------

    async def check_services(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Probe the smart-card stack. Escalates only to start a stopped daemon."""
        log = lambda text: emit(Event("log", text))
        log("\n--- PROBING CORE SERVICES ---")
        self.logger.info("Starting system compliance check")

        emit(Event("led", "led-service", "loading"))
        emit(Event("led", "led-opensc", "loading"))

        # 1. The daemon.
        if await platform_mod.service_is_active(self.platform.service):
            log("OK: pcscd is active.")
            emit(Event("led", "led-service", "success"))
            self.logger.info("PCSC Service: Active")
        else:
            log(f"WARN: {self.platform.service} is not active.")
            if dry_run:
                log(f"DRY RUN: would run: pkexec systemctl start {self.platform.service}")
                emit(Event("led", "led-service", "idle"))
            elif not self._pkexec_prefix(emit):
                emit(Event("led", "led-service", "error"))
            else:
                rc, _, err = await run(
                    ["pkexec", "systemctl", "start", self.platform.service],
                    timeout=POLKIT_TIMEOUT,
                )
                if rc == 0 and await platform_mod.service_is_active(self.platform.service):
                    log(f"SUCCESS: {self.platform.service} started.")
                    emit(Event("led", "led-service", "success"))
                    self.logger.info("PCSC Service: Started successfully")
                else:
                    reason = err.strip() or f"exit {rc}"
                    log(f"ERROR: could not start {self.platform.service}: {reason}")
                    log(f"Manual fix: sudo systemctl enable --now {self.platform.service}")
                    emit(Event("led", "led-service", "error"))
                    self.logger.error(f"PCSC Service: failed to start: {reason}")

        # 2. Required binaries. Detection only; the installer installs these.
        required = ("pcsc_scan", "pkcs11-tool", "opensc-tool")
        missing = [tool for tool in required if not platform_mod.have(tool)]
        if missing:
            log(f"WARNING: missing tools: {', '.join(missing)}")
            log(f"Detected platform: {self.platform.name}")
            log(f"Fix with: sudo {self.platform.install_hint()}")
            self.logger.warning(f"Dependencies: Missing {', '.join(missing)}")
        else:
            log("OK: required tools installed.")
            self.logger.info("Dependencies: OK")

        # 3. Middleware and card presence.
        if "pkcs11-tool" in missing:
            # B5: without this the LED would spin forever and imply a card
            # problem when the real problem is a missing package.
            log("SKIP: pkcs11-tool not installed, cannot enumerate slots.")
            emit(Event("led", "led-opensc", "idle"))
        elif dry_run:
            log("DRY RUN: would run: pkcs11-tool -L")
            emit(Event("led", "led-opensc", "idle"))
        else:
            rc, stdout, err = await run(["pkcs11-tool", "-L"])
            slots = _parse_slots(stdout)
            if rc == 0 and slots:
                log(f"OK: {len(slots)} PKCS#11 slot(s) detected.")
                emit(Event("led", "led-opensc", "success"))
                self.logger.info(f"Middleware: {len(slots)} PKCS#11 slot(s) detected")
                if slots:
                    for label in slots:
                        log(f"  slot: {label}")
                if any(k in stdout for k in ("piv_II", "CAC", "PIV")):
                    log("Card type: PIV/CAC-compatible token found.")
                    self.logger.info("Middleware: PIV/CAC token detected")
                emit(Event("led", "led-card", "success"))
            elif rc == 124:
                log("ERROR: pkcs11-tool timed out talking to pcscd.")
                emit(Event("led", "led-opensc", "error"))
                self.logger.error("Middleware: pkcs11-tool timed out")
            else:
                # Daemon up, no card. That is a normal state, not a failure, and
                # the LED must say so instead of spinning forever.
                log("INFO: no PKCS#11 slots found. Is the card inserted?")
                emit(Event("led", "led-opensc", "success"))
                emit(Event("led", "led-card", "idle"))
                self.logger.info("Middleware: no slots found")

        return Outcome(
            action="check",
            ok=not missing,
            detail="stack probed",
            data={
                "platform": self.platform.name,
                "missing_tools": missing,
                "supported": self.platform.supported,
            },
        )

    async def install_certs(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Install the DoD self-signed roots into the distribution trust store.

        The bundle is audited before it is installed: any certificate that is not
        self-signed aborts the operation, because promoting an issuing CA to a
        trust anchor is the defect this replaces.
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- INSTALLING DoD ROOT CERTIFICATES ---")
        self.logger.info("Starting DoD certificate installation")
        emit(Event("led", "led-certs", "loading"))

        platform = self.platform
        target_dir = platform.trust_anchor_dir
        refresh_cmd = platform.trust_refresh_cmd
        if target_dir is None or not refresh_cmd:
            log(f"ERROR: {platform.name} is not a supported trust-store layout.")
            log("Sentinel will not guess a certificate directory.")
            log("Install the DoD roots by hand; the README has the command for")
            log(f"your distribution.")
            self.logger.error(f"Unsupported trust store layout: {platform.family}")
            emit(Event("led", "led-certs", "error"))
            return Outcome("install-certs", False, "unsupported trust store", {"platform": platform.name})

        chain_file = os.path.join(self.SCRIPT_DIR, TRUST_ANCHOR_NAME)
        if not os.path.exists(chain_file):
            log(f"ERROR: {chain_file} not found.")
            log("The bundled certificate file is damaged. See the README.")
            emit(Event("led", "led-certs", "error"))
            return Outcome("install-certs", False, "bundle missing", {"path": chain_file})

        with open(chain_file, encoding="ascii", errors="replace") as fh:
            good, problems = sentinel_certs.verify_roots_only(fh.read())
        if problems:
            log(f"ERROR: {chain_file} is not a valid trust-anchor bundle:")
            for problem in problems:
                log(f"  - {problem}")
            log("Nothing was installed. The bundled certificate file is damaged;")
            log("see the README for how to obtain a fresh copy.")
            self.logger.error(f"Bundle rejected: {len(problems)} problem(s)")
            emit(Event("led", "led-certs", "error"))
            return Outcome(
                "install-certs", False, "bundle is not roots-only",
                {"problems": problems},
            )

        target_file = os.path.join(target_dir, platform.trust_anchor_name)
        legacy = [p for p in self._legacy_anchors() if os.path.exists(p)]

        log(f"Platform:  {platform.name}")
        log(f"Roots:     {len(good)} self-signed certificate(s)")
        for cn in good:
            log(f"  - {cn}")
        log(f"Source:    {chain_file}")
        log(f"Target:    {target_file}")
        if legacy:
            log("Removing over-trusting bundle(s) from an earlier version:")
            for path in legacy:
                log(f"  - {path}")

        steps: list[list[str]] = [
            ["pkexec", "install", "-m", "0644", chain_file, target_file],
        ]
        for path in legacy:
            steps.append(["pkexec", "rm", "-f", path])
        steps.append(["pkexec", *refresh_cmd])

        if dry_run:
            log("DRY RUN: no changes made. Commands that would run as root:")
            for command in steps:
                log(f"  $ {' '.join(command)}")
            emit(Event("led", "led-certs", "idle"))
            return Outcome(
                "install-certs", True, "dry run",
                {
                    "platform": platform.name,
                    "roots": good,
                    "target": target_file,
                    "would_remove": legacy,
                    "commands": [" ".join(c) for c in steps],
                },
            )

        if not self._pkexec_prefix(emit):
            emit(Event("led", "led-certs", "error"))
            return Outcome("install-certs", False, "pkexec unavailable")

        log("Requesting privileges via pkexec...")
        for command in steps:
            rc, _, stderr = await run(command, timeout=POLKIT_TIMEOUT)
            if rc != 0:
                reason = stderr.strip() or f"exit {rc}"
                log(f"FAILURE: {' '.join(command)}")
                log(f"  {reason}")
                self.logger.error(f"Certificate installation failed: {reason}")
                emit(Event("led", "led-certs", "error"))
                return Outcome(
                    "install-certs", False, reason,
                    {"command": " ".join(command), "returncode": rc},
                )

        log(f"SUCCESS: {len(good)} DoD root(s) installed and trust store refreshed.")
        self.logger.info(f"DoD roots installed successfully ({len(good)} certificates)")
        emit(Event("led", "led-certs", "success"))
        return Outcome(
            "install-certs", True, f"{len(good)} root(s) installed",
            {"platform": platform.name, "roots": good, "target": target_file, "removed": legacy},
        )

    async def configure_browsers(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Register the OpenSC PKCS#11 module in every NSS database the user has.

        Also imports the DoD roots into each database. Registering a module
        without importing certificates leaves the device present in Firefox with
        nothing usable in it, which reads as "the tool did not work".
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- CONFIGURING BROWSERS (NSS DB) ---")
        self.logger.info("Starting browser configuration")
        emit(Event("led", "led-browsers", "loading"))

        modutil = shutil.which("modutil")
        lib_path = self.platform.pkcs11_module
        certutil = shutil.which("certutil")

        if not modutil:
            log("ERROR: 'modutil' not found (package nss-tools / libnss3-tools).")
            log(f"Fix with: sudo {self.platform.install_hint()}")
            emit(Event("led", "led-browsers", "error"))
            return Outcome("configure-browsers", False, "modutil not found")
        if not lib_path:
            log("ERROR: opensc-pkcs11.so not found. Install OpenSC first.")
            log(f"Fix with: sudo {self.platform.install_hint()}")
            emit(Event("led", "led-browsers", "error"))
            return Outcome("configure-browsers", False, "opensc-pkcs11.so not found")
        if not certutil:
            log("WARNING: 'certutil' not found; the module will be registered but")
            log("         no certificates imported, so the device may appear empty.")

        # What is installed, and can each of them actually reach the card.
        # Reported before any write, because a sandboxed browser cannot be
        # fixed by writing to its NSS database.
        browsers = sentinel_browser.inventory()
        confined = [b for b in browsers if b.confined and b.nss_databases]
        for browser in browsers:
            log(f"Browser: {browser.name} -- {browser.detail}")

        nss_paths = nss_databases()
        log(f"Module:  {lib_path}")
        log(f"Found {len(nss_paths)} NSS database(s).")

        if dry_run:
            # A dry run reports the plan. Discovering that there is nothing to
            # do is a finding about the system, not a failure of the run.
            if not nss_paths:
                log("No NSS databases found. Launch a browser once, then retry.")
            else:
                for db_path in nss_paths:
                    log(f"Would update: {db_path}")
            log("Would add the module and import the DoD roots into each.")
            emit(Event("led", "led-browsers", "idle"))
            return Outcome(
                "configure-browsers", True, "dry run",
                {
                    "module": lib_path,
                    "databases": nss_paths,
                    "browsers_running": platform_mod.browsers_running(),
                },
            )

        if not nss_paths:
            log("No NSS databases found. Launch a browser once, then retry.")
            emit(Event("led", "led-browsers", "error"))
            return Outcome("configure-browsers", False, "no NSS databases found")

        running = platform_mod.browsers_running()
        if running:
            # Firefox rewrites prefs.json on exit and discards the change.
            log(f"WARNING: {', '.join(running)} is running.")
            log("         Firefox rewrites its profile on exit and will discard")
            log("         this change. Close it, re-run CONFIG BROWSERS, restart it.")

        bundle = os.path.join(self.SCRIPT_DIR, TRUST_ANCHOR_NAME)
        have_bundle = os.path.exists(bundle)

        succeeded: list[str] = []
        failed: list[dict] = []

        for db_path in nss_paths:
            log(f"Updating: {db_path}...")
            self.logger.info(f"Browser config: {db_path}")
            ok, reason = await self._configure_one(
                modutil, certutil, lib_path, bundle, db_path, have_bundle
            )
            if ok:
                log("  -> verified: module present and roots imported.")
                succeeded.append(db_path)
            else:
                log(f"  -> FAILED: {reason}")
                failed.append({"database": db_path, "error": reason})

        if not succeeded:
            log(f"FAILED: none of the {len(nss_paths)} database(s) could be configured.")
            self.logger.error("Browser configuration: no database succeeded")
            emit(Event("led", "led-browsers", "error"))
            return Outcome(
                "configure-browsers", False, "no database configured",
                {"databases": nss_paths, "failures": failed},
            )

        log(f"Configured and verified {len(succeeded)}/{len(nss_paths)} database(s).")
        if failed:
            log(f"{len(failed)} database(s) failed; see the lines above.")
        log("Close and restart browsers to apply.")

        # A green LED means a browser can use the card. Writing to an NSS
        # database inside a sandbox proves the write worked, not that the
        # browser can load the module. Claiming green there is the v1.0.0 bug
        # in a new place, so a confined browser gets its own state instead.
        usable = [b for b in browsers if not b.confined and b.nss_databases]
        if confined and not usable:
            for browser in confined:
                log("")
                log(f"!! {browser.name} cannot use your smart card.")
                log("")
                for line in sentinel_browser.guidance_for(browser).splitlines():
                    log(f"   {line}")
            self.logger.error("Browser configuration: every browser is sandboxed")
            emit(Event("led", "led-browsers", "error"))
            return Outcome(
                "configure-browsers", False,
                "the only browser installed cannot load a smart card",
                {"succeeded": succeeded, "confined": [b.name for b in confined],
                 "guidance": [sentinel_browser.guidance_for(b) for b in confined]},
            )

        if confined:
            for browser in confined:
                log("")
                log(f"Note: {browser.name} cannot use your smart card.")
                for line in sentinel_browser.guidance_for(browser).splitlines():
                    log(f"   {line}")

        # Green only on the strength of a post-write verification against a
        # browser that is not sandboxed.
        emit(Event("led", "led-browsers", "success"))
        return Outcome(
            "configure-browsers", not failed, f"{len(succeeded)}/{len(nss_paths)} configured",
            {"succeeded": succeeded, "failed": failed, "browsers_running": running,
             "confined": [b.name for b in confined]},
        )

    async def _configure_one(
        self, modutil, certutil, lib_path, bundle, db_path, have_bundle
    ) -> tuple[bool, str]:
        """Add the module to one NSS database and verify the result."""
        try:
            rc, stdout, _ = await run(
                [modutil, "-dbdir", f"sql:{db_path}", "-list", MODULE_NAME],
                timeout=NSS_TIMEOUT,
            )
            if rc == 0 and MODULE_NAME in stdout:
                # Present, but it may still be pointed at a stale library path.
                if lib_path in stdout:
                    module_ok = True
                else:
                    log_stale = stdout.strip()
                    rc, _, err = await run(
                        [modutil, "-force", "-dbdir", f"sql:{db_path}",
                         "-add", MODULE_NAME, "-libfile", lib_path],
                        timeout=NSS_TIMEOUT,
                    )
                    if rc != 0:
                        return False, f"could not repoint module ({err.strip() or rc})"
                    module_ok = True
            else:
                rc, _, err = await run(
                    [modutil, "-force", "-dbdir", f"sql:{db_path}",
                     "-add", MODULE_NAME, "-libfile", lib_path],
                    timeout=NSS_TIMEOUT,
                )
                if rc != 0:
                    return False, err.strip() or f"modutil -add exit {rc}"
                module_ok = True

            if module_ok and certutil and have_bundle:
                rc, _, err = await run(
                    [certutil, "-N", "-d", f"sql:{db_path}", "-A",
                     "-n", "DoD Root CAs", "-t", "C,,", "-i", bundle],
                    timeout=NSS_TIMEOUT,
                )
                if rc != 0:
                    # Not fatal: the module is registered, which is the part
                    # that makes the card appear. Say so rather than claiming
                    # success.
                    return True, f"module added, certificate import failed: {err.strip() or rc}"

            # Verify by reading back rather than trusting the exit code.
            rc, stdout, _ = await run(
                [modutil, "-dbdir", f"sql:{db_path}", "-list", MODULE_NAME],
                timeout=NSS_TIMEOUT,
            )
            if rc != 0 or MODULE_NAME not in stdout:
                return False, "module absent after write"
            return True, ""
        except Exception as exc:  # defensive: one bad profile must not stop the rest
            return False, str(exc)

    async def diagnose_reader(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Explain, in plain language, why the card is not being seen.

        "No card detected" is not actionable for someone who does not know what
        a reader is. This separates the four things that actually go wrong: no
        reader, the wrong reader (a laptop's fingerprint sensor claiming the
        card slot), a permissions problem, and a driver conflict.
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- CHECKING YOUR CARD READER ---")

        findings = await asyncio.to_thread(sentinel_diag.diagnose)
        problems = [f for f in findings if f.severity == "problem"]
        for finding in findings:
            log(finding.line())

        log("")
        if not problems:
            log("Your reader is working. If your card still does not appear, the")
            log("problem is further up the chain -- run CONFIG BROWSERS and look")
            log("for the browser section.")
        else:
            log(f"{len(problems)} thing(s) need fixing. Each one is listed above")
            log("with the exact command to run.")

        return Outcome(
            "diagnose", not problems,
            "reader is working" if not problems else f"{len(problems)} problem(s)",
            {"problems": len(problems),
             "findings": [{"severity": f.severity, "title": f.title, "fix": f.fix}
                          for f in findings]},
        )

    async def fix_opensc_conf(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Restrict OpenSC to the PIV/CAC drivers.

        Without this, OpenSC probes an inserted card with every driver it knows.
        The `setcos` driver sends APDU 00 CA DF 30 05, which the Broadcom Corp
        58200 reader's firmware cannot answer, and the probe times out after
        about 26 seconds on every first insert. The 58200 is a standard issued
        DoD reader, so an unconfigured machine in a fleet freezes for that long
        on every insert. The change is one line in /etc/opensc.conf and reduces
        first-insert latency from ~28s to ~0.2s.
        """
        log = lambda text: emit(Event("log", text))
        path = opensc_conf_path()

        if not platform_mod.broadcom_workaround_needed():
            log(f"OK: {path} already sets card_drivers; no change needed.")
            return Outcome("fix-opensc", True, "already configured", {"path": path})

        log("OpenSC is not configured to skip the reader-incompatible setcos driver.")
        log(f"This is required for the Broadcom Corp 58200 reader. Add to {path}:")
        log(f"    {BROADCOM_WORKAROUND}")
        log("Reduces first-insert latency from ~28s to ~0.2s.")

        if dry_run:
            log("DRY RUN: no change made.")
            return Outcome("fix-opensc", True, "dry run", {"path": path, "setting": BROADCOM_WORKAROUND})

        # Never rewrite the whole file: an existing configuration may hold
        # settings Sentinel knows nothing about. Append only if the key is
        # genuinely absent, and keep a backup.
        try:
            with open(path, "a+", encoding="utf-8") as fh:
                fh.seek(0)
                current = fh.read()
                if "card_drivers" in current:
                    log(f"{path} already sets card_drivers; leaving it alone.")
                    return Outcome("fix-opensc", True, "already configured", {"path": path})
                backup = f"{path}.sentinel.bak"
                with open(backup, "w", encoding="utf-8") as bfh:
                    bfh.write(current)
                fh.write(f"\n# Added by Sentinel: skip the setcos driver, whose APDU probe\n")
                fh.write(f"# hangs the Broadcom Corp 58200 reader for ~26s.\n{BROADCOM_WORKAROUND}\n")
            log(f"SUCCESS: {path} updated (backup at {path}.sentinel.bak).")
            log("No restart needed; the setting applies to the next card insert.")
            self.logger.info(f"Set card_drivers in {path}")
            return Outcome(
                "fix-opensc", True, f"card_drivers written to {path}",
                {"path": path, "setting": BROADCOM_WORKAROUND, "backup": f"{path}.sentinel.bak"},
            )
        except OSError as exc:
            log(f"ERROR: could not write {path}: {exc}")
            log(f"Add this line by hand: sudo sh -c 'echo \"{BROADCOM_WORKAROUND}\" >> {path}'")
            return Outcome("fix-opensc", False, str(exc), {"path": path})

    async def uninstall_certs(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Remove every anchor file Sentinel may have installed, then refresh.

        Removes the current name and the legacy names, so an upgrade-then-
        uninstall leaves no trust anchors behind.
        """
        log = lambda text: emit(Event("log", text))
        platform = self.platform
        target_dir = platform.trust_anchor_dir
        refresh_cmd = platform.trust_refresh_cmd
        if target_dir is None or not refresh_cmd:
            log(f"ERROR: {platform.name} is not a supported trust-store layout.")
            return Outcome("uninstall-certs", False, "unsupported trust store")

        targets = [
            os.path.join(target_dir, platform.trust_anchor_name),
            *[
                os.path.join(target_dir, name)
                for name in LEGACY_ANCHOR_NAMES
            ],
        ]
        present = [t for t in dict.fromkeys(targets) if os.path.exists(t)]

        if not present:
            log("No Sentinel trust anchors found; nothing to remove.")
            return Outcome("uninstall-certs", True, "nothing to remove", {"checked": targets})

        if dry_run:
            log("DRY RUN: would remove:")
            for path in present:
                log(f"  rm -f {path}")
            log(f"  then: {platform.refresh_hint()}")
            return Outcome(
                "uninstall-certs", True, "dry run",
                {"would_remove": present, "refresh": platform.refresh_hint()},
            )

        if not self._pkexec_prefix(emit):
            return Outcome("uninstall-certs", False, "pkexec unavailable")

        for path in present:
            rc, _, err = await run(["pkexec", "rm", "-f", path], timeout=POLKIT_TIMEOUT)
            if rc != 0:
                log(f"FAILURE: could not remove {path}: {err.strip() or rc}")
                return Outcome("uninstall-certs", False, err.strip() or str(rc))
            log(f"Removed {path}")

        rc, _, err = await run(["pkexec", *refresh_cmd], timeout=POLKIT_TIMEOUT)
        if rc != 0:
            log(f"WARNING: trust store refresh failed: {err.strip() or rc}")
            log(f"Run by hand: sudo {platform.refresh_hint()}")
            return Outcome("uninstall-certs", False, err.strip() or str(rc))

        log("SUCCESS: DoD trust anchors removed and trust store refreshed.")
        return Outcome("uninstall-certs", True, "removed", {"removed": present})


def _parse_slots(stdout: str) -> list[str]:
    """Extract slot labels from `pkcs11-tool -L` output.

    Returns an empty list for "no slots", which is the normal state when no card
    is inserted. Tests `Slot 0` explicitly rather than substring-matching, so
    error text mentioning a slot cannot be read as a slot being present.
    """
    labels = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Slot ") and stripped[5:6].isdigit():
            labels.append(stripped)
    return labels
