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
import re
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

# The name p11-kit registers itself under in an NSS database. Not the same as
# the library filename: NSS stores the module as "p11-kit-proxy" and the file it
# loads as "p11-kit-proxy.so", and only the former is the module's identity.
P11_KIT_MODULE_NAME = "p11-kit-proxy"


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

    stdin is /dev/null, and that is load-bearing rather than tidiness.
    `modutil -add` is interactive: it prints "Type 'q' to abort, or <enter> to
    continue" and then blocks on a read. Inheriting the terminal made Sentinel
    appear to hang at "Updating: ..." waiting for a keystroke the user has no
    reason to know about, with no prompt visible in the console the tool is
    printing to. modutil reads EOF as "continue" and does the work, so closing
    stdin is both safe and the difference between a tool that runs unattended
    and one that appears broken.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
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
        """Get every NSS database the user has ready to use a CAC.

        Two jobs, and which one applies depends on the machine:

        1. Make the DoD roots trusted. Always done, on every database. This is
           the part the browser genuinely needs from Sentinel.
        2. Make the card reachable. Usually a no-op, because p11-kit already
           brokers OpenSC into the browser through `p11-kit-proxy.so`. Only on a
           machine without p11-kit does this mean writing a PKCS#11 module
           entry by hand with modutil.

        Getting (2) wrong is what made this step report failure on working
        machines. See the p11-kit note in sentinel_platform for the full
        mechanism; the short version is that a manual `modutil -add` of
        opensc-pkcs11.so duplicates what p11-kit has already registered, NSS
        refuses the duplicate, and the browser -- which was never broken -- gets
        reported as unconfigured.
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- CONFIGURING BROWSERS (NSS DB) ---")
        self.logger.info("Starting browser configuration")
        emit(Event("led", "led-browsers", "loading"))

        modutil = shutil.which("modutil")
        lib_path = self.platform.pkcs11_module
        certutil = shutil.which("certutil")

        if not certutil:
            log("WARNING: 'certutil' not found; the DoD roots cannot be imported")
            log("         into the browsers, so CAC sites may still be refused.")
            log(f"Fix with: sudo {self.platform.install_hint()}")

        # What is installed, and can each of them actually reach the card.
        # Reported before any write, because a sandboxed browser cannot be
        # fixed by writing to its NSS database.
        browsers = sentinel_browser.inventory()
        confined = [b for b in browsers if b.confined and b.nss_databases]
        for browser in browsers:
            log(f"Browser: {browser.name} -- {browser.detail}")

        # Ask p11-kit before doing anything. It decides whether the manual
        # module registration below is needed at all.
        p11_kit = platform_mod.p11_kit_present()
        card_present, card_detail = platform_mod.p11_kit_exposes_card()
        self.logger.info(
            f"p11-kit present: {p11_kit}; card visible to p11-kit: {card_present} "
            f"({card_detail})"
        )

        if p11_kit:
            log("PKCS#11 access: provided by p11-kit (p11-kit-proxy.so).")
            log("              Browsers reach the card through it already, so")
            log("              Sentinel will not register OpenSC a second time.")
        else:
            log("PKCS#11 access: p11-kit is not installed, so the OpenSC module")
            log("              has to be registered in each browser by hand.")

        if not card_present:
            # This is the popup case. A CAC that is not in the reader cannot be
            # shown working, and the two reasons need different fixes, so the
            # detail travels with the event.
            log("")
            log(f"NOTE: {card_detail}.")
            log("      A CAC has to be in the reader for the browser to offer it.")
            emit(Event("card-prompt", card_detail))

        nss_paths = nss_databases()
        if lib_path:
            log(f"Module:  {lib_path}")
        log(f"Found {len(nss_paths)} NSS database(s).")

        # Checked before the dry run returns, because a dry run that plans a step
        # it cannot perform has failed at the only job it has. Without p11-kit
        # these two binaries are the whole mechanism, so their absence is a real
        # blocker rather than something to discover halfway through.
        if not p11_kit:
            if not modutil:
                log("ERROR: 'modutil' not found (package nss-tools / libnss3-tools).")
                log("       Without p11-kit and without modutil there is no way to")
                log("       register the card module in your browser.")
                log(f"Fix with: sudo {self.platform.install_hint()}")
                self.logger.error("Browser configuration: modutil not found")
                emit(Event("led", "led-browsers", "error"))
                return Outcome("configure-browsers", False, "modutil not found")
            if not lib_path:
                log("ERROR: opensc-pkcs11.so not found. Install OpenSC first.")
                log(f"Fix with: sudo {self.platform.install_hint()}")
                self.logger.error("Browser configuration: opensc-pkcs11.so not found")
                emit(Event("led", "led-browsers", "error"))
                return Outcome(
                    "configure-browsers", False, "opensc-pkcs11.so not found"
                )

        if dry_run:
            # A dry run reports the plan. Discovering that there is nothing to
            # do is a finding about the system, not a failure of the run.
            if not nss_paths:
                log("No NSS databases found. Install a browser, then retry.")
            else:
                for db_path in nss_paths:
                    log(f"Would update: {db_path}")
            if p11_kit:
                log("Would import the DoD roots into each. No module to add.")
            else:
                log("Would add the OpenSC module and import the DoD roots into each.")
            emit(Event("led", "led-browsers", "idle"))
            return Outcome(
                "configure-browsers", True, "dry run",
                {
                    "module": lib_path,
                    "databases": nss_paths,
                    "p11_kit": p11_kit,
                    "card_present": card_present,
                    "card_detail": card_detail,
                    "browsers_running": platform_mod.browsers_running(),
                },
            )

        if not nss_paths:
            log("No browser with an NSS database was found.")
            log("Install Firefox or Chrome from your distribution's packages,")
            log("then run CONFIG BROWSERS again.")
            self.logger.error("Browser configuration: no NSS databases found")
            emit(Event("led", "led-browsers", "error"))
            return Outcome(
                "configure-browsers", False, "no NSS databases found",
                {"p11_kit": p11_kit, "card_present": card_present,
                 "card_detail": card_detail},
            )

        # modutil and the OpenSC path are checked above, before the dry run
        # returns, because they are only required when p11-kit is absent.
        running = platform_mod.browsers_running()
        if running:
            # Firefox rewrites prefs.json on exit and discards the change.
            log(f"WARNING: {', '.join(running)} is running.")
            log("         Firefox rewrites its profile on exit and will discard")
            log("         this change. Close it, re-run CONFIG BROWSERS, restart it.")

        bundle = os.path.join(self.SCRIPT_DIR, TRUST_ANCHOR_NAME)
        have_bundle = os.path.exists(bundle)
        if not have_bundle:
            self.logger.warning(
                f"Trust bundle {TRUST_ANCHOR_NAME} not found next to the source; "
                "certificates cannot be imported into the browsers"
            )

        succeeded: list[str] = []
        failed: list[dict] = []

        for db_path in nss_paths:
            # A Chromium database that does not exist yet is created here rather
            # than refused earlier. modutil cannot create the directory itself
            # -- it exits 46 with SEC_ERROR_BAD_DATABASE -- so this has to
            # happen before the first modutil call, not inside it.
            if not os.path.isdir(db_path):
                if platform_mod.ensure_nss_directory(db_path):
                    log(f"Created {db_path}")
                    self.logger.info(f"Created NSS database directory {db_path}")
                else:
                    reason = f"could not create the directory {db_path}"
                    log(f"Updating: {db_path}...")
                    log(f"  -> FAILED: {reason}")
                    self.logger.error(f"Browser config {db_path}: {reason}")
                    failed.append({"database": db_path, "error": reason})
                    continue

            log(f"Updating: {db_path}...")
            self.logger.info(f"Browser config: {db_path}")
            ok, reason = await self._configure_one(
                modutil, certutil, lib_path, bundle, db_path, have_bundle,
                register_module=not p11_kit,
            )
            if ok:
                # The reason is not decoration. `_configure_one` reports a partial
                # result by returning ok=True with a reason, and the old code
                # printed "roots imported" on the strength of ok alone -- so a
                # certificate import that had failed in every single run was
                # reported to the user as a success, in the one message they were
                # most likely to believe.
                if reason:
                    log(f"  -> card module ready, but: {reason}")
                else:
                    log("  -> verified: card module available and roots imported.")
                succeeded.append(db_path)
            else:
                log(f"  -> FAILED: {reason}")
                # The reason goes to the log file as well as the console. A user
                # who reports "browser config failed" from the field can only be
                # helped if the reason is somewhere they can send.
                self.logger.error(f"Browser config {db_path} failed: {reason}")
                failed.append({"database": db_path, "error": reason})

        if not succeeded:
            log(f"FAILED: none of the {len(nss_paths)} database(s) could be configured.")
            self.logger.error(
                f"Browser configuration: no database succeeded "
                f"({len(failed)} failure(s): "
                f"{'; '.join(f['error'] for f in failed) or 'no databases'})"
            )
            emit(Event("led", "led-browsers", "error"))
            return Outcome(
                "configure-browsers", False, "no database configured",
                {"databases": nss_paths, "failures": failed,
                 "p11_kit": p11_kit, "card_present": card_present,
                 "card_detail": card_detail},
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
             "confined": [b.name for b in confined], "p11_kit": p11_kit,
             "card_present": card_present, "card_detail": card_detail},
        )

    async def _configure_one(
        self, modutil, certutil, lib_path, bundle, db_path, have_bundle,
        register_module: bool = True,
    ) -> tuple[bool, str]:
        """Make one NSS database ready to use the card, then verify it.

        `register_module=False` is the p11-kit case. The database already has
        `p11-kit-proxy.so` registered and loaded, and that proxy is what gives
        the browser the card, so the only work left is importing the DoD roots.
        Adding an opensc-pkcs11.so entry here would duplicate p11-kit's own
        registration, which NSS rejects.

        Either way the result is verified by reading the database back, not by
        trusting an exit code. Returns (ok, reason); reason is empty on success.
        """
        try:
            if register_module:
                module_ok, reason = await self._register_module(
                    modutil, lib_path, db_path
                )
                if not module_ok:
                    return False, reason
            else:
                present, reason = await self._p11_kit_registered(modutil, db_path)
                if not present:
                    return False, reason

            imported, import_reason = 0, ""
            if certutil and have_bundle:
                imported, import_reason = await self._import_roots(certutil, bundle, db_path)
                if not imported:
                    # Not fatal for the card: the module is what makes the card
                    # appear, and that part is done. But it is fatal for actually
                    # reaching a CAC site, so it is reported as a partial result
                    # rather than being folded into a success.
                    self.logger.error(
                        f"Browser config {db_path}: {import_reason}"
                    )

            # Verify by reading back rather than trusting the exit code.
            if register_module:
                rc, stdout, _ = await run(
                    [modutil, "-dbdir", f"sql:{db_path}", "-list", MODULE_NAME],
                    timeout=NSS_TIMEOUT,
                )
                if rc != 0 or MODULE_NAME not in stdout:
                    return False, "module absent after write"
            else:
                present, reason = await self._p11_kit_registered(modutil, db_path)
                if not present:
                    return False, f"p11-kit proxy not usable after write: {reason}"
            return True, import_reason
        except Exception as exc:  # defensive: one bad profile must not stop the rest
            return False, str(exc)

    async def _import_roots(self, certutil, bundle, db_path) -> tuple[int, str]:
        """Import every DoD root from the bundle into one NSS database.

        Returns (count_imported, reason); reason is empty on a clean import.

        Two things were wrong here, and both failed silently.

        The command was `certutil -N -d <db> -A -n ... -i <bundle>`. certutil
        accepts exactly one command per invocation and rejects that outright:

            certutil: only one command at a time!
            You entered:  -A -N

        So the import never happened, on any machine, ever. `-N` creates a new
        empty database and is not needed at all: `-A` initialises the database
        files itself when the directory is empty.

        And all seven roots were being imported under one nickname,
        "DoD Root CAs". NSS treats the nickname as a key, so the first import
        succeeds and the rest fail with SEC_ERROR_ADDING_CERT. One of seven DoD
        roots reached the browser and the other six were silently dropped, which
        is enough to make some CAC sites work and others fail in a way that
        looks like a server problem.

        So each certificate is imported separately, under a nickname derived from
        its own common name, and the number that actually landed is counted and
        returned rather than assumed.
        """
        try:
            with open(bundle, encoding="utf-8", errors="replace") as fh:
                pems = sentinel_certs.split_pem(fh.read())
        except OSError as exc:
            return 0, f"the trust bundle could not be read: {exc}"

        if not pems:
            return 0, "the trust bundle contains no certificates"

        imported = 0
        problems: list[str] = []
        for index, pem in enumerate(pems):
            nickname = await asyncio.to_thread(self._root_nickname, pem, index)
            path = os.path.join(
                self.SCRIPT_DIR, f".sentinel-root-{os.getpid()}-{index}.pem"
            )
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(pem if pem.endswith("\n") else pem + "\n")
                rc, _, err = await run(
                    [certutil, "-d", f"sql:{db_path}", "-A",
                     "-n", nickname, "-t", "C,,", "-i", path],
                    timeout=NSS_TIMEOUT,
                )
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            if rc == 0:
                imported += 1
            else:
                problems.append(f"{nickname} ({err.strip() or f'exit {rc}'})")

        if imported == len(pems):
            return imported, ""
        return imported, (
            f"only {imported} of {len(pems)} DoD roots could be added to this "
            f"browser: {'; '.join(problems)}"
        )

    def _root_nickname(self, pem: str, index: int) -> str:
        """A unique nickname for one root certificate.

        The common name is used because it is unique across the DoD bundle --
        "DoD Root CA 2" through "DoD Root CA 5" plus the ECA and WCF roots --
        and it is what a person recognises in Firefox's certificate manager. The
        index is appended as a backstop so two roots with a shared common name
        cannot collide into the same failure this method exists to prevent.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as workdir:
            name = sentinel_certs.common_name(pem, workdir, "root.pem")
        safe = re.sub(r"[^A-Za-z0-9 ._-]", "", name).strip() or "DoD Root"
        return f"{safe} [{index + 1}]" if safe else f"DoD Root {index + 1}"

    async def _p11_kit_registered(self, modutil, db_path) -> tuple[bool, str]:
        """Is p11-kit-proxy registered and loaded in this database?

        That is the state that means "this browser can reach the card". If p11-kit
        is installed system-wide but the proxy is somehow missing from the
        browser's own database, the browser still cannot see the card, so this
        is checked rather than assumed from p11-kit being installed.

        The whole module list has to be read and searched, rather than asking
        `modutil -list <name>`. p11-kit registers itself as an NSS *security
        module*, which NSS stores in secmod.db, not in the pkcs11.txt that
        `modutil -add` writes. `modutil -list p11-kit-proxy` therefore answers
        "not found in database" for a database where the proxy is present and
        loaded -- which is every working browser on a p11-kit system. Asking the
        wrong question here reported a perfectly good browser as broken.

        Both the name and `status: loaded` are required. A registered-but-not
        loaded proxy is exactly the failure the original module existed to catch,
        so its absence of a loaded status has to be treated as a failure.
        """
        if not modutil:
            return False, "modutil is not installed, so the database cannot be checked"
        rc, stdout, _ = await run(
            [modutil, "-dbdir", f"sql:{db_path}", "-list"],
            timeout=NSS_TIMEOUT,
        )
        if rc != 0:
            return False, f"the database could not be read (modutil exit {rc})"
        if P11_KIT_MODULE_NAME not in stdout:
            return False, (
                f"{P11_KIT_MODULE_NAME} is not registered in this browser's "
                "database, so the browser cannot reach the card through p11-kit"
            )
        # Confirm it is the entry that is loaded, not merely mentioned: the name
        # also appears on the `library name:` line of the same block.
        for block in _module_blocks(stdout):
            if P11_KIT_MODULE_NAME in block and "status: loaded" in block:
                return True, ""
        return False, (
            f"{P11_KIT_MODULE_NAME} is registered but not loaded, so the browser "
            "cannot use it; restarting p11-kit or the browser usually fixes this"
        )

    async def _register_module(self, modutil, lib_path, db_path) -> tuple[bool, str]:
        """Write an OpenSC module entry into one database, the pre-p11-kit way.

        Kept because it is still the only option on a machine with no p11-kit,
        and because it is the fix for a browser whose proxy entry is broken.
        """
        rc, stdout, _ = await run(
            [modutil, "-dbdir", f"sql:{db_path}", "-list", MODULE_NAME],
            timeout=NSS_TIMEOUT,
        )
        already_ok = rc == 0 and MODULE_NAME in stdout and lib_path in stdout
        if already_ok:
            return True, ""

        rc, _, err = await run(
            [modutil, "-force", "-dbdir", f"sql:{db_path}",
             "-add", MODULE_NAME, "-libfile", lib_path],
            timeout=NSS_TIMEOUT,
        )
        if rc != 0:
            return False, _explain_add_failure(err, stdout)
        return True, ""

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


def _module_blocks(listing: str) -> list[str]:
    """Split `modutil -list` output into one block of text per module.

    modutil prints each module as an indented header followed by its details and
    slots, with no terminator, so "is this module loaded" cannot be answered by
    searching the whole output: the name of one module and the status of another
    can both be present, and a naive search pairs them. Splitting on the module
    headers keeps each module's own status with its own name.

    A header is a line whose first non-space character is a digit and whose
    second token is a period, which is the shape modutil uses:

        1. NSS Internal PKCS #11 Module
        2. p11-kit-proxy
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in listing.splitlines():
        stripped = line.strip()
        is_header = bool(
            stripped
            and stripped[0].isdigit()
            and len(stripped) > 1
            and stripped[1] == "."
        )
        if is_header and current:
            blocks.append("\n".join(current))
            current = []
        current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _explain_add_failure(stderr: str, stdout: str = "") -> str:
    """Turn an NSS failure into something the user can act on.

    NSS reports a refused module as

        ERROR: Failed to add module "DoD CAC". Probable cause : "Unknown PKCS #11 error".

    which names neither the library, the path, nor the reason, and appears
    identically whether the library is missing, unloadable, or already
    registered by something else. Surfacing that string verbatim is how a field
    failure became undiagnosable, so the known cases are translated and
    anything unrecognised is passed through with its exit status rather than
    being flattened into "exit 22".

    The p11-kit collision is the important one: it is the expected outcome of
    following the manual instructions on a modern distribution, so a user who
    hits it needs to be told the browser is fine, not that the tool failed.
    """
    combined = f"{stdout}\n{stderr}"
    detail = stderr.strip() or stdout.strip()

    if "p11-kit is enabled" in combined or "duplicate module registration" in combined:
        return (
            "p11-kit has already registered the card module for this browser, so "
            "there is nothing to add -- the browser can reach the card as it is. "
            "See the p11-kit line in the output above."
        )
    if "cannot open shared object file" in combined:
        return (
            "the OpenSC PKCS#11 module could not be opened. OpenSC is probably "
            "not installed; run the install step, or check the module path."
        )
    if "already exists" in combined or "already in use" in combined:
        return "a module with that name is already registered under a different path."

    if "Unknown PKCS #11 error" in combined:
        return (
            f"NSS refused the module without giving a reason ({detail or 'exit 22'}). "
            "This is what NSS reports when the module will not initialise -- most "
            "often because the smart card daemon is not running or the reader is "
            "not responding. Run 'sentinel doctor' to see which."
        )
    return detail or "modutil -add failed with no message"


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
