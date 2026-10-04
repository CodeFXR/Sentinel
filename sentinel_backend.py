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

# How many DoD trust anchors the shipped bundle holds. Used to check that a
# browser's trust store received all of them rather than a few.
#
# Kept as a constant rather than counted from the bundle at runtime so that a
# truncated or tampered bundle cannot quietly lower the bar it is checked
# against. `test_bundle.py` asserts it matches the committed DoD_Roots.pem, so
# the two cannot drift.
EXPECTED_ROOTS = 7

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
        #
        # Two separate facts, checked separately: is it running now, and will it
        # start again after a reboot. The old code asked only the first and then
        # remedied only the first -- `systemctl start` -- while telling the user
        # to run `systemctl enable --now` by hand. That is how a user ends up
        # being asked to do a job the tool had already been given a password for,
        # and how a card reader silently stops working after the next reboot.
        #
        # So: do both, and say plainly when there is nothing to do.
        service = self.platform.service
        active = await platform_mod.service_is_active(service)
        enabled = await platform_mod.service_is_enabled(service)
        # Whether the daemon is usable when this step finishes. Re-read at the
        # end rather than tracked by hand through the branches, so a path added
        # later cannot forget to set it.
        service_ok = False

        if active and enabled:
            log(f"OK: {service} is running and set to start at boot.")
            emit(Event("led", "led-service", "success"))
            self.logger.info(f"PCSC Service: Active and enabled")
            service_ok = True
        elif active:
            # Running, but it will not survive a reboot. Worth fixing quietly
            # rather than shouting, because the card works right now.
            log(f"OK: {service} is running, but is not set to start at boot.")
            log("     It will stop after the next restart. Fixing that now.")
            if dry_run:
                log(f"DRY RUN: would run: pkexec systemctl enable {service}")
                emit(Event("led", "led-service", "idle"))
            elif not self._pkexec_prefix(emit):
                emit(Event("led", "led-service", "error"))
            else:
                rc, _, err = await run(
                    ["pkexec", "systemctl", "enable", service],
                    timeout=POLKIT_TIMEOUT,
                )
                if rc == 0 and await platform_mod.service_is_enabled(service):
                    log(f"SUCCESS: {service} is now set to start at boot.")
                    emit(Event("led", "led-service", "success"))
                    self.logger.info(f"PCSC Service: enabled at boot")
                    service_ok = True
                else:
                    # A command that exits 0 but leaves the state unchanged is
                    # not a failure with no reason -- it is a different thing,
                    # and printing "exit 0" as the reason is the kind of
                    # sentence that teaches a user to ignore the line.
                    if rc == 0:
                        reason = (
                            "systemd accepted the command but the unit is still "
                            f"not set to start at boot (it reports "
                            f"'{await platform_mod._systemctl_state('is-enabled', service, 5.0) or 'unknown'}')"
                        )
                    else:
                        reason = err.strip() or f"exit {rc}"
                    log(f"WARNING: {service} will not start by itself: {reason}")
                    log("         It is running now, so your card works today.")
                    log("         After a restart, run this once:")
                    log(f"           sudo systemctl enable {service}")
                    # Usable right now, which is what this step measures. The
                    # reboot problem is reported but is not a failure of the
                    # card being usable today.
                    emit(Event("led", "led-service", "success"))
                    service_ok = True
                    self.logger.warning(f"PCSC Service: {reason}")
        else:
            log(f"WARN: {service} is not running.")
            if dry_run:
                log(f"DRY RUN: would run: pkexec systemctl enable --now {service}")
                emit(Event("led", "led-service", "idle"))
            elif not self._pkexec_prefix(emit):
                emit(Event("led", "led-service", "error"))
            else:
                rc, _, err = await run(
                    ["pkexec", "systemctl", "enable", "--now", service],
                    timeout=POLKIT_TIMEOUT,
                )
                if (rc == 0
                        and await platform_mod.service_is_active(service)
                        and await platform_mod.service_is_enabled(service)):
                    log(f"SUCCESS: {service} started and set to start at boot.")
                    emit(Event("led", "led-service", "success"))
                    self.logger.info(
                        f"PCSC Service: started and enabled successfully"
                    )
                    service_ok = True
                else:
                    reason = err.strip() or f"exit {rc}"
                    log(f"ERROR: could not start {service}: {reason}")
                    log(f"       If the password prompt did not appear, run this")
                    log(f"       yourself, once:")
                    log(f"         sudo systemctl enable --now {service}")
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
            # The service counts. This used to be `not missing` alone, so a
            # daemon that could not be started produced ok=True -- the LED went
            # red, the console said ERROR, and the setup verdict, which decides
            # "works / not ready" from this flag, reported the machine as fine.
            # A tool whose verdict reads one field and whose LEDs read another
            # will eventually be believed over its own lights.
            #
            # Except in a dry run, where an unfixed condition is a finding about
            # the system rather than a failure of the run. That is the rule the
            # rest of the module already follows -- "discovering that there is
            # nothing to do is a finding, not a failure" -- and it also keeps the
            # exit status a statement about this invocation rather than about
            # the machine it happened to run on.
            ok=not missing and (service_ok or dry_run),
            detail=(
                "stack probed"
                if service_ok or dry_run
                else f"{service} is not running"
            ),
            data={
                "platform": self.platform.name,
                "missing_tools": missing,
                "supported": self.platform.supported,
                "service_active": active,
                "service_enabled": enabled,
                "service_ok": service_ok,
            },
        )

    async def verify_bundle(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Check the shipped DoD roots against the shipped manifest.

        Purely a read. Nothing is installed, nothing is written, and no network
        access is attempted -- which is the point. The question this answers is
        "are the certificates on this machine the current ones?", and on a unit
        with no internet route the only way to answer it is from files already
        on the machine.

        Three things are checked, in increasing order of how much they should
        worry the reader:

        * the bundle is present and parses;
        * every certificate in it is self-signed and in date, so installing it
          cannot promote an issuing CA to a root of trust;
        * it matches DoD_Roots.manifest exactly, so nothing has been added,
          removed, or swapped since the bundle was built.

        The manifest comparison is the one that catches a *replaced* root, which
        is the case a count or an expiry check sails straight past.
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- CHECKING THE DoD CERTIFICATE BUNDLE ---")

        bundle_path = os.path.join(self.SCRIPT_DIR, TRUST_ANCHOR_NAME)
        manifest_path = os.path.join(
            self.SCRIPT_DIR, sentinel_certs.MANIFEST_NAME
        )

        if not os.path.exists(bundle_path):
            log(f"ERROR: {TRUST_ANCHOR_NAME} is missing from the installation.")
            log("       Reinstall Sentinel; the certificates ship with it.")
            self.logger.error(f"Bundle verification: {bundle_path} missing")
            emit(Event("led", "led-certs", "error"))
            return Outcome("verify-bundle", False, f"{TRUST_ANCHOR_NAME} missing")

        try:
            with open(bundle_path, encoding="utf-8", errors="replace") as fh:
                bundle_text = fh.read()
        except OSError as exc:
            log(f"ERROR: the bundle could not be read: {exc}")
            self.logger.error(f"Bundle verification: {exc}")
            emit(Event("led", "led-certs", "error"))
            return Outcome("verify-bundle", False, "bundle unreadable")

        names, problems = await asyncio.to_thread(
            sentinel_certs.verify_roots_only, bundle_text
        )
        if problems:
            log(f"FAIL: the bundle is not fit to install as trust anchors:")
            for problem in problems:
                log(f"  - {problem}")
            self.logger.error(f"Bundle verification: {len(problems)} problem(s)")
            emit(Event("led", "led-certs", "error"))
            return Outcome(
                "verify-bundle", False, f"{len(problems)} problem(s)",
                {"problems": problems},
            )

        log(f"OK: {len(names)} root certificate(s), all self-signed and in date.")
        for name in names:
            log(f"  - {name}")

        if not os.path.exists(manifest_path):
            # Not fatal, and not a failure of the certificate check above. Say
            # what is lost rather than blocking on it: without the manifest the
            # roots are still audited, they just cannot be compared to what
            # Sentinel shipped.
            log("")
            log(f"NOTE: {sentinel_certs.MANIFEST_NAME} is not present, so the")
            log("      bundle cannot be compared against the shipped one.")
            log("      The certificates above are still verified as trust anchors.")
            return Outcome(
                "verify-bundle", True, f"{len(names)} roots, no manifest",
                {"roots": names, "manifest": False},
            )

        with open(manifest_path, encoding="utf-8", errors="replace") as fh:
            manifest_text = fh.read()

        differences = await asyncio.to_thread(
            sentinel_certs.compare_to_manifest, bundle_text, manifest_text
        )
        if differences:
            log("")
            log("FAIL: the bundle does not match the one Sentinel ships:")
            for difference in differences:
                log(f"  - {difference}")
            log("")
            log("This machine's certificates differ from the release. If you did")
            log("not expect that, reinstall Sentinel from the repository.")
            self.logger.error(
                f"Bundle verification: {len(differences)} difference(s) from manifest"
            )
            emit(Event("led", "led-certs", "error"))
            return Outcome(
                "verify-bundle", False,
                f"{len(differences)} difference(s) from the shipped bundle",
                {"roots": names, "manifest": True, "differences": differences},
            )

        log("")
        log(f"OK: identical to the bundle in {sentinel_certs.MANIFEST_NAME}.")
        log("    These are the current DoD trust anchors for this release.")
        self.logger.info(
            f"Bundle verification: {len(names)} roots, all match the manifest"
        )
        emit(Event("led", "led-certs", "success"))
        return Outcome(
            "verify-bundle", True, f"{len(names)} roots verified",
            {"roots": names, "manifest": True, "differences": []},
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
            # Scoped, because the previous wording was a claim about every
            # browser made from one host-wide measurement. A snap or Flatpak
            # browser cannot see the host's p11-kit at all, so "browsers reach
            # the card through it already" was false for exactly the browser a
            # user is most likely to be staring at -- and it was printed on the
            # same run that then showed that browser as sandboxed, which is a
            # self-contradiction nobody would act on.
            log("PKCS#11 access: p11-kit is exposing a CAC to the host.")
            log("              Browsers that are not sandboxed use it directly,")
            log("              so Sentinel will not register OpenSC a second time.")
            log("              A sandboxed browser cannot: it is cut off from the")
            log("              host entirely, including p11-kit and pcscd.")
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
                    log(f"  -> roots written, but: {reason}")
                else:
                    log("  -> verified: all DoD roots present.")
                # Worth showing, worth failing over: not. See _p11_kit_registered.
                if p11_kit and modutil:
                    present, _ = await self._p11_kit_registered(modutil, db_path)
                    if not present:
                        log("     Note: this browser keeps no p11-kit entry of its own.")
                        log("     That is normal for Chrome and Chromium, which use the")
                        log("     system p11-kit directly. Nothing to do.")
                # A Firefox profile also has to be told to *offer* the card.
                # Roots in the trust store only let the browser validate the
                # server; whether it asks the user to pick a client certificate
                # is a separate setting, and left at the default Firefox picks
                # one itself. A CAC site asking for a client certificate then
                # gets nothing, and the symptom -- a site that never prompts --
                # is indistinguishable from a card that cannot be read.
                if os.path.isfile(os.path.join(db_path, "cert9.db")) and \
                        not db_path.endswith(os.path.join(".pki", "nssdb")):
                    asked, why = sentinel_browser.set_firefox_asks_every_time(db_path)
                    if asked:
                        log("     Set to ask which certificate to use on every request.")
                    elif not dry_run:
                        log(f"     WARNING: could not set the certificate preference: {why}")
                        self.logger.warning(
                            f"Browser config {db_path}: ask-every-time not set: {why}"
                        )
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

        # --- can each browser actually reach the card? ------------------------
        # Everything above proves the DoD roots are in a database. Nothing above
        # proves a browser can read the card, and conflating the two is how this
        # step produced a green light on a machine where the browser in use could
        # not see a CAC at all.
        unreachable = [b for b in browsers if b.confined]
        unconfigured = sentinel_browser.installed_browsers_without_profile()

        if unreachable:
            for browser in unreachable:
                log("")
                log(f"!! {browser.name} CANNOT use your smart card.")
                for line in sentinel_browser.guidance_for(browser).splitlines():
                    log(f"   {line}")

        if unconfigured:
            # The field case. The log showed only ~/.pki/nssdb on every run while
            # the browser the user actually launches was never touched, and the
            # step reported success. A browser with no profile has not been
            # configured; it is not configured, and saying nothing about it is
            # what made the green light meaningless.
            log("")
            log("These browsers are installed but were NOT configured:")
            for label in unconfigured:
                log(f"   - {label}")
            log("They have never been started, so they have no profile for Sentinel")
            log("to write to. Start the one you use, then run CONFIG BROWSERS again.")

        # A green LED is only earned when a browser that is not sandboxed can
        # reach the card. It says "a browser can use your card", not "a file was
        # written" -- and the two came apart on the machine that prompted this.
        usable = [b for b in browsers if not b.confined and b.nss_databases]
        if not usable:
            for browser in unreachable:
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
                {"succeeded": succeeded, "confined": [b.name for b in unreachable],
                 "unconfigured": unconfigured,
                 "guidance": [sentinel_browser.guidance_for(b) for b in unreachable]},
            )

        # Every database was written, but at least one browser Sentinel knows
        # about cannot use the card, and a browser it never saw has not been
        # configured at all. Reporting plain success there is the false green.
        blocked = bool(unreachable or unconfigured)

        if blocked:
            log("")
            log("The DoD roots are installed, but this is NOT a working setup yet:")
            for browser in unreachable:
                log(f"  - {browser.name} is sandboxed and cannot read the card.")
            for label in unconfigured:
                log(f"  - {label} is installed but has never been started, so it")
                log("    has no profile and was not configured.")
            log("")
            log("Fix the items above, then run CONFIG BROWSERS again.")
            self.logger.warning(
                f"Browser configuration: roots written but {len(unreachable)} "
                f"sandboxed browser(s) and {len(unconfigured)} unconfigured "
                f"browser(s)"
            )
            emit(Event("led", "led-browsers", "error"))
            return Outcome(
                "configure-browsers", False,
                f"roots written, but {len(unreachable) + len(unconfigured)} "
                f"browser(s) cannot use the card",
                {"succeeded": succeeded, "failed": failed,
                 "browsers_running": running,
                 "confined": [b.name for b in unreachable],
                 "unconfigured": unconfigured,
                 "p11_kit": p11_kit, "card_present": card_present,
                 "card_detail": card_detail},
            )

        # Green only on the strength of a post-write verification against a
        # browser that is not sandboxed, and with nothing known to be blocking.
        log("Close and restart browsers to apply.")
        emit(Event("led", "led-browsers", "success"))
        return Outcome(
            "configure-browsers", not failed, f"{len(succeeded)}/{len(nss_paths)} configured",
            {"succeeded": succeeded, "failed": failed, "browsers_running": running,
             "confined": [], "unconfigured": [], "p11_kit": p11_kit,
             "card_present": card_present, "card_detail": card_detail},
        )

    async def _configure_one(
        self, modutil, certutil, lib_path, bundle, db_path, have_bundle,
        register_module: bool = True,
    ) -> tuple[bool, str]:
        """Make one NSS database ready to use the card, then verify it.

        `register_module=False` is the p11-kit case, and the important property
        of that branch is what it does *not* require.

        An earlier version demanded that `p11-kit-proxy.so` be registered inside
        the browser's own NSS database, and treated its absence as a failure. On a
        Zorin OS 18.1 laptop that reported a working configuration as broken:

            p11-kit present: True; card visible to p11-kit: True
            p11-kit-proxy is not registered in this browser's database

        The check was simply wrong. Chromium on Linux does not reach a smart card
        through an entry in its own `~/.pki/nssdb`; it goes through the system
        p11-kit client library, so no such entry is ever written. Firefox on some
        builds does keep one. Requiring it is asking for a file that the program
        in question does not use.

        It was also harmful in a second way: this function returned before the
        certificate import, so a false failure meant the DoD roots were never
        added to the browser at all.

        So the p11-kit branch no longer inspects the database for a module. What
        p11-kit exposes system-wide is the authority on whether the card is
        reachable, and that was measured once, before this loop, in
        `configure_browsers`. The only work left here is importing the roots,
        which is done unconditionally and verified.

        Returns (ok, reason); reason is empty on success.
        """
        try:
            if register_module:
                module_ok, reason = await self._register_module(
                    modutil, lib_path, db_path
                )
                if not module_ok:
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
            elif certutil and have_bundle:
                # On the p11-kit path the module needs no database entry, so the
                # roots are the only thing that can be verified -- and they are
                # what a CAC site actually depends on.
                if not await self._roots_present(certutil, db_path):
                    return False, (
                        "the DoD roots are still not in this browser's trust "
                        "store after writing them"
                    )
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

    async def _roots_present(self, certutil, db_path) -> bool:
        """True when the DoD roots are actually in this browser's trust store.

        Read back from the database rather than inferred from certutil's exit
        code, because certutil reports a failed import on a partially successful
        run and because the count is the thing that matters: a browser holding
        one of seven roots fails in a way that looks like a server problem.
        """
        rc, stdout, _ = await run(
            [certutil, "-d", f"sql:{db_path}", "-L"], timeout=NSS_TIMEOUT,
        )
        if rc != 0:
            return False
        return stdout.count("C,,") >= EXPECTED_ROOTS

    async def _p11_kit_registered(self, modutil, db_path) -> tuple[bool, str]:
        """Is p11-kit-proxy registered in this database? Informational only.

        Not a pass/fail gate any more, and the docstring says why, because the
        previous version of this was the bug reported from Zorin OS.

        A browser on a p11-kit system may or may not keep a `p11-kit-proxy`
        entry in its own NSS database, and neither case says anything about
        whether it can reach the card: Chromium does not use that entry at all,
        going to the system p11-kit client library instead. The answerable
        question is what p11-kit exposes system-wide, which `configure_browsers`
        asks once via `p11_kit_exposes_card`.

        Kept because the answer is worth showing: on a machine where it is
        absent, a user who then removes p11-kit will find the browser can no
        longer reach the card, and nothing else would have told them.
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

    async def diagnose_browser(self, emit: Emit, dry_run: bool = False) -> Outcome:
        """Answer the only question that matters: will this browser offer my card?

        Everything else this tool reports is a fact about a file or a service.
        The question a user actually has is whether their browser will ask them
        to pick a certificate on a CAC site, and that has four separate
        preconditions. Each is checked here and reported by name, so the answer
        is a list rather than a light:

        1. The card is readable at all -- by the host's p11-kit.
        2. The browser is not sandboxed. A snap or Flatpak browser cannot see
           the host's p11-kit or its pcscd, whatever the host can see.
        3. The browser has a profile Sentinel can see. A browser that has never
           been started has none, and was never configured.
        4. Firefox is set to ask which certificate to use. Left at the default it
           picks one itself, and a CAC site that never prompts looks exactly
           like a card that cannot be read.

        Read-only. No writes, no privileges, no network. This is the command to
        run when the setup says green and the browser still does nothing, and it
        is written for that moment specifically.
        """
        log = lambda text: emit(Event("log", text))
        log("\n--- WILL MY BROWSER OFFER MY CARD? ---")
        self.logger.info("Browser card-access diagnostic")

        problems: list[str] = []

        # 1. The card, as the host sees it.
        card, detail = platform_mod.p11_kit_exposes_card()
        if card:
            log("1. Card readable by the host .......... YES")
        else:
            log(f"1. Card readable by the host .......... NO")
            log(f"     {detail}.")
            problems.append(
                "The card is not readable. Insert it, and if it still is not, "
                "run 'sentinel doctor'."
            )

        # 2 and 3. Which browsers exist, and which of them can reach the card.
        browsers = sentinel_browser.inventory()
        log("")
        log("2. Browsers found:")
        if not browsers:
            log("     (none that Sentinel recognises)")
        for browser in browsers:
            if browser.confined:
                verdict = "SANDBOXED -- cannot reach the card"
                problems.append(
                    f"{browser.name} is sandboxed and cannot read a smart card. "
                    "Install it from your distribution's software centre instead."
                )
            elif not browser.nss_databases:
                verdict = "installed, but never started"
                problems.append(
                    f"{browser.name} has never been started, so it has no profile "
                    "and was not configured. Start it, then run CONFIG BROWSERS."
                )
            else:
                verdict = "not sandboxed -- can reach the card"
            log(f"     - {browser.name}: {verdict}")
            log(f"       {browser.detail}")

        unconfigured = sentinel_browser.installed_browsers_without_profile()
        if unconfigured:
            log("")
            log("3. Installed but never started (not configured):")
            for label in unconfigured:
                log(f"     - {label}")
            problems.append(
                "Started no profile for: " + ", ".join(unconfigured)
                + ". Start the browser you use, then run CONFIG BROWSERS again."
            )
        else:
            log("")
            log("3. Installed but never started ......... none")

        # 4. Firefox certificate selection, per profile.
        profiles = [
            path for browser in browsers
            for path in browser.nss_databases
            if os.path.basename(os.path.dirname(path)) in ("firefox",)
            or "firefox" in path
        ]
        log("")
        log("4. Firefox set to ask which certificate to use:")
        if not profiles:
            log("     (no Firefox profile found)")
        for profile in profiles:
            if sentinel_browser.firefox_asks_every_time(profile):
                log(f"     - {os.path.basename(profile)}: YES")
            else:
                log(f"     - {os.path.basename(profile)}: NO")
                problems.append(
                    f"Firefox profile {os.path.basename(profile)} is not set to "
                    "'Ask me every time'. Run CONFIG BROWSERS to set it, or set it "
                    "in Preferences > Privacy & Security > Certificates."
                )

        log("")
        if not problems:
            log("Everything checks out. Your browser should offer your CAC when a")
            log("site asks for one.")
            self.logger.info("Browser diagnostic: all checks passed")
            emit(Event("led", "led-browsers", "success"))
            return Outcome("diagnose-browser", True, "browser can offer the card",
                           {"problems": [], "card_present": card})

        log(f"{len(problems)} thing(s) to fix, in the order they matter:")
        for index, problem in enumerate(problems, 1):
            log(f"  {index}. {problem}")
        self.logger.warning(
            f"Browser diagnostic: {len(problems)} problem(s): {'; '.join(problems)}"
        )
        emit(Event("led", "led-browsers", "error"))
        return Outcome("diagnose-browser", False, f"{len(problems)} problem(s)",
                       {"problems": problems, "card_present": card,
                        "card_detail": detail})

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
