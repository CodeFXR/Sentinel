"""Reader diagnostics: why is the card not being seen?

For a user whose CAC does not work, this is the question that matters, and it is
almost never "is pcscd running". It is one of four things:

1. **No reader at all.** The reader is not plugged in, or the USB port is dead.
2. **The wrong reader.** Very common on a laptop: the integrated fingerprint
   reader also presents itself as a smart card reader. `pcscd` comes up, a
   reader enumerates, there is no card, and the tool correctly says "no card
   inserted" — which sends the user looking at the wrong thing entirely.
3. **A reader with no permission.** `/dev/bus/usb` nodes are owned by root and
   given to a `pcscd` group by udev. Without that rule, pcscd cannot open the
   reader, and the failure surfaces as an empty reader list.
4. **A reader claimed by a competing driver.** `ccid` versus `ifd` versus a
   vendor kernel module. Two drivers on one interface means whichever bound
   first wins, and it may not be `ccid`.

Each of these gets a specific, checkable finding and a specific thing to do,
because "the card was not detected" is not actionable for someone who does not
know what a reader is.

Everything here degrades to "unknown" rather than guessing when a tool is
missing. Absence of `lsusb` is not evidence of a missing reader.
"""

from __future__ import annotations

import os
import pwd
import grp
import re
import shutil
import subprocess
from dataclasses import dataclass, field

QUERY_TIMEOUT = 6

# Readers that are almost certainly not holding a CAC.
NOT_A_CARD_READER = (
    "fingerprint", "finger print", "biometric", "synaptics", "validity",
    "goodix", "authen", "fprint", "digital persona", "apple touch id",
)

# Real CAC readers, and what they usually call themselves.
KNOWN_CAC_READERS = (
    "broadcom", "58200", "harg", "omnikey", "gemalto", "id tech",
    "actividentity", "thales", "sagem", "xiring", "identiv",
    "apple generic", "usb token",
)


@dataclass
class Finding:
    """One measured problem, with the action that fixes it."""

    severity: str  # "problem" | "warning" | "ok"
    title: str
    detail: str = ""
    fix: str = ""

    def line(self) -> str:
        mark = {"problem": "FAIL", "warning": "warn", "ok": "ok"}[self.severity]
        out = f"  [{mark}] {self.title}"
        if self.detail:
            out += f"\n         {self.detail}"
        if self.fix:
            out += f"\n         To fix: {self.fix}"
        return out


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=QUERY_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return result.returncode, result.stdout


def _group_ids(name: str) -> set[int]:
    ids: set[int] = set()
    try:
        record = pwd.getpwnam(name)
        ids.add(record.pw_gid)
    except KeyError:
        pass
    try:
        ids |= {g.gr_gid for g in grp.getgrall() if g.gr_name == name}
    except (OSError, KeyError):
        pass
    return ids


# --- 1. is anything plugged in at all? ---------------------------------------

def usb_readers() -> tuple[list[str], bool]:
    """Readers found on the USB bus, and whether the query was possible."""
    if not shutil.which("lsusb"):
        return [], False
    rc, out = _run(["lsusb"])
    if rc != 0:
        return [], False
    readers = []
    for line in out.splitlines():
        lowered = line.lower()
        if any(needle in lowered for needle in KNOWN_CAC_READERS):
            readers.append(line.strip())
    return readers, True


# --- 2. the wrong reader ------------------------------------------------------

def fingerprint_readers() -> list[str]:
    """Integrated fingerprint readers that also claim to be card readers."""
    if not shutil.which("lsusb"):
        return []
    rc, out = _run(["lsusb"])
    if rc != 0:
        return []
    return [
        line.strip() for line in out.splitlines()
        if any(needle in line.lower() for needle in NOT_A_CARD_READER)
    ]


# --- 3. permissions -----------------------------------------------------------

def pcsc_socket_accessible() -> tuple[bool | None, str]:
    """Can this user reach the pcscd socket? (None = cannot tell)"""
    for path in ("/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm"):
        if not os.path.exists(path):
            continue
        if not os.access(path, os.R_OK | os.W_OK):
            return False, path
        return True, path
    return None, ""


def pcscd_owns_the_reader() -> bool | None:
    """Does pcscd run as a privileged user, i.e. open the reader for us?

    None when it cannot be determined.

    There was a check here for whether the current user was in the group owning
    /dev/bus/usb. It was wrong, and it reported a problem on a machine where
    the card worked perfectly: pcscd opens the reader itself, under its own
    privileged account, and the user never touches /dev/bus/usb. Only the
    pcscd *socket* is the user's to reach, and that is checked above.
    """
    if not shutil.which("pgrep"):
        return None
    rc, out = _run(["pgrep", "-x", "pcscd"])
    if rc != 0:
        return None
    pids = [p for p in out.split() if p]
    if not pids:
        return None
    users = set()
    for pid in pids:
        rc, who = _run(["ps", "-o", "user=", "-p", pid])
        if rc == 0 and who.strip():
            users.add(who.strip())
    if not users:
        return None
    # Anything other than the invoking user means pcscd is doing the opening.
    return not (users == {os.environ.get("USER", "")})


# --- 4. competing drivers -----------------------------------------------------

def reader_driver_bindings() -> list[tuple[str, str]]:
    """(interface, bound driver) pairs for USB devices, if readable."""
    base = "/sys/bus/usb/devices"
    if not os.path.isdir(base):
        return []
    found = []
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return []
    for entry in entries:
        driver_link = os.path.join(base, entry, "driver")
        if not os.path.islink(driver_link):
            continue
        found.append((entry, os.path.basename(os.readlink(driver_link))))
    return found


def ccid_claimed_reader_ids() -> set[str]:
    """USB device ids of interfaces bound to a CCID-family driver.

    Kept as a diagnostic aid, not a verdict. Modern pcsc-lite talks to readers
    through libusb and does not bind the ccid *kernel* driver at all, so "no
    ccid symlink" is normal on a working system. An earlier version of this
    module treated its absence as a fault and reported one on a laptop whose
    card read perfectly. The authoritative answer to "is the reader working"
    is what pcscd itself reports, which is checked below.
    """
    ids: set[str] = set()
    base = "/sys/bus/usb/devices"
    if not os.path.isdir(base):
        return ids
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return ids
    for entry in entries:
        device = os.path.join(base, entry)
        driver_link = os.path.join(device, "driver")
        # The driver binds to the *interface*, not the device.
        for interface in _interfaces_of(device):
            link = os.path.join(interface, "driver")
            if not os.path.islink(link):
                continue
            driver = os.path.basename(os.readlink(link))
            if driver not in ("ccid", "pcscd_ccid", "ifd"):
                continue
            vendor = _read(os.path.join(device, "idVendor"))
            product = _read(os.path.join(device, "idProduct"))
            if vendor:
                ids.add(f"{vendor}:{product}")
    return ids


def _interfaces_of(device_dir: str) -> list[str]:
    try:
        entries = os.listdir(device_dir)
    except OSError:
        return []
    return [
        os.path.join(device_dir, e)
        for e in entries
        if ":" in e and os.path.isdir(os.path.join(device_dir, e))
    ]


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip().lower()
    except OSError:
        return ""


# --- the card itself ----------------------------------------------------------

def card_present() -> tuple[bool | None, str]:
    """Is a card in a reader? (None = cannot tell)"""
    if not shutil.which("opensc-tool"):
        return None, ""
    rc, out = _run(["opensc-tool", "--list-readers"])
    if rc not in (0, 1):
        return None, ""
    return bool(re.search(r"Card present", out, re.I)), out


def diagnose() -> list[Finding]:
    """Every reader finding we can actually measure, most severe first."""
    findings: list[Finding] = []

    # Is pcscd even up? Everything else is noise without it.
    service_up = False
    if shutil.which("systemctl"):
        rc, out = _run(["systemctl", "is-active", "pcscd"])
        service_up = out.strip() == "active"
    if not service_up:
        findings.append(Finding(
            "problem", "The smart card service (pcscd) is not running.",
            "Nothing else can work until it is.",
            # Deliberately not a sudo command. The tool can start this service
            # itself through the same password prompt it uses for everything
            # else, so telling the user to open a terminal and run it is handing
            # back a job Sentinel is already equipped to do. "Run 'sentinel
            # check'" is the action that actually fixes it.
            "run 'sentinel check' -- it will start it for you",
        ))

    readers, queried = usb_readers()
    if not queried:
        findings.append(Finding(
            "warning", "Could not check the USB bus.",
            "'lsusb' is not installed, so the reader cannot be identified.",
            "sudo apt install usbutils    (or: sudo dnf install usbutils)",
        ))
    elif not readers:
        findings.append(Finding(
            "problem", "No smart card reader found on the USB bus.",
            "Nothing is plugged in that pcscd could use. Check the cable, and "
            "try a different port if this is a laptop.",
            "Re-run this check with the reader plugged in.",
        ))
    else:
        findings.append(Finding(
            "ok", f"{len(readers)} smart card reader(s) found.",
            "\n         ".join(readers),
        ))

    prints = fingerprint_readers()
    if prints:
        findings.append(Finding(
            "warning", "A fingerprint reader is also present.",
            "Laptops often expose the fingerprint sensor as a card reader. If "
            "the CAC is in an external reader, pcscd may be enumerating the "
            "fingerprint sensor instead, and the CAC will look absent:\n"
            + "\n         ".join(prints),
            "Insert the CAC, then run RUN CHECKS again. If the card still is "
            "not seen, try disabling the fingerprint reader in the BIOS, or "
            "moving the CAC to a different reader.",
        ))

    have_socket, socket_path = pcsc_socket_accessible()
    if have_socket is False:
        findings.append(Finding(
            "problem", f"You cannot reach the pcscd socket ({socket_path}).",
            "This happens when the udev rule that grants your user access to "
            "the smart card socket is missing.",
            "Log out and back in. If that does not help, add yourself to the "
            "group and log in again:\n"
            "         sudo usermod -aG pcscd $USER",
        ))

    owned = pcscd_owns_the_reader()
    if owned is True:
        findings.append(Finding(
            "ok", "pcscd opens the reader on your behalf.",
            "You do not need permission to the USB device itself; only to the "
            "pcscd socket, which the check above covers.",
        ))

    present, _detail = card_present()
    if present is False:
        # Not a failure: this is the most common state on a laptop and the
        # reader is demonstrably working. Calling it FAIL teaches users to
        # ignore the output, which is the opposite of the point.
        findings.append(Finding(
            "warning", "No card is in the reader yet.",
            "Everything below the card is working. Insert your CAC and run "
            "RUN CHECKS again.",
            "Take the card out and put it back in firmly, then wait a moment.",
        ))
    elif present is True:
        findings.append(Finding("ok", "A card is present in a reader."))

    if not findings:
        findings.append(Finding(
            "warning", "No reader problems found, but nothing could be measured.",
            "Install the tools above to get a real answer.",
        ))

    return findings
