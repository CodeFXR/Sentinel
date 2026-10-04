"""Distribution-aware platform facts.

Every distro-specific assumption in Sentinel lives here: where the trust-anchor
directory is, how to refresh the trust store, where the OpenSC PKCS#11 module is,
which package manager is present, and where browsers keep their NSS databases.

Adding support for a new distribution means adding one entry to `_FAMILIES` and
nothing else.

Design rule: when the distribution is not recognised, `detect()` returns a
Platform with `trust_anchor_dir` set to None. Callers must refuse to act rather
than guess at a path. Writing certificates to a guessed location is worse than
not writing them at all.
"""

from __future__ import annotations

import asyncio
import glob
import os
import shutil
import subprocess
from dataclasses import dataclass

import distro

# --- Python dependencies ------------------------------------------------------
# Sentinel's only third-party imports, with upper bounds, pinned here rather than
# in a requirements.txt so the installer, the updater and the test suite all read
# one list. Upper bounds matter: Textual's widget API (Static.label, set_interval,
# TabbedContent) has broken across majors, and an unbounded install is not
# reproducible. tests/test_dependencies.py fails if this drifts from the imports
# actually used by the source.
PIP_REQUIREMENTS = (
    "textual>=0.27.0,<2.0.0",
    "distro>=1.8.0,<2.0.0",
)

# Name of the trust anchor Sentinel installs. The bundle it points at contains
# self-signed roots only.
TRUST_ANCHOR_NAME = "DoD_Roots.pem"

# Anchor names written by earlier Sentinel versions. Those installs put 62
# non-root certificates into the trust store; re-running INSTALL CERTS removes
# them, so an upgraded install converges on a correct trust store instead of
# leaving the over-trust in place.
LEGACY_ANCHOR_NAMES = ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt")

# The OpenSC driver list that avoids a firmware-level hang on the Broadcom
# Corp 58200, a standard issued DoD reader. OpenSC otherwise probes the inserted
# card with every driver it knows, and the `setcos` driver sends APDU
# `00 CA DF 30 05`, which this reader's firmware cannot answer. The probe
# times out after ~26 seconds on every unconfigured machine in a fleet.
BROADCOM_WORKAROUND = "card_drivers = piv-II, cac, cac1"


@dataclass(frozen=True)
class Platform:
    name: str
    family: str
    install_cmd: tuple[str, ...] | None
    packages: tuple[str, ...]
    trust_anchor_dir: str | None
    trust_refresh_cmd: tuple[str, ...] | None
    trust_anchor_name: str = TRUST_ANCHOR_NAME
    service: str = "pcscd"
    pkcs11_module: str | None = None

    @property
    def supported(self) -> bool:
        """True when Sentinel knows how to install certificates on this distro."""
        return self.trust_anchor_dir is not None and bool(self.trust_refresh_cmd)

    def install_hint(self, packages: tuple[str, ...] | None = None) -> str:
        """A copy-pasteable command for the user to run themselves."""
        pkgs = " ".join(packages or self.packages)
        if not self.install_cmd:
            return f"Install these manually: {pkgs}"
        return " ".join((*self.install_cmd, pkgs))

    def refresh_hint(self) -> str:
        """The trust-store refresh command, for documentation and dry-run output."""
        if not self.trust_refresh_cmd:
            return "(unknown for this distribution)"
        return " ".join(self.trust_refresh_cmd)


_FAMILIES: dict[str, dict] = {
    "fedora": {
        "name": "Fedora/RHEL",
        "install_cmd": ("dnf", "install", "-y"),
        "packages": ("pcsc-lite", "pcsc-tools", "opensc", "openssl", "nss-tools"),
        "trust_anchor_dir": "/etc/pki/ca-trust/source/anchors",
        "trust_refresh_cmd": ("update-ca-trust",),
    },
    "debian": {
        "name": "Debian/Ubuntu",
        "install_cmd": ("apt-get", "install", "-y"),
        "packages": ("pcscd", "opensc", "openssl", "libnss3-tools", "pcsc-tools"),
        "trust_anchor_dir": "/usr/local/share/ca-certificates",
        "trust_refresh_cmd": ("update-ca-certificates",),
        "trust_anchor_name": "DoD_Roots.crt",
    },
    # Verified against a real Arch container: the directory is
    # `trust-source/anchors`, with no `source/` component. The widely-copied
    # `/etc/ca-certificates/trust/source/anchors` does not exist on Arch, and
    # writing to a non-existent directory is the failure mode this whole
    # module exists to prevent.
    "arch": {
        "name": "Arch",
        "install_cmd": ("pacman", "-S", "--needed", "--noconfirm"),
        # Arch names the daemon package `pcsclite`. There is no `pcscd`
        # package, and pacman refuses the whole transaction when any name in
        # the list is wrong -- so one bad name here means the user gets
        # "target not found" and installs nothing. Confirmed against a real
        # Arch container.
        "packages": ("pcsclite", "opensc", "openssl", "nss", "pcsc-tools"),
        "trust_anchor_dir": "/etc/ca-certificates/trust-source/anchors",
        "trust_refresh_cmd": ("trust", "extract-compat",),
    },
    # Verified against openSUSE Tumbleweed: the anchors directory is
    # /etc/pki/trust/anchors, NOT the Debian /usr/local/share/ca-certificates.
    # openSUSE ships `update-ca-certificates` but points it at its own layout.
    "suse": {
        "name": "openSUSE",
        "install_cmd": ("zypper", "install", "-y"),
        "packages": ("pcsc-lite", "pcsc-tools", "opensc", "openssl", "mozilla-nss-tools"),
        "trust_anchor_dir": "/etc/pki/trust/anchors",
        "trust_refresh_cmd": ("update-ca-certificates",),
    },
}

# Ordered by preference. A distro id or a like-token is matched against these keys.
_ALIASES = {
    "rhel": "fedora",
    "centos": "fedora",
    "rocky": "fedora",
    "almalinux": "fedora",
    "amzn": "fedora",
    "ol": "fedora",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "zorin": "debian",
    "raspbian": "debian",
    "devuan": "debian",
    "elementary": "debian",
    "manjaro": "arch",
    "endeavouros": "arch",
    "garuda": "arch",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sles": "suse",
    "suse": "suse",
}

_PKCS11_PATTERNS = (
    "/usr/lib64/opensc-pkcs11.so*",
    # Arch ships the NSS-facing copy here, which is the one modutil is meant
    # to be given; prefer it over the plain /usr/lib copy.
    "/usr/lib/pkcs11/opensc-pkcs11.so*",
    "/usr/lib/opensc-pkcs11.so*",
    "/usr/lib/*/opensc-pkcs11.so*",
    "/usr/lib/*-linux-gnu/opensc-pkcs11.so*",
    "/usr/local/lib/opensc-pkcs11.so*",
    "/usr/local/lib/*/opensc-pkcs11.so*",
    "/lib/*/opensc-pkcs11.so*",
)


def find_pkcs11_module() -> str | None:
    """Locate opensc-pkcs11.so on the filesystem.

    Returns the unversioned symlink (`opensc-pkcs11.so`) in preference to the
    versioned file it points at (`opensc-pkcs11.so.0.27.0`).

    That preference is not cosmetic. The chosen path is written into every
    browser's NSS database and is not rewritten until Sentinel runs again, so a
    versioned path is a time bomb: the next OpenSC upgrade replaces
    `opensc-pkcs11.so.0.27.0` with a higher version, deletes the old file, and
    every browser that was pointed at it loses the card with nothing in the
    logs. The unversioned symlink is repointed by the package manager and
    survives the upgrade. This is also why the community instructions name
    `/usr/lib/pkcs11/opensc-pkcs11.so` explicitly rather than letting a tool
    pick for itself.

    Asks ldconfig first because it is authoritative and needs no guessing, then
    falls back to globbing the usual multiarch and lib directories. Returns None
    if OpenSC is not installed.
    """
    try:
        result = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "opensc-pkcs11.so" in line and "=>" in line:
                candidate = line.split("=>", 1)[1].strip()
                if not _is_versioned_library(candidate):
                    return candidate
                # A versioned path from the cache is usable but fragile, so
                # remember it and prefer a stable symlink if one can be found.
                versioned = candidate
                break
        else:
            versioned = None
    except (OSError, subprocess.SubprocessError):
        versioned = None

    for pattern in _PKCS11_PATTERNS:
        matches = sorted(glob.glob(pattern))
        if not matches:
            continue
        for match in matches:
            if not _is_versioned_library(match):
                return match
        if matches:
            return matches[0]

    return versioned


def have(binary: str) -> bool:
    """True when an executable is on PATH. Checks for a binary, not a package."""
    return shutil.which(binary) is not None


async def service_is_active(service: str = "pcscd", timeout: float = 5.0) -> bool:
    """Ask systemd whether a unit is active, without blocking the event loop.

    Returns False on any failure, including systemctl being absent, wedged, or
    timing out. A probe that cannot answer is indistinguishable from a service
    that is down, and the caller reports that as "unknown" rather than
    "broken".
    """
    if not have("systemctl"):
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl", "is-active", service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False
    return stdout.decode(errors="replace").strip() == "active"


def opensc_conf_path() -> str:
    """Path to opensc.conf.

    SENTINEL_OPENSC_CONF overrides it. That exists so the test suite can prove
    the card_drivers logic against a real file instead of asserting against a
    mock, and so a user on a non-standard layout can point Sentinel at the right
    one.
    """
    return os.environ.get("SENTINEL_OPENSC_CONF", "/etc/opensc.conf")


def broadcom_workaround_needed() -> bool:
    """True when /etc/opensc.conf does not already restrict the driver list.

    Also returns True when the file is absent or unreadable, which is the
    common case on a fleet machine.
    """
    path = opensc_conf_path()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("#") or "=" not in stripped:
                    continue
                key = stripped.split("=", 1)[0].strip()
                if key == "card_drivers":
                    return False
    except OSError:
        return True
    return True


def _family_key() -> str | None:
    candidates = [distro.id()] + distro.like().split()
    for candidate in candidates:
        if candidate in _FAMILIES:
            return candidate
        alias = _ALIASES.get(candidate)
        if alias:
            return alias
    return None


def _pretty_name() -> str:
    try:
        return distro.name(pretty=True) or "Unknown Linux"
    except Exception:
        return "Unknown Linux"


def _unknown() -> Platform:
    """A Platform that refuses to touch the filesystem.

    Reached for an unrecognised distribution, and also if distro detection
    itself fails. Detection must never crash app startup, so every path into
    here is wrapped.
    """
    return Platform(
        name=_pretty_name(),
        family="unknown",
        install_cmd=None,
        packages=("pcscd", "opensc", "openssl"),
        trust_anchor_dir=None,
        trust_refresh_cmd=None,
    )


def detect() -> Platform:
    """Build a Platform for the running distribution."""
    try:
        key = _family_key()
    except Exception:
        return _unknown()

    if key is None:
        return _unknown()

    return Platform(
        family=key,
        pkcs11_module=find_pkcs11_module(),
        **_FAMILIES[key],
    )


# Chromium and Electron share one NSS database. The directory is created on
# demand by `ensure_nss_directory`, because modutil cannot create it: pointing
# modutil at a path whose directory does not exist fails with
# SEC_ERROR_BAD_DATABASE and exit 46, and it does not create the directory as a
# side effect. The community instructions get away with a relative
# `sql:.pki/nssdb/` only because the browser has usually already made it.
CHROMIUM_NSS_DIR = os.path.join(".pki", "nssdb")

# Binaries that mean "a Chromium-family browser is installed on this machine".
# The shared database is only a candidate when one of these exists, so that a
# machine with no Chromium at all is not reported as having an unconfigured one.
CHROMIUM_BINARIES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    "chrome", "microsoft-edge", "brave-browser", "vivaldi", "opera",
)


def chromium_installed() -> bool:
    """True when a Chromium-family browser is installed from packages."""
    return any(shutil.which(name) for name in CHROMIUM_BINARIES)


def ensure_nss_directory(path: str) -> bool:
    """Create an NSS database directory if it is missing.

    Returns True when the directory exists afterwards. Refuses rather than
    raising, because a failure here is reported to the user as "could not
    prepare", not as a traceback.

    Mode 0700 and nothing wider: the directory holds cert9.db and key4.db, and
    NSS refuses to use a database whose permissions are too open anyway.
    """
    if os.path.isdir(path):
        return True
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError:
        return False
    return os.path.isdir(path)


def nss_databases() -> list[str]:
    """Every NSS database directory that could belong to this user.

    Chromium and Electron keep one in ~/.pki/nssdb. Firefox keeps one per
    profile, native, Flatpak and Snap. A Firefox profile only counts if it
    actually contains cert9.db, which is what distinguishes a real profile from
    "Crash Reports" or a stray directory that happens to contain the word
    "default" -- a Firefox profile cannot be conjured, because which profile is
    default is Firefox's decision to record.

    The Chromium directory is a different case and is reported even when it does
    not exist yet, as long as a Chromium-family browser is installed. That is
    what a browser that has been installed but never launched looks like, and it
    is a state Sentinel can fix with `ensure_nss_directory` instead of refusing.
    """
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, CHROMIUM_NSS_DIR)]

    firefox_roots = [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.Firefox", ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
    ]
    for root in firefox_roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for entry in entries:
            path = os.path.join(root, entry)
            if os.path.isfile(os.path.join(path, "cert9.db")):
                candidates.append(path)

    seen, unique = set(), []
    for path in candidates:
        if path in seen:
            continue
        if os.path.isdir(path) or (
            path == candidates[0] and chromium_installed()
        ):
            seen.add(path)
            unique.append(path)
    return unique


# --- p11-kit -----------------------------------------------------------------
# p11-kit is the PKCS#11 module broker that every current mainstream
# distribution ships (Fedora, Ubuntu and therefore Zorin OS, Debian, openSUSE,
# Arch). It loads OpenSC itself and hands the resulting slots to applications
# through `p11-kit-proxy.so`, which is registered in each browser's NSS
# database out of the box.
#
# That inverts the manual instructions Sentinel was built on. Those say to run
#
#     modutil -dbdir sql:.pki/nssdb/ -add "CAC Module" -libfile .../opensc-pkcs11.so
#
# which registers OpenSC a *second* time, behind p11-kit's back. NSS rejects the
# duplicate and modutil exits 22 with `Unknown PKCS #11 error`, two lines after
# printing:
#
#     WARNING: Manually adding a module while p11-kit is enabled could cause
#     duplicate module registration in your security database.
#
# The browser never needed the manual entry -- it already has the card through
# p11-kit-proxy. A tool that checks the exit code therefore reports failure on a
# machine whose browser is working perfectly, which is worse than not checking:
# the user is told their setup is broken when it is not.
#
# So: ask p11-kit first. Only reach for modutil when p11-kit is not doing the
# job, which is the case this code path exists for and the only case where
# `modutil -add` is the right instruction.

# Long enough for a wedged reader to answer on a slow USB bus, short enough
# that the GUI does not appear to hang on a daemon that is not responding.
PROBE_TIMEOUT_SECONDS = 15.0

P11_KIT_PROXY = "p11-kit-proxy.so"

# The p11-kit configuration that wires OpenSC into the broker. Present on every
# distribution that uses p11-kit, and the thing that makes the proxy able to
# reach the card.
P11_KIT_OPENSC_CONF = "/usr/share/p11-kit/modules/opensc.module"

# Directories p11-kit keeps its own module configuration in. More than one
# because Fedora uses the first and Debian/Ubuntu use the second.
P11_KIT_CONF_DIRS = ("/usr/share/p11-kit/modules", "/etc/pkcs11/modules")

# A token that identifies itself as a CAC or PIV card.
_CAC_MARKERS = ("common access card", "piv_ii", "piv-ii", "piv applet", "cac")


def p11_kit_present() -> bool:
    """True when p11-kit is installed and configured to broker OpenSC.

    Checks the configuration file rather than the shared library: the library
    can be installed without being wired up, and a proxy with no modules behind
    it exposes nothing to a browser, so its presence alone proves nothing.
    """
    for directory in P11_KIT_CONF_DIRS:
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith(".module"):
                continue
            try:
                with open(os.path.join(directory, entry), encoding="utf-8",
                          errors="replace") as fh:
                    body = fh.read()
            except OSError:
                continue
            if "opensc-pkcs11.so" in body:
                return True
    return False


def p11_kit_exposes_card() -> tuple[bool, str]:
    """Ask p11-kit what it is currently offering: is a CAC sitting in a slot?

    Returns (card_present, detail). The detail is a short human-readable reason
    either way, because the difference between "no reader" and "reader present,
    no card" is the difference between fixing the hardware and inserting the
    card, and the user has to be told which one applies.

    Deliberately uses p11-kit's own view rather than loading OpenSC directly.
    p11-kit's view is what a browser sees, so a positive here means the browser
    can reach the card -- which is the only claim worth making.
    """
    pkcs11_tool = shutil.which("pkcs11-tool")
    if not pkcs11_tool:
        return False, "pkcs11-tool is not installed, so the card cannot be checked"

    proxy = find_p11_kit_proxy()
    argv = [pkcs11_tool, "-L"]
    if proxy:
        argv[1:1] = ["--module", proxy]
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "the smart card stack did not answer in time"

    if result.returncode != 0:
        return False, "pkcs11-tool could not reach the smart card daemon"

    stdout = result.stdout
    if "Available slots" not in stdout and "Slot" not in stdout:
        return False, "no smart card reader is attached"

    for line in stdout.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("token label") or stripped.startswith("token manufacturer"):
            if any(marker in stripped for marker in _CAC_MARKERS):
                return True, "p11-kit is exposing a CAC to the browser"
    return False, "a reader is attached but no card is in it"


def find_p11_kit_proxy() -> str | None:
    """Locate p11-kit-proxy.so, the module browsers actually load."""
    for pattern in ("/usr/lib64/p11-kit-proxy.so*", "/usr/lib/*/p11-kit-proxy.so*",
                    "/usr/lib/pkcs11/p11-kit-proxy.so*", "/lib/*/p11-kit-proxy.so*"):
        matches = sorted(glob.glob(pattern))
        for match in matches:
            # Prefer the unversioned symlink, for the same reason as OpenSC: a
            # versioned path stops existing the moment p11-kit is upgraded.
            if not _is_versioned_library(match):
                return match
        if matches:
            return matches[0]
    return None


def _is_versioned_library(path: str) -> bool:
    """True for `foo.so.1.2.3` but not for `foo.so` or its bare symlink."""
    base = os.path.basename(path)
    return ".so." in base


def browsers_running() -> list[str]:
    """Browsers that hold an NSS database open.

    Firefox rewrites prefs.json when it exits, so a module added to a live
    profile is silently discarded. Detecting this is the difference between a
    configuration that works and one that appears to work.
    """
    running = []
    for binary in ("firefox", "firefox-bin", "chromium", "chromium-browser", "google-chrome"):
        path = shutil.which(binary)
        if not path:
            continue
        try:
            result = subprocess.run(
                ["pgrep", "-x", os.path.basename(path)],
                capture_output=True, text=True, timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            running.append(os.path.basename(path))
    return running
