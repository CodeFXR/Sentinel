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
                return line.split("=>", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass

    for pattern in _PKCS11_PATTERNS:
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[0]
    return None


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


def nss_databases() -> list[str]:
    """Every NSS database directory that could belong to this user.

    Chromium and Electron keep one in ~/.pki/nssdb. Firefox keeps one per
    profile, native, Flatpak and Snap. A profile only counts if it actually
    contains cert9.db, which is what distinguishes a real profile from
    "Crash Reports" or a stray directory that happens to contain the word
    "default".
    """
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, ".pki", "nssdb")]

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
        if path not in seen and os.path.isdir(path):
            seen.add(path)
            unique.append(path)
    return unique


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
