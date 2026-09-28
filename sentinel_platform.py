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

import glob
import os
import subprocess
from dataclasses import dataclass

import distro


@dataclass(frozen=True)
class Platform:
    name: str
    family: str
    install_cmd: tuple[str, ...] | None
    packages: tuple[str, ...]
    trust_anchor_dir: str | None
    trust_refresh_cmd: tuple[str, ...] | None
    trust_anchor_name: str = "DoD_Full_Chain.pem"
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


_FAMILIES: dict[str, dict] = {
    "fedora": {
        "name": "Fedora/RHEL",
        "install_cmd": ("dnf", "install", "-y"),
        "packages": ("pcscd", "pcsc-lite", "opensc", "openssl", "nss-tools"),
        "trust_anchor_dir": "/etc/pki/ca-trust/source/anchors",
        "trust_refresh_cmd": ("update-ca-trust",),
    },
    "debian": {
        "name": "Debian/Ubuntu",
        "install_cmd": ("apt-get", "install", "-y"),
        "packages": ("pcscd", "opensc", "openssl", "libnss3-tools", "pcsc-tools"),
        "trust_anchor_dir": "/usr/local/share/ca-certificates",
        "trust_refresh_cmd": ("update-ca-certificates",),
        "trust_anchor_name": "DoD_Full_Chain.crt",
    },
    "arch": {
        "name": "Arch",
        "install_cmd": ("pacman", "-S", "--needed", "--noconfirm"),
        "packages": ("pcscd", "opensc", "openssl", "nss", "pcsc-tools"),
        "trust_anchor_dir": "/etc/ca-certificates/trust/source/anchors",
        "trust_refresh_cmd": ("trust", "extract-compat"),
    },
    "suse": {
        "name": "openSUSE",
        "install_cmd": ("zypper", "install", "-y"),
        "packages": ("pcscd", "opensc", "openssl", "mozilla-nss-tools"),
        "trust_anchor_dir": "/usr/local/share/ca-certificates",
        "trust_refresh_cmd": ("update-ca-certificates",),
        "trust_anchor_name": "DoD_Full_Chain.crt",
    },
    "gentoo": {
        "name": "Gentoo",
        "install_cmd": ("emerge",),
        "packages": ("pcscd", "opensc", "nss", "dev-libs/openssl"),
        "trust_anchor_dir": "/etc/ssl/certs",
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
    "zinor": "debian",
    "zorin": "debian",
    "raspbian": "debian",
    "devuan": "debian",
    "manjaro": "arch",
    "endeavouros": "arch",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sles": "suse",
}

_PKCS11_PATTERNS = (
    "/usr/lib64/opensc-pkcs11.so*",
    "/usr/lib/opensc-pkcs11.so*",
    "/usr/lib/*/opensc-pkcs11.so*",
    "/usr/lib/*-linux-gnu/opensc-pkcs11.so*",
    "/usr/local/lib/opensc-pkcs11.so*",
    "/usr/local/lib/*/opensc-pkcs11.so*",
    "/lib/*/opensc-pkcs11.so*",
    "/opt/homebrew/lib/opensc-pkcs11.so*",
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
    profile, native and Flatpak/Snap. A profile only counts if it actually
    contains cert9.db.
    """
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, ".pki", "nssdb")]

    firefox_roots = [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
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
