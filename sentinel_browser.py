"""Browser inventory: what is installed, and can it actually reach the card?

This module exists because of a specific failure that the tool was about to ship.

On a personal Ubuntu laptop, Firefox is a **snap** (since Ubuntu 24.04) and on
some distributions it is a **Flatpak**. Both are sandboxed. A sandboxed Firefox
runs in its own mount and user namespace and generally cannot:

* `dlopen()` a PKCS#11 module from a host path such as
  `/usr/lib64/opensc-pkcs11.so`, because that path does not exist inside the
  sandbox's view of the filesystem, and
* reach `/run/pcscd/pcscd.comm`, the pcscd socket, if the sandbox does not
  expose it.

Sentinel's `configure_browsers` finds the profile at
`~/snap/firefox/common/.mozilla/firefox/<profile>`, writes the module into the
NSS database with `modutil`, reads it back, and reports success. Every one of
those steps really does work. The CAC still does not appear in the browser,
because the browser cannot load the module it was just given.

That is the exact failure the v1.0.0 review called out as a finding in its own
right: a green light reporting a property the code did not verify. A soldier
who sees a green LED and a CAC that does not work concludes the tool is broken
and gives up — which is the outcome this whole project exists to prevent.

So: this module reports what it can *measure*, marks a confined browser as
unverified rather than working, and tells the user what to do about it. It
never claims a browser can use a hardware token when it has not been shown to.

Measurement, not assumption
---------------------------
Confinement is read from the packaging system rather than inferred from a path:

* snap: `snap list firefox` for the notes, and the presence of
  `/snap/firefox/current` to confirm it is the snap build.
* flatpak: `flatpak list --app` for the application id, and the Flatpak id in
  the profile path.

Where the tool cannot determine confinement, it says so and stays unverified.
"I don't know" is a legitimate answer; "it works" is not one it is entitled to
without evidence.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

import sentinel_platform

# How long a packaging query may take. These are local commands, but a wedged
# Flatpak daemon can block, and a hung tool on a laptop is worse than a
# missing answer.
QUERY_TIMEOUT = 6


@dataclass(frozen=True)
class Browser:
    """One browser installation, and what is known about its ability to use a token."""

    name: str
    packaging: str  # "native", "snap", "flatpak"
    confined: bool
    nss_databases: tuple[str, ...]
    detail: str = ""

    @property
    def can_use_hardware_token(self) -> bool:
        """True only when the browser is not sandboxed and has a profile to write to.

        This is a statement about sandboxing and presence, not about the whole
        chain. Even for a native browser the card, the daemon and the module all
        have to work; that is what `check` and `diagnose_reader` are for.

        A browser with no NSS database cannot be configured at all, so it cannot
        use a token either -- claiming otherwise was how a missing profile could
        be reported as a working browser.
        """
        return not self.confined and bool(self.nss_databases)

    @property
    def status(self) -> str:
        """One of: ok, unverified, missing."""
        if not self.nss_databases:
            return "missing"
        return "ok" if self.can_use_hardware_token else "unverified"


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=QUERY_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return result.returncode, result.stdout


def snap_firefox_confined() -> bool | None:
    """True/False for a snap Firefox, or None when snap Firefox is not present.

    A snap with `classic` confinement runs with access to the host filesystem
    and can load a host PKCS#11 module. A `strict` snap cannot.
    """
    if not os.path.isdir("/snap/firefox/current"):
        return None
    if not shutil.which("snap"):
        # The snap directory exists but we cannot ask about it. Do not guess.
        return None
    rc, out = _run(["snap", "list", "firefox"])
    if rc != 0:
        return None
    notes = _snap_notes(out)
    if notes is None:
        return None
    return "classic" not in notes


def _snap_notes(output: str) -> str | None:
    """Pull the Notes column out of `snap list` output.

    `snap list` prints a header row and a data row, not `Notes: value`:

        Name    Version  Rev  Tracking  Publisher  Notes
        firefox 140.0.4  4103  latest/stable  mozilla  classic

    An earlier version of this function searched for a line beginning with
    "Notes:", which never matches, so it returned None for every snap Firefox
    and the caller fell back to "unverified" for all of them -- including the
    classic ones that work. Returns None only when the column genuinely cannot
    be located, so "unknown" still means unknown.
    """
    lines = [l for l in output.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    header = lines[0].lower().split()
    if "notes" not in header:
        return None
    index = header.index("notes")
    for line in lines[1:]:
        fields = line.split()
        # The first field is the snap name; take the row that matches.
        if fields and fields[0] == "firefox":
            if len(fields) <= index:
                return ""  # column present, value empty
            return fields[index].strip().lower()
    return None


def flatpak_firefox_present() -> bool:
    if not shutil.which("flatpak"):
        return False
    rc, out = _run(["flatpak", "list", "--app", "--columns=application"])
    if rc != 0:
        return False
    return "org.mozilla.firefox" in out.lower()


def native_firefox_present() -> bool:
    """A Firefox installed by the distribution's own package manager."""
    return shutil.which("firefox") is not None or os.path.exists("/usr/bin/firefox")


def _firefox_profiles() -> dict[str, list[str]]:
    """Firefox profile directories, grouped by how the browser is installed."""
    home = os.path.expanduser("~")
    groups: dict[str, list[str]] = {"native": [], "snap": [], "flatpak": []}

    roots = {
        "native": os.path.join(home, ".mozilla", "firefox"),
        "snap": os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        "flatpak": os.path.join(home, ".var", "app", "org.mozilla.firefox",
                                ".mozilla", "firefox"),
        "flatpak": os.path.join(home, ".var", "app", "org.mozilla.Firefox",
                                ".mozilla", "firefox"),
    }
    seen = set()
    for packaging, root in roots.items():
        if not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for entry in entries:
            path = os.path.join(root, entry)
            if not os.path.isfile(os.path.join(path, "cert9.db")):
                continue
            if path in seen:
                continue
            seen.add(path)
            groups[packaging].append(path)
    return groups


def chromium_databases() -> list[str]:
    """Chromium and Electron share ~/.pki/nssdb.

    Reported when a Chromium-family browser is installed, even if the directory
    does not exist yet: a browser that has been installed but never launched has
    no database, and that is a state Sentinel can create rather than a reason to
    report the browser as absent. Gated on the browser actually being installed
    so that a machine without Chromium is not told it has an unconfigured one.
    """
    if not sentinel_platform.chromium_installed():
        return []
    path = os.path.join(os.path.expanduser("~"), ".pki", "nssdb")
    return [path]


def is_firefox_profile(path: str) -> bool:
    """True when this NSS database belongs to a Firefox profile.

    The distinction decides whether a PKCS#11 module has to be registered in it,
    which is the whole difference between the two browser families:

    * **Firefox** reads its module list from the profile's secmod.db. Neither
      Firefox nor NSS contains a single reference to p11-kit -- checked against
      `security/manager/ssl/PKCS11ModuleDB.cpp` and NSS's own `nssinit.c`, both
      of which use `SECMOD_GetDefaultModuleList()` / `SECMOD_AddNewModule()` and
      mention p11-kit zero times. So a profile with no entry has no card module
      at all, and the browser can never offer a certificate, however healthy the
      host's p11-kit is. This is what the "Load" button in Preferences > Privacy
      & Security > Security Devices writes.

    * **Chromium and Chrome** reach the card through the system p11-kit client
      library and keep no module entry of their own. Registering one is at best
      redundant.

    Getting this backwards is not a cosmetic difference. A previous version of
    Sentinel applied the Chromium rule to every browser because a field report
    came from a Chromium-only machine, and Firefox on that machine then had no
    way to read a card at all.
    """
    normalised = path.replace(os.sep, "/")
    return (
        "/.mozilla/firefox/" in normalised
        or "/snap/firefox/" in normalised
        or "/.var/app/org.mozilla.firefox/" in normalised.lower()
        or "/.var/app/org.mozilla.firefox" in normalised
    )


# Browsers a user is likely to launch, and the binary that proves each is
# installed. Used to notice a browser that Sentinel never configured, which is
# the state a false green hides: the tool writes the one database it found and
# says nothing about the browser actually on the desktop.
LAUNCHABLE = (
    ("Firefox", "firefox"),
    ("Firefox", "firefox-esr"),
    ("Chromium", "chromium"),
    ("Chromium", "chromium-browser"),
    ("Google Chrome", "google-chrome"),
    ("Brave", "brave-browser"),
)


def installed_browsers_without_profile() -> list[str]:
    """Browsers installed here that have no profile Sentinel can write to.

    A browser that has never been started has no profile, so there is nothing to
    configure. That is not a failure -- but it is also not the same thing as
    "configured", and conflating the two is how a machine ends up looking
    complete from the inside while the browser the user actually launches was
    never touched. A field report was exactly this: the log listed only
    `~/.pki/nssdb` on every run, and the browser in use was not that one.

    Reported rather than acted on, because the fix is "start the browser once",
    which is the user's to do, not Sentinel's.

    Returns display names, deduplicated, so a machine with both `chromium` and
    `chromium-browser` is not told about the same browser twice.
    """
    profiles = _firefox_profiles()
    have_firefox = any(profiles.values())
    have_chromium = bool(chromium_databases())

    missing: list[str] = []
    for label, binary in LAUNCHABLE:
        if not shutil.which(binary):
            continue
        if label == "Firefox":
            configured = have_firefox
        else:
            configured = have_chromium
        if not configured and label not in missing:
            missing.append(label)
    return missing


# The preference that decides whether Firefox offers a choice of certificate or
# picks one itself.
#
# Every set of community CAC instructions includes this step, and Sentinel did
# not have it. Preferences > Privacy & Security > Certificates > "Ask me every
# time" is `security.default_personal_cert` set to the empty string; the
# alternative, "Select one automatically", is the string `auto`.
#
# It matters because a CAC site asks the browser to present a client
# certificate, and there are usually several on the card -- the plain
# certificate, the email certificate, and both halves of a dual-persona card.
# Left on automatic, Firefox may pick the wrong one, or present none, and the
# symptom is a site that never prompts, which looks exactly like a card that
# cannot be read.
#
# Set through `user.js` rather than `prefs.js`: Firefox overwrites prefs.js from
# its in-memory copy on exit, so a value written there while the browser is
# running is discarded. user.js is applied on every start and wins over
# prefs.js, which is what makes the setting stick.
ASK_EVERY_TIME_PREF = "security.default_personal_cert"
_ASK_EVERY_TIME_VALUE = ""


def firefox_asks_every_time(profile: str) -> bool:
    """True when this Firefox profile is set to ask which certificate to use.

    Reads `user.js` and `prefs.js` in that order of authority. An unreadable or
    absent file means "not set", which is False: the default is automatic
    selection, so a profile with no such line has not been configured for CAC
    use.
    """
    value = None
    for name in ("user.js", "prefs.js"):
        path = os.path.join(profile, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        match = re.search(
            r'user_pref\(\s*"' + re.escape(ASK_EVERY_TIME_PREF) + r'"\s*,\s*"([^"]*)"\s*\)',
            body,
        )
        if match:
            value = match.group(1)
            if name == "user.js":
                break
    return value == _ASK_EVERY_TIME_VALUE


def set_firefox_asks_every_time(profile: str) -> tuple[bool, str]:
    """Make one Firefox profile ask which certificate to use. Returns (ok, why).

    Writes `user.js` because Firefox rewrites `prefs.js` on exit and discards
    the change, which is the failure the existing code warns about elsewhere.
    user.js is re-applied at every start and takes precedence, so the setting
    survives the browser being closed -- which is the only way to get a value to
    stick in a profile the user owns and Firefox also writes.
    """
    path = os.path.join(profile, "user.js")
    line = f'user_pref("{ASK_EVERY_TIME_PREF}", "{_ASK_EVERY_TIME_VALUE}");'

    existing = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
    except OSError:
        pass

    pattern = re.compile(
        r'^.*' + re.escape(ASK_EVERY_TIME_PREF) + r'.*$\n?', re.M
    )
    if pattern.search(existing):
        updated = pattern.sub("", existing)
        updated = updated.rstrip("\n")
        updated = (updated + "\n" if updated else "") + line + "\n"
    else:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        updated = existing + separator + line + "\n"

    try:
        # user.js holds preferences, not secrets, but it is inside the user's
        # profile and this tool should not widen access to anything it writes.
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as fh:
            fh.write(updated)
    except OSError as exc:
        return False, f"could not write {path}: {exc}"

    if not firefox_asks_every_time(profile):
        return False, f"wrote {path} but the preference did not take effect"
    return True, ""


def inventory() -> list[Browser]:
    """Every browser that could hold a smart card configuration on this system."""
    profiles = _firefox_profiles()
    found: list[Browser] = []

    snap_confined = snap_firefox_confined()
    flatpak_present = flatpak_firefox_present()

    if profiles["native"] or (native_firefox_present() and not snap_confined):
        found.append(Browser(
            name="Firefox (system package)",
            packaging="native",
            confined=False,
            nss_databases=tuple(profiles["native"]),
            detail="runs with normal access to the host filesystem and to pcscd",
        ))

    if profiles["snap"] or snap_confined is not None:
        if snap_confined is None:
            detail = ("a snap Firefox is present but its confinement could not be "
                      "read; treating it as unverified rather than working")
            found.append(Browser(
                name="Firefox (snap)",
                packaging="snap",
                confined=True,
                nss_databases=tuple(profiles["snap"]),
                detail=detail,
            ))
        else:
            found.append(Browser(
                name="Firefox (snap, classic)" if not snap_confined else "Firefox (snap)",
                packaging="snap",
                confined=snap_confined,
                nss_databases=tuple(profiles["snap"]),
                detail=(
                    "classic confinement: the host PKCS#11 module is reachable"
                    if not snap_confined else
                    "sandboxed: the host PKCS#11 module is not reachable from inside"
                ),
            ))

    if profiles["flatpak"] or flatpak_present:
        found.append(Browser(
            name="Firefox (Flatpak)",
            packaging="flatpak",
            confined=True,
            nss_databases=tuple(profiles["flatpak"]),
            detail=(
                "sandboxed: a Flatpak Firefox cannot load a host PKCS#11 module. "
                "Mozilla does not support hardware tokens in the Flatpak build"
            ),
        ))

    dbs = chromium_databases()
    if dbs:
        found.append(Browser(
            name="Chromium / Electron",
            packaging="native",
            confined=False,
            nss_databases=tuple(dbs),
            detail="uses the shared NSS database in ~/.pki/nssdb",
        ))

    return found


# --- guidance ----------------------------------------------------------------
# Kept next to the detection so the two cannot drift. Each entry states what to
# do, and every one of them is a change the user can make and then re-check.

REMEDIATION = {
    "flatpak": (
        "The Flatpak build of Firefox cannot use a smart card: it is sandboxed "
        "and cannot load a host PKCS#11 module.\n"
        "  Install Firefox from your distribution's packages instead:\n"
        "    sudo apt remove flatpak firefox     # or your distribution's equivalent\n"
        "    sudo apt install firefox            # or: sudo dnf install firefox\n"
        "  Then run CONFIG BROWSERS again."
    ),
    "snap-strict": (
        "Your Firefox is a snap with strict confinement. It cannot load the "
        "host PKCS#11 module, so the card will not appear.\n"
        "  Reinstall it with classic confinement, which grants access to the "
        "host filesystem:\n"
        "    sudo snap remove firefox\n"
        "    sudo snap install --classic firefox\n"
        "  Then run CONFIG BROWSERS again."
    ),
    "snap-unknown": (
        "A snap Firefox is installed and its confinement could not be read, so "
        "Sentinel will not claim it works.\n"
        "  Check it yourself with:  snap list firefox\n"
        "  If the notes do not say 'classic', reinstall it with:\n"
        "    sudo snap remove firefox && sudo snap install --classic firefox"
    ),
    "no-browser": (
        "No browser with a smart card profile was found.\n"
        "  Start Firefox or Chrome once so it creates a profile, then run "
        "CONFIG BROWSERS again."
    ),
}


def guidance_for(browser: Browser) -> str:
    """What this user should do about this browser, in plain language."""
    if not browser.nss_databases:
        return REMEDIATION["no-browser"]
    if not browser.confined:
        return ""
    if browser.packaging == "flatpak":
        return REMEDIATION["flatpak"]
    if browser.packaging == "snap":
        return REMEDIATION["snap-strict"]
    return REMEDIATION["snap-unknown"]
