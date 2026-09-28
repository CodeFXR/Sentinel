"""Platform resolution tests.

No external test framework required:

    python3 tests/test_platform.py

These are pure data-path tests. They mock `distro`, so they run identically on
any machine and cannot touch the real trust store.
"""

import os
import sys
import tempfile
import unittest
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sentinel_platform as sp


class _FakeDistro:
    """Stands in for the `distro` module."""

    def __init__(self, ident="", pretty="", like=""):
        self._id, self._pretty, self._like = ident, pretty, like

    def id(self):
        return self._id

    def name(self, pretty=False):
        return self._pretty

    def like(self):
        return self._like


@contextmanager
def as_distro(fake, pkcs11="/usr/lib/opensc-pkcs11.so"):
    """Temporarily replace the distro module and the PKCS#11 probe."""
    saved = (sp.distro, sp.find_pkcs11_module)
    sp.distro = fake
    sp.find_pkcs11_module = lambda: pkcs11
    try:
        yield
    finally:
        sp.distro, sp.find_pkcs11_module = saved


@contextmanager
def as_home(path):
    """Temporarily point os.path.expanduser('~') at a temp directory."""
    real = os.path.expanduser
    os.path.expanduser = lambda p: p.replace("~", path, 1)
    try:
        yield
    finally:
        os.path.expanduser = real


class TestFamilyResolution(unittest.TestCase):
    """Every supported distro id and alias must land in the right family."""

    EXPECTED = {
        "fedora": "fedora",
        "rhel": "fedora",
        "centos": "fedora",
        "rocky": "fedora",
        "almalinux": "fedora",
        "ol": "fedora",
        "ubuntu": "debian",
        "debian": "debian",
        "linuxmint": "debian",
        "pop": "debian",
        "zorin": "debian",
        "raspbian": "debian",
        "arch": "arch",
        "manjaro": "arch",
        "endeavouros": "arch",
        "opensuse-leap": "suse",
        "opensuse-tumbleweed": "suse",
        "sles": "suse",
        "gentoo": "gentoo",
    }

    def test_each_id_maps_to_its_family(self):
        for ident, family in self.EXPECTED.items():
            with self.subTest(ident):
                with as_distro(_FakeDistro(ident, ident, ident)):
                    self.assertEqual(sp.detect().family, family)

    def test_like_token_used_when_id_unrecognised(self):
        with as_distro(_FakeDistro("myweirdos", "My Weird OS", "ubuntu debian")):
            self.assertEqual(sp.detect().family, "debian")

    def test_unknown_distro_is_unsupported(self):
        with as_distro(_FakeDistro("plan9", "Plan 9", "plan9")):
            platform = sp.detect()
        self.assertEqual(platform.family, "unknown")
        self.assertIsNone(platform.trust_anchor_dir)
        self.assertIsNone(platform.trust_refresh_cmd)
        self.assertFalse(platform.supported)

    def test_detection_failure_does_not_propagate(self):
        """A raising distro module must never crash application startup."""

        class Exploding:
            def id(self):
                raise RuntimeError("no /etc/os-release")

            def like(self):
                raise RuntimeError("no /etc/os-release")

            def name(self, pretty=False):
                raise RuntimeError("no /etc/os-release")

        with as_distro(Exploding()):
            platform = sp.detect()
        self.assertEqual(platform.family, "unknown")
        self.assertIsNone(platform.trust_anchor_dir)
        self.assertEqual(platform.name, "Unknown Linux")


class TestTrustStoreLayout(unittest.TestCase):
    """Each distribution must get the paths it actually uses."""

    def test_fedora_layout(self):
        with as_distro(_FakeDistro("fedora", "Fedora", "fedora")):
            p = sp.detect()
        self.assertEqual(p.trust_anchor_dir, "/etc/pki/ca-trust/source/anchors")
        self.assertEqual(p.trust_refresh_cmd, ("update-ca-trust",))

    def test_debian_layout(self):
        with as_distro(_FakeDistro("ubuntu", "Ubuntu", "ubuntu debian")):
            p = sp.detect()
        self.assertEqual(p.trust_anchor_dir, "/usr/local/share/ca-certificates")
        self.assertEqual(p.trust_refresh_cmd, ("update-ca-certificates",))
        self.assertTrue(p.trust_anchor_name.endswith(".crt"))

    def test_zorin_uses_the_debian_layout(self):
        """The distribution that originally broke the tool."""
        with as_distro(_FakeDistro("zorin", "Zorin OS 18", "ubuntu debian")):
            p = sp.detect()
        self.assertEqual(p.family, "debian")
        self.assertEqual(p.trust_anchor_dir, "/usr/local/share/ca-certificates")
        self.assertEqual(p.trust_refresh_cmd, ("update-ca-certificates",))
        self.assertTrue(p.install_hint().startswith("apt-get install"))

    def test_arch_layout(self):
        with as_distro(_FakeDistro("arch", "Arch", "arch")):
            p = sp.detect()
        self.assertEqual(
            p.trust_anchor_dir, "/etc/ca-certificates/trust/source/anchors"
        )
        self.assertEqual(p.trust_refresh_cmd, ("trust", "extract-compat"))

    def test_every_family_is_fully_specified(self):
        for key, spec in sp._FAMILIES.items():
            with self.subTest(key):
                self.assertTrue(spec["name"])
                self.assertTrue(spec["install_cmd"])
                self.assertTrue(spec["packages"])
                self.assertTrue(spec["trust_anchor_dir"])
                self.assertTrue(spec["trust_refresh_cmd"])

    def test_package_names_differ_per_family(self):
        """opensc's NSS tools package is named differently per distribution."""
        with as_distro(_FakeDistro("fedora", "Fedora", "fedora")):
            self.assertIn("nss-tools", sp.detect().packages)
        with as_distro(_FakeDistro("ubuntu", "Ubuntu", "ubuntu")):
            self.assertIn("libnss3-tools", sp.detect().packages)
        with as_distro(_FakeDistro("arch", "Arch", "arch")):
            self.assertIn("nss", sp.detect().packages)

    def test_install_hint_uses_native_package_manager(self):
        for ident, manager in (
            ("fedora", "dnf"),
            ("ubuntu", "apt-get"),
            ("arch", "pacman"),
            ("opensuse-leap", "zypper"),
        ):
            with self.subTest(ident):
                with as_distro(_FakeDistro(ident, ident, ident)):
                    hint = sp.detect().install_hint()
                self.assertTrue(hint.startswith(manager), hint)
                self.assertIn("opensc", hint)

    def test_install_hint_on_unknown_distro_degrades_to_text(self):
        with as_distro(_FakeDistro("plan9", "Plan 9", "plan9")):
            self.assertIn("manually", sp.detect().install_hint())


class TestPkcs11Discovery(unittest.TestCase):
    @contextmanager
    def ldconfig_output(self, stdout, glob_hits=()):
        """Mock both the ldconfig cache and the filesystem glob."""
        real_run, real_glob = sp.subprocess.run, sp.glob.glob
        sp.subprocess.run = lambda *a, **k: type(
            "R", (), {"stdout": stdout, "returncode": 0}
        )()
        sp.glob.glob = lambda pattern: list(glob_hits)
        try:
            yield
        finally:
            sp.subprocess.run, sp.glob.glob = real_run, real_glob

    def test_ldconfig_hit_is_preferred(self):
        cache = (
            "\tlibfoo.so.1 (libc6,x86-64) => /lib64/libfoo.so.1\n"
            "\topensc-pkcs11.so (libc6,x86-64) => /usr/lib64/opensc-pkcs11.so.0.27.0\n"
        )
        with self.ldconfig_output(cache):
            found = sp.find_pkcs11_module()
        self.assertEqual(found, "/usr/lib64/opensc-pkcs11.so.0.27.0")

    def test_glob_used_when_ldconfig_has_no_entry(self):
        with self.ldconfig_output("", glob_hits=["/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"]):
            self.assertEqual(
                sp.find_pkcs11_module(), "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
            )

    def test_missing_module_returns_none(self):
        with self.ldconfig_output(""):
            self.assertIsNone(sp.find_pkcs11_module())

    def test_glob_patterns_cover_multiarch_debian_layout(self):
        self.assertTrue(
            any("linux-gnu" in p for p in sp._PKCS11_PATTERNS),
            "must glob the Debian/Ubuntu multiarch path, not just /usr/lib64",
        )
        self.assertTrue(any(p.startswith("/usr/lib64/") for p in sp._PKCS11_PATTERNS))


class TestNssDatabases(unittest.TestCase):
    def test_finds_real_profiles_and_skips_decoys(self):
        with tempfile.TemporaryDirectory() as home:
            nssdb = os.path.join(home, ".pki", "nssdb")
            profile = os.path.join(
                home, ".mozilla", "firefox", "abc.default-release"
            )
            decoy = os.path.join(home, ".mozilla", "firefox", "Crash Reports")
            flatpak = os.path.join(
                home, ".var", "app", "org.mozilla.firefox",
                ".mozilla", "firefox", "xyz.default",
            )
            for d in (nssdb, profile, decoy, flatpak):
                os.makedirs(d)
            for p in (profile, flatpak):
                open(os.path.join(p, "cert9.db"), "w").close()

            with as_home(home):
                found = sp.nss_databases()

            self.assertIn(nssdb, found)
            self.assertIn(profile, found)
            self.assertIn(flatpak, found)
            self.assertNotIn(decoy, found, "a dir without cert9.db is not a profile")
            self.assertEqual(len(found), len(set(found)), "paths must be unique")

    def test_missing_directories_are_not_reported(self):
        with tempfile.TemporaryDirectory() as home:
            with as_home(home):
                self.assertEqual(sp.nss_databases(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
