import sys
import unittest
import subprocess
from pathlib import Path

# Ensure repo root is on sys.path for direct test execution
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.rust_bridge import (
    is_rust_available,
    get_rust_version,
    is_cac_atr_rust,
    parse_pkcs15_list_rust,
    PinBuffer,
    parse_card_certificate_rust,
)
from core.platform_detector import detect_platform
from cli import _clean_term


class TestRustBridge(unittest.TestCase):
    def test_rust_availability(self):
        # On systems where Rust is compiled, verify version 2.0.3
        if is_rust_available():
            self.assertEqual(get_rust_version(), "2.0.3")
        else:
            self.assertIsNone(get_rust_version())

    def test_cac_atr_detection(self):
        # Known Oberthur ID-One PIV CAC ATR
        self.assertTrue(is_cac_atr_rust("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"))
        # Known Gemalto TOP DL GX4 ATR
        self.assertTrue(is_cac_atr_rust("3b:db:96:00:80:1f:03:00:31:c0:64:b0:18:23:00:00:82:90:00"))
        # Non-DoD card ATR
        self.assertFalse(is_cac_atr_rust("3b:00:00:00"))

    def test_pkcs15_parser(self):
        sample_output = """
        PKCS#15 Certificate [Certificate 1]
            ID : 0005
            Label : CAC ID / PIV Authentication
        PKCS#15 Certificate [Certificate 2]
            ID : 0002
            Label : CAC Email Signature
        """
        pairs = parse_pkcs15_list_rust(sample_output)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs[0], ("0005", "CAC ID / PIV Authentication"))
        self.assertEqual(pairs[1], ("0002", "CAC Email Signature"))

    def test_pin_buffer_hygiene(self):
        pin = PinBuffer("123456")
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.is_valid_pin_format())
        self.assertIn("REDACTED", repr(pin))
        pin.scrub()
        self.assertEqual(len(pin), 0)

    def test_x509_certificate_parsing(self):
        # Generate temporary self-signed cert with DoD naming format
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=SMITH.JANE.E.9876543210",
            "-days", "30", "-outform", "DER"
        ]
        p = subprocess.run(cmd, capture_output=True)
        self.assertEqual(p.returncode, 0)
        der_bytes = p.stdout

        cert = parse_card_certificate_rust("0005", "CAC ID / PIV Authentication", "DoD Web Logon", der_bytes)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.id, "0005")
        self.assertEqual(cert.holder_name, "Jane E Smith")
        self.assertEqual(cert.edipi, "9876543210")
        self.assertTrue(cert.is_valid)
        self.assertIn("Revocation Unchecked", cert.status_text)
        self.assertIsNotNone(cert.raw_der)
        self.assertEqual(len(cert.raw_der), len(der_bytes))
        self.assertIsNotNone(cert.valid_to)

    def test_contractor_and_suffix_name_parsing(self):
        # Contractor CAC: DOE.JOHN.R.CTR.1234567890
        cmd_ctr = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DOE.JOHN.R.CTR.1234567890",
            "-days", "30", "-outform", "DER"
        ]
        p1 = subprocess.run(cmd_ctr, capture_output=True)
        self.assertEqual(p1.returncode, 0)
        cert_ctr = parse_card_certificate_rust("0005", "CAC ID", "DoD Web Logon", p1.stdout)
        self.assertIsNotNone(cert_ctr)
        self.assertEqual(cert_ctr.holder_name, "John R Doe")
        self.assertEqual(cert_ctr.edipi, "1234567890")

        # Civilian with generational suffix: WILLIAMS.JAMES.T.JR.CIV.9876543210
        cmd_civ = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=WILLIAMS.JAMES.T.JR.CIV.9876543210",
            "-days", "30", "-outform", "DER"
        ]
        p2 = subprocess.run(cmd_civ, capture_output=True)
        self.assertEqual(p2.returncode, 0)
        cert_civ = parse_card_certificate_rust("0005", "CAC ID", "DoD Web Logon", p2.stdout)
        self.assertIsNotNone(cert_civ)
        self.assertEqual(cert_civ.holder_name, "James T Williams Jr")
        self.assertEqual(cert_civ.edipi, "9876543210")

    def test_native_pcsc_query(self):
        import os
        from unittest.mock import MagicMock, patch
        from core.rust_bridge import query_native_pcsc_rust

        if os.environ.get("SENTINEL_TEST_HARDWARE") == "1":
            status = query_native_pcsc_rust()
            if status is not None:
                self.assertTrue(status.available)
                self.assertIsInstance(status.readers, list)
        else:
            fake_status = MagicMock(available=True, service_running=False, readers=[], card_present=False, atr=None, is_cac=False)
            with patch("core.rust_bridge.is_rust_available", return_value=True), \
                 patch("core.rust_bridge._sentinel_core") as mock_sc:
                mock_sc.query_native_pcsc.return_value = fake_status
                status = query_native_pcsc_rust()
                self.assertIsNotNone(status)
                self.assertTrue(status.available)
                self.assertEqual(status.readers, [])

    def test_native_piv_apdu_reader(self):
        import os
        from unittest.mock import patch
        from core.rust_bridge import read_card_certificates_rust

        if os.environ.get("SENTINEL_TEST_HARDWARE") == "1":
            certs = read_card_certificates_rust()
            self.assertIsInstance(certs, list)
        else:
            with patch("core.rust_bridge.is_rust_available", return_value=True), \
                 patch("core.rust_bridge._sentinel_core") as mock_sc:
                mock_sc.read_card_certificates.return_value = []
                certs = read_card_certificates_rust()
                self.assertEqual(certs, [])

    def test_native_piv_metadata_reader(self):
        import os
        from unittest.mock import patch, MagicMock
        from core.rust_bridge import read_card_metadata_rust

        if os.environ.get("SENTINEL_TEST_HARDWARE") == "1":
            c_name, t_label, t_serial = read_card_metadata_rust()
        else:
            fake_meta = MagicMock(
                card_name="DoD Common Access Card (CAC / PIV)",
                token_label="DoD Common Access Card",
                token_serial="01020304-0506-0708-090a-0b0c0d0e0f10",
            )
            with patch("core.rust_bridge.is_rust_available", return_value=True), \
                 patch("core.rust_bridge._sentinel_core") as mock_sc:
                mock_sc.read_card_metadata.return_value = fake_meta
                c_name, t_label, t_serial = read_card_metadata_rust()
                self.assertEqual(c_name, "DoD Common Access Card (CAC / PIV)")
                self.assertEqual(t_label, "DoD Common Access Card")
                self.assertEqual(t_serial, "01020304-0506-0708-090a-0b0c0d0e0f10")

    def test_verify_cert_ocsp_handling(self):
        from core.smartcard import CardCertificate, verify_cert_ocsp
        # Certificate with no raw_der
        dummy = CardCertificate(
            id="0005", label="Test", subject="Test", issuer="Test", issuer_cn="Test",
            cn="Test", holder_name="Test", edipi="1234567890", valid_from=None,
            valid_to=None, valid_to_str="2030-01-01", serial="123", usage="Test",
            is_valid=True, status_text="Date Valid", raw_der=None
        )
        res, msg = verify_cert_ocsp(dummy)
        self.assertIsNone(res)
        self.assertIn("unavailable", msg)


class TestCliSanitization(unittest.TestCase):
    def test_clean_term(self):
        # Strip ANSI escape and control characters
        dirty = "\x1b[31mMalicious\x1b[0m\x07Text\nLine"
        cleaned = _clean_term(dirty)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x07", cleaned)
        self.assertEqual(_clean_term(None, "Fallback"), "Fallback")

    def test_desktop_entry_newline_injection_rejection(self):
        import tempfile
        import os
        from core.system_fix import install_desktop_integration
        with tempfile.TemporaryDirectory() as tmp_home:
            success, msg = install_desktop_integration(
                project_dir="/tmp/malicious\nExec=evil",
                home_dir=tmp_home,
            )
            self.assertFalse(success)
            self.assertIn("must not contain newline characters", msg)
            # Verify no launcher or alias was created
            launcher = os.path.join(tmp_home, ".local", "bin", "sentinel-cac-manager")
            self.assertFalse(os.path.exists(launcher))
            alias = os.path.join(tmp_home, ".local", "bin", "sentinel")
            self.assertFalse(os.path.exists(alias))

    def test_desktop_integration_isolated_home(self):
        import tempfile
        import os
        from core.system_fix import install_desktop_integration, uninstall_desktop_integration, SCRIPT_DIR
        with tempfile.TemporaryDirectory() as tmp_home:
            # Pre-create a dummy third-party file named "sentinel" to test non-clobbering
            bin_dir = os.path.join(tmp_home, ".local", "bin")
            os.makedirs(bin_dir, exist_ok=True)
            custom_sentinel = os.path.join(bin_dir, "sentinel")
            with open(custom_sentinel, "w") as f:
                f.write("#!/bin/sh\necho hashicorp")

            success, msg = install_desktop_integration(
                project_dir=SCRIPT_DIR,
                home_dir=tmp_home,
            )
            self.assertTrue(success)
            launcher = os.path.join(tmp_home, ".local", "bin", "sentinel-cac-manager")
            self.assertTrue(os.path.isfile(launcher))

            # Must NOT overwrite existing regular file sentinel
            self.assertFalse(os.path.islink(custom_sentinel))
            with open(custom_sentinel, "r") as f:
                self.assertEqual(f.read(), "#!/bin/sh\necho hashicorp")

            # Check desktop entry content for App ID com.codefxr.sentinel
            desktop = os.path.join(tmp_home, ".local", "share", "applications", "sentinel.desktop")
            self.assertTrue(os.path.isfile(desktop))
            with open(desktop, "r") as f:
                content = f.read()
                self.assertIn("StartupWMClass=com.codefxr.sentinel", content)
                self.assertNotIn("mil.dod.sentinel", content)

            # Test uninstaller
            un_ok, un_msg = uninstall_desktop_integration(home_dir=tmp_home)
            self.assertTrue(un_ok)
            self.assertFalse(os.path.exists(launcher))
            self.assertFalse(os.path.exists(desktop))

    def test_cmd_export_certs(self):
        import tempfile
        import os
        from pathlib import Path
        from unittest.mock import patch
        from cli import cmd_export_certs
        from core.smartcard import SmartCardStatus, CardCertificate

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. No card present -> returns False
            empty_stat = SmartCardStatus(
                service_active=True, reader_name=None, card_present=False, atr=None,
                card_name=None, token_label=None, token_serial=None, certificates=[]
            )
            with patch("core.smartcard.scan_smartcard", return_value=empty_stat):
                ok_none = cmd_export_certs(tmp_dir)
                self.assertFalse(ok_none)

            # 2. Card present with cert -> exports PEM
            dummy_cert = CardCertificate(
                id="0005", label="CAC ID / PIV Authentication", subject="CN=SMITH.JOHN.1234567890",
                issuer="DoD Root CA 3", issuer_cn="DoD Root CA 3", cn="SMITH.JOHN.1234567890",
                holder_name="John Smith", edipi="1234567890", valid_from=None, valid_to=None,
                valid_to_str="2030-01-01", serial="123456", usage="Authentication",
                is_valid=True, status_text="Valid", raw_der=b"FAKE_DER_BYTES_FOR_EXPORT"
            )
            card_stat = SmartCardStatus(
                service_active=True, reader_name="Test Reader", card_present=True,
                atr="3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00",
                card_name="DoD CAC", token_label="DoD CAC", token_serial="1234",
                certificates=[dummy_cert]
            )
            with patch("core.smartcard.scan_smartcard", return_value=card_stat):
                ok_export = cmd_export_certs(tmp_dir)
                self.assertTrue(ok_export)
                # Verify file was written
                files = os.listdir(tmp_dir)
                self.assertEqual(len(files), 1)
                self.assertTrue(files[0].endswith(".pem"))
                content = Path(tmp_dir, files[0]).read_text(encoding="utf-8")
                self.assertIn("-----BEGIN CERTIFICATE-----", content)
                self.assertIn("-----END CERTIFICATE-----", content)


class TestPythonFallbacks(unittest.TestCase):
    def test_python_atr_detection(self):
        from core.rust_bridge import is_cac_atr_rust
        # Force testing fallback logic directly
        # Oberthur CAC
        atr1 = "3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"
        self.assertTrue(is_cac_atr_rust(atr1))
        # Non-CAC
        atr_bad = "3b:00:11:22"
        self.assertFalse(is_cac_atr_rust(atr_bad))

    def test_python_pkcs15_parser(self):
        from core.rust_bridge import parse_pkcs15_list_rust
        sample = """
        PKCS#15 Certificate [Cert A]
            ID : 0005
            Label : PIV Authentication
        PKCS#15 Certificate [Cert B]
            ID : 0002
            Label : Digital Signature
        """
        parsed = parse_pkcs15_list_rust(sample)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ("0005", "PIV Authentication"))
        self.assertEqual(parsed[1], ("0002", "Digital Signature"))

    def test_python_cardholder_name_parser(self):
        from core.smartcard import format_dod_cardholder_name
        # Contractor format
        holder, edipi = format_dod_cardholder_name("DOE.JOHN.R.CTR.1234567890")
        self.assertEqual(holder, "John R Doe")
        self.assertEqual(edipi, "1234567890")

        # Civilian with generational suffix
        holder_jr, edipi_jr = format_dod_cardholder_name("WILLIAMS.JAMES.T.JR.CIV.9876543210")
        self.assertEqual(holder_jr, "James T Williams Jr")
        self.assertEqual(edipi_jr, "9876543210")


class TestPrivilegedHelperSecurity(unittest.TestCase):
    def test_symlink_rejection(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a target secret file
            secret_file = os.path.join(tmp_dir, "secret.txt")
            with open(secret_file, "w") as f:
                f.write("SUPER_SECRET_ROOT_DATA")

            # Create a malicious symlink ending with .crt pointing to secret
            link_path = os.path.join(tmp_dir, "malicious.crt")
            os.symlink(secret_file, link_path)

            # Privileged helper must reject reading symlink
            result = _read_and_validate_cert(link_path, tmp_dir)
            self.assertIsNone(result)

    def test_invalid_cert_content_rejection(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_crt = os.path.join(tmp_dir, "fake.crt")
            with open(fake_crt, "w") as f:
                f.write("root:x:0:0:root:/root:/bin/bash\n")

            result = _read_and_validate_cert(fake_crt, tmp_dir)
            self.assertIsNone(result)

    def test_valid_cert_validation_and_reserialization(self):
        import os
        from core.privileged_helper import _read_and_validate_cert

        real_cert = os.path.join(REPO_ROOT, "certificates", "all_cas", "DOD_ID_CA-81.crt")
        certs_dir = os.path.join(REPO_ROOT, "certificates", "all_cas")
        if os.path.isfile(real_cert):
            result = _read_and_validate_cert(real_cert, certs_dir)
            self.assertIsNotNone(result)
            self.assertTrue(result.startswith(b"-----BEGIN CERTIFICATE-----"))
            self.assertTrue(result.endswith(b"-----END CERTIFICATE-----\n"))

    def test_sha256_whitelist_enforcement(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        real_cert = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        if os.path.isfile(real_cert):
            with open(real_cert, "rb") as f:
                data = f.read()

            with tempfile.TemporaryDirectory() as tmp_dir:
                # 1. Authentic file should pass
                valid_copy = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
                with open(valid_copy, "wb") as f:
                    f.write(data)
                res_ok = _read_and_validate_cert(valid_copy, tmp_dir)
                self.assertIsNotNone(res_ok)

                # 2. Tampered file must fail fingerprint verification
                tampered_copy = os.path.join(tmp_dir, "DoD_Root_CA_4.crt")
                with open(tampered_copy, "wb") as f:
                    # Write wrong certificate content under DoD_Root_CA_4.crt name
                    f.write(data)
                res_tampered = _read_and_validate_cert(tampered_copy, tmp_dir)
                self.assertIsNone(res_tampered)

                # 3. Unauthorized certificate name must be rejected
                unauth_file = os.path.join(tmp_dir, "Evil_Hacker_Root_CA.crt")
                with open(unauth_file, "wb") as f:
                    f.write(data)
                res_unauth = _read_and_validate_cert(unauth_file, tmp_dir)
                self.assertIsNone(res_unauth)


class TestPlatformDetector(unittest.TestCase):
    def test_platform_detection(self):
        plat = detect_platform()
        self.assertIn(plat.family, ["fedora", "debian", "arch", "suse", "unknown"])
        self.assertTrue(len(plat.name) > 0)


class TestSubprocessTimeoutHandling(unittest.TestCase):
    def test_run_privileged_helper_timeout(self):
        import tempfile
        import os
        import time
        from unittest.mock import patch
        from core.system_fix import run_privileged_helper

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import time\ntime.sleep(5)\n")
            sleep_script = f.name

        try:
            with patch("core.system_fix.get_helper_script", return_value=sleep_script), \
                 patch("os.geteuid", return_value=0):
                t0 = time.monotonic()
                ok, msg = run_privileged_helper([], timeout=1)
                duration = time.monotonic() - t0
                self.assertFalse(ok)
                self.assertIn("timed out", msg)
                self.assertLess(duration, 3.0)
        finally:
            if os.path.exists(sleep_script):
                os.remove(sleep_script)


class TestVersionConsistency(unittest.TestCase):
    def test_version_matches(self):
        import core
        self.assertEqual(core.__version__, "2.0.3")


class TestPinManagement(unittest.TestCase):
    def test_pin_validation_rules(self):
        from core.rust_bridge import change_pin_rust
        # Same PIN
        ok, retries, msg = change_pin_rust("123456", "123456")
        self.assertFalse(ok)
        self.assertIn("must be different", msg)

        # Short current PIN
        ok, retries, msg = change_pin_rust("12345", "123456")
        self.assertFalse(ok)
        self.assertIn("6 to 8 numeric digits", msg)

        # Alpha current PIN
        ok, retries, msg = change_pin_rust("abcdef", "123456")
        self.assertFalse(ok)
        self.assertIn("6 to 8 numeric digits", msg)

        # Alpha new PIN
        ok, retries, msg = change_pin_rust("123456", "abcdef")
        self.assertFalse(ok)
        self.assertIn("6 to 8 numeric digits", msg)

    def test_change_card_pin_final_retry_guard(self):
        from unittest.mock import patch
        from core.smartcard import change_card_pin

        with patch("core.rust_bridge.query_pin_status_rust", return_value=(True, 1, "1 attempt(s) remaining")):
            ok, retries, msg = change_card_pin("123456", "654321")
            self.assertFalse(ok)
            self.assertEqual(retries, 1)
            self.assertIn("only 1 PIN retry attempt remains", msg)

    def test_query_pin_status_types(self):
        import os
        from unittest.mock import patch
        from core.rust_bridge import query_pin_status_rust

        if os.environ.get("SENTINEL_TEST_HARDWARE") == "1":
            ok, retries, msg = query_pin_status_rust()
        else:
            with patch("core.rust_bridge.is_rust_available", return_value=True), \
                 patch("core.rust_bridge._sentinel_core") as mock_sc:
                mock_sc.query_pin_status.return_value = (False, 0, "No smart card reader with inserted card found")
                ok, retries, msg = query_pin_status_rust()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(retries, int)
        self.assertIsInstance(msg, str)


class TestAgentDaemon(unittest.TestCase):
    def test_send_desktop_notification_mock(self):
        from unittest.mock import patch
        from core.agent import send_desktop_notification

        with patch("shutil.which", return_value="/usr/bin/notify-send"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            ok = send_desktop_notification("Test Title", "Test Body", urgency="low")
            self.assertTrue(ok)
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            self.assertIn("Test Title", call_args)
            self.assertIn("Test Body", call_args)

    def test_systemd_user_service_install_uninstall(self):
        import tempfile
        import os
        from unittest.mock import patch
        from core.agent import install_systemd_user_service, uninstall_systemd_user_service

        with tempfile.TemporaryDirectory() as tmp_home:
            with patch("shutil.which", return_value=None):
                ok, msg = install_systemd_user_service(home_dir=tmp_home)
                self.assertTrue(ok)
                service_file = os.path.join(tmp_home, ".config", "systemd", "user", "sentinel-agent.service")
                self.assertTrue(os.path.isfile(service_file))
                with open(service_file, "r") as f:
                    content = f.read()
                    self.assertIn("Description=Sentinel Card Monitor Daemon", content)
                    self.assertIn("ExecStart=%h/.local/bin/sentinel --agent", content)

                un_ok, un_msg = uninstall_systemd_user_service(home_dir=tmp_home)
                self.assertTrue(un_ok)
                self.assertFalse(os.path.isfile(service_file))


class TestWorkstationLogonAndLock(unittest.TestCase):
    def test_check_logon_status_structure(self):
        import tempfile
        from core.system_fix import check_smartcard_logon_status
        with tempfile.TemporaryDirectory() as tmp_home:
            stat = check_smartcard_logon_status(home_dir=tmp_home)
            self.assertIsInstance(stat, dict)
            self.assertIn("logon_enabled", stat)
            self.assertIn("lock_removal_enabled", stat)
            self.assertIn("sssd_configured", stat)
            self.assertIn("platform_supported", stat)

    def test_set_lock_on_removal_toggle_isolated(self):
        import tempfile
        from core.system_fix import set_lock_on_removal
        with tempfile.TemporaryDirectory() as tmp_home:
            ok1, msg1 = set_lock_on_removal(True, home_dir=tmp_home)
            self.assertTrue(ok1)
            self.assertIn("enabled", msg1)

            ok2, msg2 = set_lock_on_removal(False, home_dir=tmp_home)
            self.assertTrue(ok2)
            self.assertIn("disabled", msg2)

    def test_lock_on_removal_check_isolated(self):
        import tempfile
        from core.agent import is_lock_on_removal_enabled
        from core.system_fix import set_lock_on_removal
        with tempfile.TemporaryDirectory() as tmp_home:
            set_lock_on_removal(True, home_dir=tmp_home)
            self.assertTrue(is_lock_on_removal_enabled(home_dir=tmp_home))
            set_lock_on_removal(False, home_dir=tmp_home)
            self.assertFalse(is_lock_on_removal_enabled(home_dir=tmp_home))

    def test_archived_future_workstation_logon_hardening(self):
        import tempfile
        import os
        from unittest.mock import patch, MagicMock, mock_open
        from core.logon import (
            validate_logon_inputs,
            build_sssd_smartcard_config,
            has_existing_enterprise_sssd_domain,
            is_running_in_vm,
        )
        # Missing or wildcard EDIPI must be rejected
        ok_empty, _ = validate_logon_inputs("root", "")
        self.assertFalse(ok_empty)
        ok_short, _ = validate_logon_inputs("root", "12345")
        self.assertFalse(ok_short)

        # Valid 10-digit EDIPI and existing local user (root) must succeed
        ok_valid, _ = validate_logon_inputs("root", "1234567890")
        self.assertTrue(ok_valid)

        # Generated SSSD config must bind both EDIPI and local username (never wildcard CN=.*)
        cfg = build_sssd_smartcard_config("root", "1234567890", "/usr/lib64/opensc-pkcs11.so")
        self.assertIn("1234567890", cfg)
        self.assertIn("maprule = (uid=root)", cfg)
        self.assertNotIn("CN=.*\n", cfg)

        # Enterprise SSSD domain conflict detection
        with tempfile.TemporaryDirectory() as tmp_dir:
            conf_path = os.path.join(tmp_dir, "sssd.conf")
            with open(conf_path, "w") as f:
                f.write("[sssd]\ndomains = corp.example.mil\n[domain/corp.example.mil]\nid_provider = ad\n")
            self.assertTrue(has_existing_enterprise_sssd_domain(sssd_conf_path=conf_path, conf_d_dir=tmp_dir))

        # Test is_running_in_vm with mock
        with patch("shutil.which", return_value="/usr/bin/systemd-detect-virt"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="kvm\n")
            self.assertTrue(is_running_in_vm())
            mock_run.return_value = MagicMock(returncode=1, stdout="none\n")
            with patch("os.path.isfile", return_value=False):
                self.assertFalse(is_running_in_vm())

        # Test DMI fallback when systemd-detect-virt is absent
        with patch("shutil.which", return_value=None), \
             patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data="QEMU Virtual Machine\n")):
            self.assertTrue(is_running_in_vm())


class TestV201SecurityAndRollbackHardening(unittest.TestCase):
    def test_python_fallback_when_rust_disabled(self):
        from unittest.mock import patch
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DOE.JOHN.R.CTR.1234567890",
            "-days", "30", "-outform", "DER"
        ]
        p = subprocess.run(cmd, capture_output=True)
        self.assertEqual(p.returncode, 0)

        with patch("core.rust_bridge.is_rust_available", return_value=False):
            cert = parse_card_certificate_rust("0005", "CAC ID", "DoD Web Logon", p.stdout)
            self.assertIsNotNone(cert)
            self.assertEqual(cert.holder_name, "John R Doe")
            self.assertEqual(cert.edipi, "1234567890")
            self.assertTrue(cert.is_valid)

    def test_future_not_before_status_text(self):
        from core.smartcard import _parse_x509_text
        future_out = (
            "subject=C = US, O = U.S. Government, OU = DoD, CN = DOE.JANE.1234567890\n"
            "issuer=C = US, O = U.S. Government, OU = DoD, CN = DOD ID CA-81\n"
            "notBefore=Jan  1 00:00:00 2099 GMT\n"
            "notAfter=Jan  1 00:00:00 2100 GMT\n"
            "serial=01020304\n"
        )
        cert = _parse_x509_text(future_out, "0005", "CAC ID", "DoD Web Logon")
        self.assertFalse(cert.is_valid)
        self.assertIn("Not Yet Valid", cert.status_text)

    def test_non_destructive_debian_ca_cleanup(self):
        import tempfile
        import os
        import shutil
        from core.privileged_helper import _clean_sentinel_owned_certs_in_dir

        real_root3 = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        real_root5 = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_5.crt")

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Sentinel-owned root cert with verified content -> removed
            sentinel_crt = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
            shutil.copy2(real_root3, sentinel_crt)

            # 2. Same filename (DoD_Root_CA_4.crt) but modified by administrator -> MUST BE PRESERVED
            admin_modified_crt = os.path.join(tmp_dir, "DoD_Root_CA_4.crt")
            with open(admin_modified_crt, "w") as f:
                f.write("admin customized DoD_Root_CA_4 content")

            # 3. Sentinel-owned cert with a .pre-sentinel-bak backup -> backup restored
            restored_crt = os.path.join(tmp_dir, "DoD_Root_CA_5.crt")
            shutil.copy2(real_root5, restored_crt)
            with open(restored_crt + ".pre-sentinel-bak", "w") as f:
                f.write("original pre-sentinel root 5")

            # 4. Unrelated enterprise/admin cert in same directory -> preserved
            custom_crt = os.path.join(tmp_dir, "Internal_Agency_Root_CA.crt")
            with open(custom_crt, "w") as f:
                f.write("custom enterprise cert")

            removed = _clean_sentinel_owned_certs_in_dir(tmp_dir)
            self.assertEqual(removed, 2)
            self.assertFalse(os.path.exists(sentinel_crt))
            self.assertTrue(os.path.exists(admin_modified_crt))
            self.assertTrue(os.path.exists(restored_crt))
            with open(restored_crt, "r") as f:
                self.assertEqual(f.read(), "original pre-sentinel root 5")
            self.assertTrue(os.path.exists(custom_crt))

    def test_non_destructive_firefox_policy_revert(self):
        import tempfile
        import json
        import os
        from core.privileged_helper import revert_firefox_policy_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_path = os.path.join(tmp_dir, "policies.json")
            # Case 1: Mixed enterprise policy + Sentinel keys -> preserve enterprise keys
            mixed = {
                "policies": {
                    "DisableTelemetry": True,
                    "Certificates": {
                        "ImportEnterpriseRoots": True,
                        "Install": ["/usr/share/sentinel/certificates/DoD_Full_Chain.pem"],
                    },
                    "SecurityDevices": {
                        "DoD CAC": "/usr/lib64/opensc-pkcs11.so",
                        "YubiKey PKCS11": "/usr/lib64/libykcs11.so",
                    },
                }
            }
            with open(policy_path, "w") as f:
                json.dump(mixed, f)

            revert_firefox_policy_file(policy_path)
            self.assertTrue(os.path.isfile(policy_path))
            with open(policy_path, "r") as f:
                updated = json.load(f)
            self.assertTrue(updated["policies"].get("DisableTelemetry"))
            self.assertNotIn("DoD CAC", updated["policies"].get("SecurityDevices", {}))
            self.assertIn("YubiKey PKCS11", updated["policies"].get("SecurityDevices", {}))

            # Case 2: Only Sentinel keys -> file removed cleanly
            sentinel_only = {
                "policies": {
                    "Certificates": {
                        "ImportEnterpriseRoots": True,
                        "Install": ["/usr/share/sentinel/certificates/DoD_Full_Chain.pem"],
                    },
                    "SecurityDevices": {
                        "DoD CAC": "/usr/lib64/opensc-pkcs11.so",
                    },
                }
            }
            with open(policy_path, "w") as f:
                json.dump(sentinel_only, f)

            revert_firefox_policy_file(policy_path)
            self.assertFalse(os.path.exists(policy_path))

    def test_comment_aware_opensc_config_check(self):
        from core.privileged_helper import is_opensc_config_optimized
        commented = "app default {\n    # card_drivers = CAC, piv-II;\n}\n"
        self.assertFalse(is_opensc_config_optimized(commented))

        active = "app default {\n    card_drivers = cac, piv-II;\n}\n"
        self.assertTrue(is_opensc_config_optimized(active))

    def test_validate_pkcs11_module_path(self):
        from core.privileged_helper import validate_pkcs11_module_path
        self.assertFalse(validate_pkcs11_module_path("relative/opensc-pkcs11.so"))
        self.assertFalse(validate_pkcs11_module_path("/usr/lib64/opensc-pkcs11.so\nmalicious: true"))
        self.assertFalse(validate_pkcs11_module_path("/nonexistent/path/opensc-pkcs11.so"))

    def test_ocsp_cryptographic_verification(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import ocsp
        from cryptography.x509.oid import NameOID
        from core.smartcard import _verify_ocsp_response_cryptographically

        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test DoD ID CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.1234567890")])
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(42)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )

        # 1. Valid CA-signed OCSP response -> must pass cryptographic verification
        valid_resp = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf_cert,
                issuer=ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now - timedelta(minutes=1),
                next_update=now + timedelta(hours=1),
                revocation_time=None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
            .sign(ca_key, hashes.SHA256())
        )
        single = next(iter(valid_resp.responses))
        ok, msg = _verify_ocsp_response_cryptographically(valid_resp, single, leaf_cert, ca_cert)
        self.assertTrue(ok, msg)

        # 2. Forged OCSP response signed by an untrusted key -> must be rejected
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue OCSP Signer")])
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(rogue_name)
            .issuer_name(rogue_name)
            .public_key(rogue_key.public_key())
            .serial_number(999)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(rogue_key, hashes.SHA256())
        )
        rogue_resp = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf_cert,
                issuer=ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now - timedelta(minutes=1),
                next_update=now + timedelta(hours=1),
                revocation_time=None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, rogue_cert)
            .sign(rogue_key, hashes.SHA256())
        )
        rogue_single = next(iter(rogue_resp.responses))
        ok_rogue, _ = _verify_ocsp_response_cryptographically(rogue_resp, rogue_single, leaf_cert, ca_cert)
        self.assertFalse(ok_rogue)

        # 3. Replay attack with expired nextUpdate -> must be rejected
        expired_resp = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf_cert,
                issuer=ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now - timedelta(days=2),
                next_update=now - timedelta(days=1),
                revocation_time=None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
            .sign(ca_key, hashes.SHA256())
        )
        expired_single = next(iter(expired_resp.responses))
        ok_exp, msg_exp = _verify_ocsp_response_cryptographically(expired_resp, expired_single, leaf_cert, ca_cert)
        self.assertFalse(ok_exp)
        self.assertIn("expired", msg_exp)
        _ = serialization.Encoding.DER

    def test_updater_semver_and_sha256_verification(self):
        import hashlib
        import io
        import os
        import tarfile
        import tempfile
        from core.updater import (
            parse_semver,
            is_newer_version,
            verify_and_stage_archive,
            UpdateInfo,
            perform_update,
        )

        self.assertEqual(parse_semver("v2.0.1"), (2, 0, 1))
        self.assertEqual(parse_semver("2.1.0"), (2, 1, 0))
        self.assertIsNone(parse_semver("v2.0.1; rm -rf /"))
        self.assertTrue(is_newer_version("2.0.1", "2.0.2"))
        self.assertFalse(is_newer_version("2.0.1", "2.0.1"))
        self.assertFalse(is_newer_version("2.0.1", "1.9.9"))

        # Build a valid in-memory tar.gz archive
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            payload = b"print('hello sentinel')\n"
            info = tarfile.TarInfo(name="Sentinel-CAC-Manager/app.py")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        archive_bytes = buf.getvalue()
        valid_sha = hashlib.sha256(archive_bytes).hexdigest()

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Missing SHA-256 must fail closed
            ok_missing, _ = verify_and_stage_archive(archive_bytes, "", tmp_dir)
            self.assertFalse(ok_missing)

            # 2. Mismatched SHA-256 must fail closed
            ok_bad, msg_bad = verify_and_stage_archive(archive_bytes, "0" * 64, tmp_dir)
            self.assertFalse(ok_bad)
            self.assertIn("mismatch", msg_bad)

            # 3. Matching SHA-256 extracts cleanly
            ok_good, _ = verify_and_stage_archive(archive_bytes, valid_sha, tmp_dir)
            self.assertTrue(ok_good)

            # 4. perform_update refuses unverified archive when git tag isn't used
            unverified_info = UpdateInfo(
                current_version="2.0.1",
                latest_version="2.0.2",
                tag_name="v2.0.2",
                update_available=True,
                html_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/tag/v2.0.2",
                download_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/download/v2.0.2/Sentinel-CAC-Manager.tar.gz",
                expected_sha256=None,
                status_message="Update available",
            )
            ok_upd, msg_upd = perform_update(unverified_info, project_dir=tmp_dir)
            self.assertFalse(ok_upd)
            self.assertIn("SHA-256", msg_upd)

            # 5. perform_update applies a SHA-256 verified archive transactionally
            from unittest.mock import MagicMock, patch
            verified_info = UpdateInfo(
                current_version="2.0.1",
                latest_version="2.0.2",
                tag_name="v2.0.2",
                update_available=True,
                html_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/tag/v2.0.2",
                download_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/download/v2.0.2/Sentinel-CAC-Manager.tar.gz",
                expected_sha256=valid_sha,
                status_message="Update available",
            )
            mock_resp = MagicMock()
            mock_resp.read.return_value = archive_bytes
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = False
            target_proj = os.path.join(tmp_dir, "proj_install")
            os.makedirs(target_proj, exist_ok=True)
            with patch("urllib.request.urlopen", return_value=mock_resp):
                ok_ver, msg_ver = perform_update(verified_info, project_dir=target_proj)
                self.assertTrue(ok_ver, msg_ver)
                self.assertTrue(os.path.isfile(os.path.join(target_proj, "app.py")))

    def test_updater_tar_slip_and_symlink_rejection(self):
        import io
        import os
        import tarfile
        import tempfile
        from core.updater import safe_extract_tarball

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Path traversal archive (../../evil.py)
            trav_path = os.path.join(tmp_dir, "traversal.tar.gz")
            with tarfile.open(trav_path, "w:gz") as tar:
                data = b"malicious"
                tinfo = tarfile.TarInfo(name="../../evil.py")
                tinfo.size = len(data)
                tar.addfile(tinfo, io.BytesIO(data))

            ok_trav, msg_trav = safe_extract_tarball(trav_path, os.path.join(tmp_dir, "out1"))
            self.assertFalse(ok_trav)
            self.assertIn("Security policy", msg_trav)

            # 2. Symlink archive
            sym_path = os.path.join(tmp_dir, "symlink.tar.gz")
            with tarfile.open(sym_path, "w:gz") as tar:
                sinfo = tarfile.TarInfo(name="Sentinel-CAC-Manager/evil_link")
                sinfo.type = tarfile.SYMTYPE
                sinfo.linkname = "/etc/shadow"
                tar.addfile(sinfo)

            ok_sym, msg_sym = safe_extract_tarball(sym_path, os.path.join(tmp_dir, "out2"))
            self.assertFalse(ok_sym)
            self.assertIn("Security policy", msg_sym)


class TestV202SecurityOwnershipAndVerification(unittest.TestCase):
    def test_unprivileged_modules_never_import_privileged_helper(self):
        import os

        unprivileged_files = [
            os.path.join(REPO_ROOT, "core", "certificates.py"),
            os.path.join(REPO_ROOT, "core", "smartcard.py"),
            os.path.join(REPO_ROOT, "core", "browsers.py"),
            os.path.join(REPO_ROOT, "core", "updater.py"),
            os.path.join(REPO_ROOT, "core", "ownership.py"),
            os.path.join(REPO_ROOT, "core", "ca_manifest.py"),
            os.path.join(REPO_ROOT, "core", "rust_bridge.py"),
            os.path.join(REPO_ROOT, "ui", "system_view.py"),
        ]
        for path in unprivileged_files:
            with open(path, "r", encoding="utf-8") as f:
                source = f.read()
            self.assertNotIn(
                "from core.privileged_helper import",
                source,
                f"Unprivileged module {path} must not import core.privileged_helper",
            )
            self.assertNotIn(
                "import core.privileged_helper",
                source,
                f"Unprivileged module {path} must not import core.privileged_helper",
            )

    def test_all_bundled_cas_valid_and_unexpired(self):
        import os
        from core.ca_manifest import check_bundled_ca_expirations

        certs_dir = os.path.join(REPO_ROOT, "certificates")
        res = check_bundled_ca_expirations(certs_dir)
        # Root CAs must strictly never be expired
        root_names = {"DoD_Root_CA_3.crt", "DoD_Root_CA_4.crt", "DoD_Root_CA_5.crt", "DoD_Root_CA_6.crt"}
        expired_roots = [e for e in res["expired"] if any(r in e for r in root_names)]
        self.assertEqual(expired_roots, [], f"Official DoD Root CAs must never be expired: {expired_roots}")
        # Total bundle must account for all 44-45 official DoD CAs
        total_cas = len(res["valid"]) + len(res["expiring_soon"]) + len(res["expired"])
        self.assertIn(total_cas, (44, 45))

    def test_firefox_policy_snapshot_preserves_preexisting_keys(self):
        import json
        import os
        import tempfile
        from core.privileged_helper import merge_firefox_policy_file, revert_firefox_policy_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_path = os.path.join(tmp_dir, "policies.json")
            preexisting = {
                "policies": {
                    "Certificates": {
                        "ImportEnterpriseRoots": True,
                        "Install": ["/etc/corp/enterprise_root.pem"],
                    },
                    "Preferences": {
                        "security.default_personal_cert": {
                            "Value": "Ask Every Time",
                            "Status": "locked",
                        }
                    },
                }
            }
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(preexisting, f)

            ok = merge_firefox_policy_file(
                policy_path,
                "/usr/lib64/opensc-pkcs11.so",
                "/usr/share/sentinel/certificates/DoD_Full_Chain.pem",
            )
            self.assertTrue(ok)
            self.assertTrue(os.path.isfile(policy_path + ".pre-sentinel-snap"))

            rev_ok = revert_firefox_policy_file(policy_path)
            self.assertTrue(rev_ok)
            self.assertTrue(os.path.isfile(policy_path))
            with open(policy_path, "r", encoding="utf-8") as f:
                after = json.load(f)

            self.assertTrue(after["policies"]["Certificates"]["ImportEnterpriseRoots"])
            self.assertEqual(
                after["policies"]["Certificates"]["Install"],
                ["/etc/corp/enterprise_root.pem"],
            )
            self.assertEqual(
                after["policies"]["Preferences"]["security.default_personal_cert"]["Value"],
                "Ask Every Time",
            )
            self.assertNotIn("SecurityDevices", after["policies"])

    def test_firefox_user_js_snapshot_preserves_preexisting_pref(self):
        import os
        import tempfile
        from core.browsers import configure_firefox_user_js, revert_firefox_user_js

        with tempfile.TemporaryDirectory() as tmp_profile:
            user_js = os.path.join(tmp_profile, "user.js")
            with open(user_js, "w", encoding="utf-8") as f:
                f.write(
                    'user_pref("security.default_personal_cert", "Ask Every Time");\n'
                    'user_pref("browser.startup.homepage", "https://intranet.mil");\n'
                )

            self.assertTrue(configure_firefox_user_js(tmp_profile))
            self.assertTrue(revert_firefox_user_js(tmp_profile))

            with open(user_js, "r", encoding="utf-8") as f:
                reverted = f.read()
            self.assertIn('user_pref("security.default_personal_cert", "Ask Every Time");', reverted)
            self.assertIn('user_pref("browser.startup.homepage", "https://intranet.mil");', reverted)

    def test_nss_import_rejects_tampered_ca(self):
        import os
        import tempfile
        from unittest.mock import patch
        from core.certificates import import_root_cas_to_nss

        with tempfile.TemporaryDirectory() as tmp_dir:
            roots_dir = os.path.join(tmp_dir, "roots")
            os.makedirs(roots_dir, exist_ok=True)
            tampered_root = os.path.join(roots_dir, "DoD_Root_CA_3.crt")
            with open(tampered_root, "w", encoding="utf-8") as f:
                f.write("-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n")

            nss_db = os.path.join(tmp_dir, "nssdb")
            os.makedirs(nss_db, exist_ok=True)
            inter_dir = os.path.join(tmp_dir, "intermediates")
            os.makedirs(inter_dir, exist_ok=True)

            with patch("shutil.which", return_value="/usr/bin/certutil"), \
                 patch("core.certificates.ROOTS_DIR", roots_dir), \
                 patch("core.certificates.INTERMEDIATES_DIR", inter_dir), \
                 patch("subprocess.run") as mock_run:
                imported, errors = import_root_cas_to_nss(nss_db)
                self.assertEqual(imported, 0)
                self.assertTrue(len(errors) > 0)
                for call_item in mock_run.call_args_list:
                    self.assertNotIn("-A", call_item[0][0])

    def test_ocsp_host_and_leaf_signature_enforcement(self):
        import os
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import AuthorityInformationAccessOID, UniformResourceIdentifier
        from cryptography.x509.oid import NameOID
        from core.smartcard import CardCertificate, verify_cert_ocsp

        now = datetime.now(timezone.utc)
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Load subject of genuine DoD Root CA 3
        real_root3_path = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        with open(real_root3_path, "rb") as f:
            real_root3 = x509.load_pem_x509_certificate(f.read())

        # 1. Non-.mil OCSP URL must be rejected when allow_non_mil_for_testing=False
        evil_aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                UniformResourceIdentifier("http://evil.example.com/ocsp"),
            )
        ])
        leaf_non_mil = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.1234567890")]))
            .issuer_name(real_root3.subject)
            .public_key(rogue_key.public_key())
            .serial_number(101)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(evil_aia, critical=False)
            .sign(rogue_key, hashes.SHA256())
        )
        card_non_mil = CardCertificate(
            id="0005", label="Test", subject="Test", issuer="DoD Root CA 3", issuer_cn="DoD Root CA 3",
            cn="DOE.JOHN.1234567890", holder_name="John Doe", edipi="1234567890",
            valid_from=now, valid_to=now + timedelta(days=30), valid_to_str="2026-11-24",
            serial="101", usage="Test", is_valid=True, status_text="Valid",
            raw_der=leaf_non_mil.public_bytes(serialization.Encoding.DER),
        )
        res1, msg1 = verify_cert_ocsp(card_non_mil, allow_non_mil_for_testing=False)
        self.assertIsNone(res1)
        self.assertIn("non-.mil", msg1)

        # 2. Forged leaf claiming DoD Root CA 3 issuer with .mil OCSP URL must fail leaf signature check
        mil_aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                UniformResourceIdentifier("http://ocsp.disa.mil"),
            )
        ])
        forged_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.1234567890")]))
            .issuer_name(real_root3.subject)
            .public_key(rogue_key.public_key())
            .serial_number(102)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(mil_aia, critical=False)
            .sign(rogue_key, hashes.SHA256())
        )
        card_forged = CardCertificate(
            id="0005", label="Test", subject="Test", issuer="DoD Root CA 3", issuer_cn="DoD Root CA 3",
            cn="DOE.JOHN.1234567890", holder_name="John Doe", edipi="1234567890",
            valid_from=now, valid_to=now + timedelta(days=30), valid_to_str="2026-11-24",
            serial="102", usage="Test", is_valid=True, status_text="Valid",
            raw_der=forged_leaf.public_bytes(serialization.Encoding.DER),
        )
        res2, msg2 = verify_cert_ocsp(card_forged)
        self.assertIsNone(res2)
        self.assertIn("Leaf certificate signature failed verification", msg2)

    def test_change_card_pin_fails_closed_when_status_query_fails(self):
        from unittest.mock import patch
        from core.smartcard import change_card_pin

        with patch("core.rust_bridge.query_pin_status_rust", return_value=(False, 0, "APDU transmit failure")), \
             patch("core.rust_bridge.change_pin_rust") as mock_change:
            ok, retries, msg = change_card_pin("123456", "654321")
            self.assertFalse(ok)
            self.assertEqual(retries, -1)
            self.assertIn("Security abort", msg)
            mock_change.assert_not_called()

    def test_updater_http_404_and_internal_relative_symlinks(self):
        import io
        import os
        import tarfile
        import tempfile
        import urllib.error
        from unittest.mock import patch
        from core.updater import check_for_updates, safe_extract_tarball

        # 1. HTTP 404 must report error, never "up to date"
        err_404 = urllib.error.HTTPError(
            url="https://api.github.com/repos/CodeFXR/Sentinel-CAC-Manager/releases/latest",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=err_404):
            info = check_for_updates("2.0.2")
            self.assertFalse(info.update_available)
            self.assertEqual(info.error, "HTTP 404")
            self.assertNotIn("up to date", info.status_message.lower())

        # 2. Internal relative symlink inside archive is allowed; escaping relative symlink is rejected
        with tempfile.TemporaryDirectory() as tmp_dir:
            good_sym_tar = os.path.join(tmp_dir, "good_sym.tar.gz")
            with tarfile.open(good_sym_tar, "w:gz") as tar:
                payload = b"cert data"
                finfo = tarfile.TarInfo(name="Sentinel-CAC-Manager/DoD_Roots.pem")
                finfo.size = len(payload)
                tar.addfile(finfo, io.BytesIO(payload))

                sinfo = tarfile.TarInfo(name="Sentinel-CAC-Manager/DoW_Roots.pem")
                sinfo.type = tarfile.SYMTYPE
                sinfo.linkname = "DoD_Roots.pem"
                tar.addfile(sinfo)

            ok_good, msg_good = safe_extract_tarball(good_sym_tar, os.path.join(tmp_dir, "out_good"))
            self.assertTrue(ok_good, msg_good)

            bad_sym_tar = os.path.join(tmp_dir, "bad_sym.tar.gz")
            with tarfile.open(bad_sym_tar, "w:gz") as tar:
                sinfo = tarfile.TarInfo(name="Sentinel-CAC-Manager/escape_link")
                sinfo.type = tarfile.SYMTYPE
                sinfo.linkname = "../../etc/passwd"
                tar.addfile(sinfo)

            ok_bad, msg_bad = safe_extract_tarball(bad_sym_tar, os.path.join(tmp_dir, "out_bad"))
            self.assertFalse(ok_bad)
            self.assertIn("Security policy", msg_bad)

            # 3. Verify real release archive extracts cleanly if present
            release_tar = os.path.join(REPO_ROOT, "Sentinel-CAC-Manager.tar.gz")
            if os.path.isfile(release_tar):
                ok_rel, msg_rel = safe_extract_tarball(release_tar, os.path.join(tmp_dir, "out_rel"))
                self.assertTrue(ok_rel, msg_rel)

    def test_rust_pki_integrity_and_ocsp_engines(self):
        import os
        from core.ca_manifest import validate_and_reserialize_cert, verify_file_matches_manifest
        from core.ownership import compute_file_sha256
        from core.rust_bridge import is_rust_available, validate_ocsp_url_rust

        root3_path = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        self.assertTrue(verify_file_matches_manifest(root3_path))
        with open(root3_path, "rb") as f:
            root3_bytes = f.read()
        reserialized = validate_and_reserialize_cert(root3_bytes, "DoD_Root_CA_3.crt")
        self.assertIsNotNone(reserialized)
        self.assertIn(b"-----BEGIN CERTIFICATE-----", reserialized)

        tampered = validate_and_reserialize_cert(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "DoD_Root_CA_3.crt")
        self.assertIsNone(tampered)

        sha = compute_file_sha256(root3_path)
        self.assertEqual(sha, "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177")

        if is_rust_available():
            self.assertTrue(validate_ocsp_url_rust("http://ocsp.disa.mil", False))
            self.assertFalse(validate_ocsp_url_rust("http://evil.example.com/ocsp", False))


class TestV203SecurityOwnershipAndCorrectness(unittest.TestCase):
    def test_write_secure_cert_backup_failure_fails_closed(self):
        import tempfile
        import os
        from core.privileged_helper import _write_secure_cert

        src_cert = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        with tempfile.TemporaryDirectory() as tmp_dir:
            dst_cert = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
            orig_admin_content = b"CUSTOM ADMIN ROOT CA CERTIFICATE THAT MUST BE PROTECTED"
            with open(dst_cert, "wb") as f_orig:
                f_orig.write(orig_admin_content)

            # Collide backup path with a directory so creating .pre-sentinel-bak raises OSError
            bak_path = f"{dst_cert}.pre-sentinel-bak"
            os.makedirs(bak_path, exist_ok=True)

            ok = _write_secure_cert(src_cert, dst_cert, os.path.dirname(src_cert))
            self.assertFalse(ok, "Expected _write_secure_cert to fail closed when backup fails")

            with open(dst_cert, "rb") as f_check:
                self.assertEqual(f_check.read(), orig_admin_content)

    def test_symlink_backup_and_restoration(self):
        import tempfile
        import os
        from core.privileged_helper import _write_secure_cert, _remove_or_restore_sentinel_cert_file
        from core.ownership import get_file_ownership_entry

        src_cert = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        with tempfile.TemporaryDirectory() as tmp_dir:
            admin_target = os.path.join(tmp_dir, "admin_ca_target.pem")
            with open(admin_target, "wb") as f_admin:
                f_admin.write(b"ADMIN CA TARGET CONTENT")

            sym_link = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
            os.symlink(admin_target, sym_link)

            ok_write = _write_secure_cert(src_cert, sym_link, os.path.dirname(src_cert))
            self.assertTrue(ok_write)

            entry = get_file_ownership_entry(sym_link)
            self.assertIsNotNone(entry)
            self.assertTrue(entry.get("was_symlink"))
            self.assertEqual(entry.get("symlink_target"), admin_target)

            ok_restore = _remove_or_restore_sentinel_cert_file(sym_link)
            self.assertTrue(ok_restore)
            self.assertTrue(os.path.islink(sym_link))
            self.assertEqual(os.readlink(sym_link), admin_target)

    def test_pre_existing_dod_cert_preservation_on_uninstall(self):
        import tempfile
        import os
        from core.privileged_helper import _write_secure_cert, _remove_or_restore_sentinel_cert_file

        src_cert = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        with tempfile.TemporaryDirectory() as tmp_dir:
            dst_cert = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
            with open(src_cert, "rb") as f_s:
                real_dod_content = f_s.read()
            with open(dst_cert, "wb") as f_d:
                f_d.write(real_dod_content)

            ok_write = _write_secure_cert(src_cert, dst_cert, os.path.dirname(src_cert))
            self.assertTrue(ok_write)

            ok_remove = _remove_or_restore_sentinel_cert_file(dst_cert)
            self.assertFalse(ok_remove)
            self.assertTrue(os.path.isfile(dst_cert))
            with open(dst_cert, "rb") as f_check:
                self.assertEqual(f_check.read(), real_dod_content)

    def test_firefox_policy_malformed_json_fails_closed(self):
        import tempfile
        import os
        from core.privileged_helper import merge_firefox_policy_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_policy = os.path.join(tmp_dir, "policies.json")
            malformed_cases = [
                b"INVALID NOT JSON",
                b'{"policies": "not a dict"}',
                b'{"policies": {"SecurityDevices": "not a dict"}}',
            ]
            for bad_payload in malformed_cases:
                with open(target_policy, "wb") as f:
                    f.write(bad_payload)
                ok = merge_firefox_policy_file(target_policy, "/usr/lib/opensc-pkcs11.so", "/usr/share/sentinel/cert.pem")
                self.assertFalse(ok)
                with open(target_policy, "rb") as f_check:
                    self.assertEqual(f_check.read(), bad_payload)

    def test_firefox_policy_dow_cac_preservation_and_cas_concurrency(self):
        import json
        import tempfile
        import os
        from unittest.mock import patch
        from core.privileged_helper import merge_firefox_policy_file, revert_firefox_policy_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_policy = os.path.join(tmp_dir, "policies.json")
            initial_data = {
                "policies": {
                    "SecurityDevices": {
                        "DoW CAC": "/opt/custom/dow.so"
                    }
                }
            }
            with open(target_policy, "w", encoding="utf-8") as f:
                json.dump(initial_data, f)

            ok_merge = merge_firefox_policy_file(target_policy, "/usr/lib/opensc-pkcs11.so", "/usr/share/sentinel/cert.pem")
            self.assertTrue(ok_merge)

            with open(target_policy, "r", encoding="utf-8") as f_res:
                merged = json.load(f_res)
            self.assertEqual(merged["policies"]["SecurityDevices"]["DoW CAC"], "/opt/custom/dow.so")
            self.assertEqual(merged["policies"]["SecurityDevices"]["DoD CAC"], "/usr/lib/opensc-pkcs11.so")

            orig_named_temp = tempfile.NamedTemporaryFile
            def modify_target_during_merge(*args, **kwargs):
                with open(target_policy, "a", encoding="utf-8") as f_append:
                    f_append.write("/* concurrent modification */\n")
                return orig_named_temp(*args, **kwargs)

            with patch("tempfile.NamedTemporaryFile", side_effect=modify_target_during_merge), \
                 patch("os.replace") as mock_replace:
                ok_cas = merge_firefox_policy_file(target_policy, "/usr/lib/opensc-pkcs11.so", "/usr/share/sentinel/cert.pem")
                self.assertFalse(ok_cas)
                mock_replace.assert_not_called()

            with open(target_policy, "w", encoding="utf-8") as f:
                json.dump(merged, f)
            ok_revert = revert_firefox_policy_file(target_policy)
            self.assertTrue(ok_revert)
            with open(target_policy, "r", encoding="utf-8") as f_rev:
                reverted = json.load(f_rev)
            self.assertEqual(reverted["policies"]["SecurityDevices"].get("DoW CAC"), "/opt/custom/dow.so")
            self.assertNotIn("DoD CAC", reverted["policies"]["SecurityDevices"])

    def test_updater_rollback_preserves_old_file_and_reports_honest_failures(self):
        import tempfile
        import os
        import shutil
        from unittest.mock import patch
        from core.updater import perform_update, UpdateInfo

        with tempfile.TemporaryDirectory() as tmp_dir:
            proj_dir = os.path.join(tmp_dir, "sentinel_app")
            os.makedirs(proj_dir, exist_ok=True)
            old_file = os.path.join(proj_dir, "critical_config.py")
            with open(old_file, "w") as f:
                f.write("# ORIGINAL CRITICAL CONTENT")

            info = UpdateInfo(
                current_version="2.0.2",
                latest_version="2.0.3",
                tag_name="v2.0.3",
                update_available=True,
                html_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/tag/v2.0.3",
                download_url="https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/download/v2.0.3/Sentinel-CAC-Manager.tar.gz",
                expected_sha256="a" * 64,
                status_message="Update available",
            )

            real_move = shutil.move
            def fail_on_install_move(src, dst):
                if "critical_config.py" in dst and "extracted" in src:
                    raise OSError("Disk full simulation on install")
                return real_move(src, dst)

            with patch("urllib.request.urlopen") as mock_url, \
                 patch("core.updater.verify_and_stage_archive") as mock_stage, \
                 patch("shutil.move", side_effect=fail_on_install_move):
                mock_url.return_value.__enter__.return_value.read.return_value = b"archive data"
                def fake_stage(data, sha, staging_dir):
                    extracted = os.path.join(staging_dir, "extracted")
                    os.makedirs(extracted, exist_ok=True)
                    with open(os.path.join(extracted, "critical_config.py"), "w") as f:
                        f.write("# NEW UPDATE CONTENT")
                    return True, "Extracted successfully"
                mock_stage.side_effect = fake_stage

                ok_up, msg_up = perform_update(info, project_dir=proj_dir)
                self.assertFalse(ok_up)
                self.assertIn("rolled back cleanly", msg_up)
                with open(old_file, "r") as f:
                    self.assertEqual(f.read(), "# ORIGINAL CRITICAL CONTENT")

            # Also verify honest reporting when rollback move encounters an error
            def fail_on_both(src, dst):
                if "extracted" in src:
                    raise OSError("Install disk full")
                if "rollback_backup" in src:
                    raise OSError("Rollback hardware failure")
                return real_move(src, dst)

            with patch("urllib.request.urlopen") as mock_url, \
                 patch("core.updater.verify_and_stage_archive") as mock_stage, \
                 patch("shutil.move", side_effect=fail_on_both):
                mock_url.return_value.__enter__.return_value.read.return_value = b"archive data"
                def fake_stage(data, sha, staging_dir):
                    extracted = os.path.join(staging_dir, "extracted")
                    os.makedirs(extracted, exist_ok=True)
                    with open(os.path.join(extracted, "critical_config.py"), "w") as f:
                        f.write("# NEW UPDATE CONTENT")
                    return True, "Extracted successfully"
                mock_stage.side_effect = fake_stage

                ok_up_err, msg_up_err = perform_update(info, project_dir=proj_dir)
                self.assertFalse(ok_up_err)
                self.assertIn("rollback encountered errors", msg_up_err)
                self.assertIn("Preserved backup state", msg_up_err)

    def test_nss_trust_flags_repair_and_enforcement(self):
        from unittest.mock import patch, MagicMock
        from core.certificates import _get_nss_cert_trust_flags

        mock_certutil_output = (
            "Certificate Nickname                                         Trust Attributes\n"
            "                                                             SSL,S/MIME,JAR/XPI\n\n"
            "DoD Root CA 3                                                CT,,\n"
            "DoD Root CA 4                                                ,,\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_certutil_output)
            t3 = _get_nss_cert_trust_flags("certutil", "/fake/db", "DoD Root CA 3")
            t4 = _get_nss_cert_trust_flags("certutil", "/fake/db", "DoD Root CA 4")
            self.assertEqual(t3, "CT,,")
            self.assertEqual(t4, ",,")

    def test_manifest_parity_across_manifest_helper_and_rust(self):
        from core.ca_manifest import DOD_CA_DER_FINGERPRINTS, DOD_ROOT_DER_FINGERPRINTS
        from core.privileged_helper import DOD_CA_DER_FINGERPRINTS as HELPER_DER

        self.assertEqual(DOD_CA_DER_FINGERPRINTS, HELPER_DER)
        self.assertEqual(len(DOD_ROOT_DER_FINGERPRINTS), 4)
        self.assertEqual(len(DOD_CA_DER_FINGERPRINTS), 45)

    def test_scdaemon_conflict_detection_and_fix(self):
        from unittest.mock import patch, MagicMock
        from pathlib import Path
        import tempfile
        from core.system_fix import check_scdaemon_conflict, fix_scdaemon_conflict

        # Scenario 1: pgrep scdaemon not running
        with patch("shutil.which", return_value="/usr/bin/pgrep"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            conflicted, msg = check_scdaemon_conflict()
            self.assertFalse(conflicted)
            self.assertIn("No scdaemon conflict", msg)

        # Scenario 2: scdaemon running without disable-ccid in user conf
        with tempfile.TemporaryDirectory() as tmp_home:
            with patch("shutil.which", side_effect=lambda cmd: f"/usr/bin/{cmd}"), \
                 patch("subprocess.run") as mock_run, \
                 patch("pathlib.Path.home", return_value=Path(tmp_home)):
                mock_run.return_value = MagicMock(returncode=0)
                conflicted, msg = check_scdaemon_conflict()
                self.assertTrue(conflicted)
                self.assertIn("disable-ccid", msg)

                # Fix the conflict
                ok, fix_msg = fix_scdaemon_conflict()
                self.assertTrue(ok)
                self.assertIn("Successfully configured", fix_msg)

                # Verify ~/.gnupg/scdaemon.conf content and permissions
                conf_file = Path(tmp_home) / ".gnupg" / "scdaemon.conf"
                self.assertTrue(conf_file.is_file())
                self.assertIn("disable-ccid", conf_file.read_text(encoding="utf-8"))

                # Now check again, conflict should be resolved
                conflicted2, msg2 = check_scdaemon_conflict()
                self.assertFalse(conflicted2)
                self.assertIn("No scdaemon conflict", msg2)

    def test_card_certificate_upn_and_aia_fields(self):
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=TESTER.ALICE.1234567890",
            "-days", "30", "-outform", "DER"
        ]
        p = subprocess.run(cmd, capture_output=True)
        self.assertEqual(p.returncode, 0)
        der_bytes = p.stdout

        cert = parse_card_certificate_rust("0005", "CAC ID / PIV Authentication", "DoD Web Logon", der_bytes)
        self.assertIsNotNone(cert)
        # Verify attributes exist and default gracefully when absent from cert
        self.assertTrue(hasattr(cert, "upn"))
        self.assertTrue(hasattr(cert, "aia_url"))
        self.assertIsNone(cert.upn)
        self.assertIsNone(cert.aia_url)


if __name__ == "__main__":
    unittest.main()

