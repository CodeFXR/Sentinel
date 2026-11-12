"""Rust Bridge for Sentinel.

Provides high-performance native acceleration for ASN.1 DER/PEM parsing,
DoD EDIPI regex extraction, ATR matching, and secure memory zeroization.
Gracefully falls back to pure-Python/OpenSSL logic if the Rust binary is not compiled.
"""

from __future__ import annotations

import email.utils
import importlib.util
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from core.smartcard import CardCertificate

logger = logging.getLogger("sentinel.rust_bridge")

_sentinel_core = None
_INITIALIZED = False
IS_RUST_AVAILABLE = False


def _ensure_init():
    global _sentinel_core, IS_RUST_AVAILABLE, _INITIALIZED
    if _INITIALIZED:
        return
    _INITIALIZED = True

    # 1. Try standard Python import
    try:
        from core import __version__
        import sentinel_core as sc
        if hasattr(sc, "version") and sc.version() != __version__:
            logger.warning(
                f"Native module version {sc.version()} differs from application version {__version__}; "
                "ignoring stale native library."
            )
        else:
            _sentinel_core = sc
            IS_RUST_AVAILABLE = True
            logger.debug("Loaded sentinel_core via standard sys.path import.")
            return
    except ImportError:
        pass

    # 2. Check known compiled binary paths relative to repository root
    repo_root = Path(__file__).resolve().parent.parent
    candidate_paths = [
        repo_root / "target" / "release" / "libsentinel_core.so",
        repo_root / "target" / "release" / "sentinel_core.so",
        repo_root / "native" / "sentinel_core" / "target" / "release" / "libsentinel_core.so",
        repo_root / "native" / "sentinel_core" / "target" / "release" / "sentinel_core.so",
        Path(__file__).resolve().parent / "libsentinel_core.so",
        Path(__file__).resolve().parent / "sentinel_core.so",
    ]

    for p in candidate_paths:
        if p.is_file():
            try:
                spec = importlib.util.spec_from_file_location("sentinel_core", str(p))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules["sentinel_core"] = mod
                    spec.loader.exec_module(mod)
                    mod_ver = getattr(mod, "version", lambda: None)()
                    from core import __version__
                    if mod_ver and mod_ver != __version__:
                        logger.warning(
                            f"Native module {p} version {mod_ver} differs from application version {__version__}; "
                            "ignoring stale native library."
                        )
                        continue
                    _sentinel_core = mod
                    IS_RUST_AVAILABLE = True
                    logger.debug(f"Loaded sentinel_core native module from: {p}")
                    return
            except Exception as e:
                logger.debug(f"Failed to load sentinel_core from {p}: {e}")

    logger.debug("Native sentinel_core module not found or failed to load; using pure-Python fallbacks.")


def is_rust_available() -> bool:
    """Return True if native sentinel_core accelerator is loaded and operational."""
    _ensure_init()
    return IS_RUST_AVAILABLE and _sentinel_core is not None


def get_rust_version() -> Optional[str]:
    """Return the version string of the loaded Rust core module, or None."""
    if is_rust_available():
        try:
            return _sentinel_core.version()
        except Exception:
            return None
    return None


def _parse_card_certificate_python_fallback(
    cert_id: str,
    label: str,
    usage: str,
    data: bytes,
) -> Optional["CardCertificate"]:
    """Pure-Python / OpenSSL fallback for parsing DER or PEM certificate bytes."""
    import subprocess
    from core.smartcard import _parse_x509_text

    if not data or len(data) < 32:
        return None

    try:
        res_x509 = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-serial"],
            input=data,
            capture_output=True,
            timeout=3,
        )
        out = res_x509.stdout.decode(errors="replace")
        if "subject=" not in out:
            res_x509 = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                input=data,
                capture_output=True,
                timeout=3,
            )
            out = res_x509.stdout.decode(errors="replace")

        if "subject=" in out:
            parsed = _parse_x509_text(out, cert_id, label, usage)
            parsed.raw_der = data
            return parsed
    except Exception as e:
        logger.debug(f"Python certificate parser fallback failed for id={cert_id}: {e}")

    return None


def parse_card_certificate_rust(
    cert_id: str,
    label: str,
    usage: str,
    data: bytes,
) -> Optional["CardCertificate"]:
    """Parse ASN.1 DER or PEM certificate bytes using Rust native accelerator with pure-Python fallback.

    Returns a populated CardCertificate dataclass, or None on parse failure.
    """
    if not is_rust_available():
        return _parse_card_certificate_python_fallback(cert_id, label, usage, data)

    try:
        from core.smartcard import CardCertificate

        py_cert = _sentinel_core.parse_certificate(cert_id, label, usage, data)

        valid_from: Optional[datetime] = None
        if py_cert.valid_from_str:
            try:
                valid_from = email.utils.parsedate_to_datetime(py_cert.valid_from_str)
            except Exception:
                valid_from = None

        valid_to: Optional[datetime] = None
        if py_cert.valid_to_str:
            try:
                valid_to = email.utils.parsedate_to_datetime(py_cert.valid_to_str)
            except Exception:
                valid_to = None

        valid_to_display = valid_to.strftime("%Y-%m-%d") if valid_to else (py_cert.valid_to_str or "Unknown")
        raw_der_bytes = bytes(py_cert.raw_der) if hasattr(py_cert, "raw_der") and py_cert.raw_der else data

        return CardCertificate(
            id=py_cert.id,
            label=py_cert.label,
            subject=py_cert.subject,
            issuer=py_cert.issuer,
            issuer_cn=py_cert.issuer_cn,
            cn=py_cert.cn,
            holder_name=py_cert.holder_name,
            edipi=py_cert.edipi,
            valid_from=valid_from,
            valid_to=valid_to,
            valid_to_str=valid_to_display,
            serial=py_cert.serial,
            usage=py_cert.usage,
            is_valid=py_cert.is_valid,
            status_text=py_cert.status_text,
            raw_der=raw_der_bytes,
            upn=getattr(py_cert, "upn", None),
            aia_url=getattr(py_cert, "aia_url", None),
        )
    except Exception as e:
        logger.debug(f"Rust parse_certificate failed for id={cert_id}: {e}")
        return _parse_card_certificate_python_fallback(cert_id, label, usage, data)


def read_card_certificates_rust(reader_name: Optional[str] = None) -> List["CardCertificate"]:
    """Read digital certificates directly via native NIST SP 800-73-4 PIV APDUs.

    Returns a list of populated CardCertificate instances, or an empty list if no card
    is present, non-PIV card, or if the native module is unavailable.
    """
    if not is_rust_available() or not hasattr(_sentinel_core, "read_card_certificates"):
        return []

    try:
        from core.smartcard import CardCertificate
        py_certs = _sentinel_core.read_card_certificates(reader_name)
        results: List[CardCertificate] = []
        for py_cert in py_certs:
            valid_from: Optional[datetime] = None
            if py_cert.valid_from_str:
                try:
                    valid_from = email.utils.parsedate_to_datetime(py_cert.valid_from_str)
                except Exception:
                    valid_from = None

            valid_to: Optional[datetime] = None
            if py_cert.valid_to_str:
                try:
                    valid_to = email.utils.parsedate_to_datetime(py_cert.valid_to_str)
                except Exception:
                    valid_to = None

            valid_to_display = valid_to.strftime("%Y-%m-%d") if valid_to else (py_cert.valid_to_str or "Unknown")
            raw_der_bytes = bytes(py_cert.raw_der) if hasattr(py_cert, "raw_der") and py_cert.raw_der else None

            results.append(CardCertificate(
                id=py_cert.id,
                label=py_cert.label,
                subject=py_cert.subject,
                issuer=py_cert.issuer,
                issuer_cn=py_cert.issuer_cn,
                cn=py_cert.cn,
                holder_name=py_cert.holder_name,
                edipi=py_cert.edipi,
                valid_from=valid_from,
                valid_to=valid_to,
                valid_to_str=valid_to_display,
                serial=py_cert.serial,
                usage=py_cert.usage,
                is_valid=py_cert.is_valid,
                status_text=py_cert.status_text,
                raw_der=raw_der_bytes,
                upn=getattr(py_cert, "upn", None),
                aia_url=getattr(py_cert, "aia_url", None),
            ))
        return results
    except Exception as e:
        logger.debug(f"Rust read_card_certificates failed: {e}")
        return []


def read_card_metadata_rust(reader_name: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Read smart card name, token label, and token serial number directly via PIV APDU containers (CHUID / CCC).

    Returns:
        (card_name, token_label, token_serial)
    """
    if not is_rust_available() or not hasattr(_sentinel_core, "read_card_metadata"):
        return None, None, None

    try:
        meta = _sentinel_core.read_card_metadata(reader_name)
        return meta.card_name, meta.token_label, meta.token_serial
    except Exception as e:
        logger.debug(f"Rust read_card_metadata failed: {e}")
        return None, None, None


def parse_pkcs15_list_rust(output: str) -> List[Tuple[str, str]]:
    """Parse output of `pkcs15-tool -c` into (id, label) pairs using Rust or Python fallback."""
    if is_rust_available():
        try:
            return _sentinel_core.parse_pkcs15_list(output)
        except Exception as e:
            logger.debug(f"Rust parse_pkcs15_list failed: {e}")

    # Fallback Python regex parser
    import re
    pairs: List[Tuple[str, str]] = []
    current_id: Optional[str] = None
    re_id = re.compile(r"^\s*ID\s*:\s*([a-fA-F0-9]+)")
    re_label = re.compile(r"^\s*Label\s*:\s*(.+)")

    for line in output.splitlines():
        m_id = re_id.match(line)
        if m_id:
            current_id = m_id.group(1).strip()
            continue
        m_label = re_label.match(line)
        if m_label and current_id:
            pairs.append((current_id, m_label.group(1).strip()))
            current_id = None

    return pairs


def is_cac_atr_rust(atr: str) -> bool:
    """Check if ATR matches known DoD CAC or PIV smart card profiles."""
    if is_rust_available():
        try:
            return _sentinel_core.is_cac_atr(atr)
        except Exception as e:
            logger.debug(f"Rust is_cac_atr failed: {e}")

    # Fallback prefix check
    clean = atr.replace(":", "").replace(" ", "").replace("-", "").lower()
    return (
        clean.startswith("3b7d96")
        or clean.startswith("3bdb96")
        or clean.startswith("3b7b94")
        or clean.startswith("3b7d94")
        or clean.startswith("3bf818")
        or clean.startswith("3bfa18")
    )


def query_native_pcsc_rust():
    """Query smart card readers, card presence, and ATR via native Rust PC/SC client."""
    if is_rust_available() and hasattr(_sentinel_core, "query_native_pcsc"):
        try:
            return _sentinel_core.query_native_pcsc()
        except Exception as e:
            logger.debug(f"Rust query_native_pcsc failed: {e}")
    return None


def _query_pin_status_cli_fallback(reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Pure-Python / CLI fallback to query PIN retry counter via opensc-tool or pkcs11-tool."""
    import re
    import shutil
    import subprocess

    tool = shutil.which("opensc-tool")
    if tool:
        try:
            cmd = [tool, "-s", "00:a4:04:00:0b:a0:00:00:03:08:00:00:10:00:01:00", "-s", "00:20:00:80:00"]
            if reader_name:
                cmd.extend(["-r", reader_name])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                line_clean = line.strip().replace(" ", "").upper()
                if "63C" in line_clean:
                    m = re.search(r"63C([0-9A-F])", line_clean)
                    if m:
                        retries = int(m.group(1), 16)
                        return True, retries, f"{retries} attempt(s) remaining"
                elif "9000" in line_clean and "00200080" in line_clean:
                    return True, 3, "PIN operational (verified session)"
        except Exception as e:
            logger.debug(f"opensc-tool PIN query note: {e}")

    p11_tool = shutil.which("pkcs11-tool")
    if p11_tool:
        try:
            res = subprocess.run([p11_tool, "--list-slots"], capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                l_low = line.lower()
                if "flags:" in l_low and "user pin" in l_low:
                    if "final try" in l_low:
                        return True, 1, "1 attempt remaining (FINAL TRY)"
                    elif "locked" in l_low:
                        return True, 0, "PIN locked"
                    # Do not fabricate a numeric retry count if exact counter was not returned
                    return True, 255, "PIN operational (exact retry count unread; requires native PC/SC)"
        except Exception as e:
            logger.debug(f"pkcs11-tool PIN query note: {e}")

    return False, 0, "Native smart card engine unavailable (opensc-tool / pkcs11-tool not found or reader empty)"


def query_pin_status_rust(reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Query PIV cardholder PIN retry counter non-destructively.

    Returns: (is_success, retries_remaining, status_message)
    """
    if is_rust_available() and hasattr(_sentinel_core, "query_pin_status"):
        try:
            ok, retries, msg = _sentinel_core.query_pin_status(reader_name)
            return ok, int(retries), str(msg)
        except Exception as e:
            logger.debug(f"Rust query_pin_status failed: {e}")
            return False, 0, f"PIN query failure: {e}"
    return _query_pin_status_cli_fallback(reader_name)


def change_pin_rust(old_pin: str, new_pin: str, reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Change PIV cardholder PIN on inserted smart card via native APDUs.

    Returns: (is_success, retries_remaining, status_message)
    """
    if old_pin == new_pin:
        return False, 0, "New PIN must be different from current PIN"
    if len(old_pin) < 6 or len(old_pin) > 8 or not old_pin.isdigit():
        return False, 0, "Current PIN must be 6 to 8 numeric digits"
    if len(new_pin) < 6 or len(new_pin) > 8 or not new_pin.isdigit():
        return False, 0, "New PIN must be 6 to 8 numeric digits"

    if is_rust_available() and hasattr(_sentinel_core, "change_pin"):
        try:
            ok, retries, msg = _sentinel_core.change_pin(old_pin, new_pin, reader_name)
            return ok, int(retries), str(msg)
        except Exception as e:
            logger.debug(f"Rust change_pin failed: {e}")
            return False, 0, f"PIN change failure: {e}"

    # Never pass PIN credentials on subprocess command-line arguments (SEC-05 / CWE-214).
    # Secure cardholder verification requires direct in-process PC/SC APDU execution.
    return (
        False,
        0,
        "Secure PIN modification requires the compiled native Rust security core "
        "(in-memory APDU only; CLI argument fallback is prohibited for credential security).",
    )


def wait_for_card_event_rust(timeout_ms: int = 3000) -> Optional[Tuple[str, bool]]:
    """Block waiting for a smart card insertion or removal event.

    Returns (reader_name, is_card_present) on state change, or None on timeout.
    """
    import time
    if is_rust_available() and hasattr(_sentinel_core, "wait_for_card_event"):
        try:
            return _sentinel_core.wait_for_card_event(timeout_ms)
        except Exception as e:
            logger.debug(f"Rust wait_for_card_event failed: {e}")
    # Prevent tight polling loops when native engine is unavailable
    time.sleep(max(0.1, timeout_ms / 1000.0))
    return None


def validate_and_reserialize_ca_rust(
    data: bytes,
    fname: str,
    verify_whitelist: bool = True,
) -> Optional[Tuple[Optional[bytes], Optional[str]]]:
    """Validate and reserialize a DoD CA PEM/DER certificate using the native Rust PKI engine.

    Returns (canonical_pem_bytes, error_message) if Rust is available, or None if unavailable.
    """
    if is_rust_available() and hasattr(_sentinel_core, "validate_and_reserialize_ca"):
        try:
            pem_bytes, err_msg = _sentinel_core.validate_and_reserialize_ca(
                data, fname, bool(verify_whitelist)
            )
            return (bytes(pem_bytes) if pem_bytes is not None else None, err_msg)
        except Exception as e:
            logger.debug(f"Rust validate_and_reserialize_ca failed: {e}")
    return None


def verify_ca_file_manifest_rust(filepath: str, fname_override: Optional[str] = None) -> Optional[bool]:
    """Verify a certificate file against the DoD SHA-256/DER manifest in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "verify_ca_file_manifest"):
        try:
            return bool(_sentinel_core.verify_ca_file_manifest(filepath, fname_override))
        except Exception as e:
            logger.debug(f"Rust verify_ca_file_manifest failed: {e}")
    return None


def check_ca_bundle_expirations_rust(
    certs_dir: str,
    warn_days: int = 180,
) -> Optional[Tuple[List[str], List[str], List[str]]]:
    """Inspect bundled DoD certificates in Rust and return (valid, expiring_soon, expired)."""
    if is_rust_available() and hasattr(_sentinel_core, "check_ca_bundle_expirations"):
        try:
            valid, expiring, expired = _sentinel_core.check_ca_bundle_expirations(
                certs_dir, int(warn_days)
            )
            return list(valid), list(expiring), list(expired)
        except Exception as e:
            logger.debug(f"Rust check_ca_bundle_expirations failed: {e}")
    return None


def validate_pkcs11_module_path_rust(raw_path: str) -> Optional[Tuple[Optional[str], Optional[str]]]:
    """Validate PKCS#11 shared library path ownership and permissions in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "validate_pkcs11_module_path"):
        try:
            canonical, err = _sentinel_core.validate_pkcs11_module_path(raw_path)
            return canonical, err
        except Exception as e:
            logger.debug(f"Rust validate_pkcs11_module_path failed: {e}")
    return None


def is_opensc_config_optimized_rust(content: str) -> Optional[bool]:
    """Inspect opensc.conf text (ignoring comments) in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "is_opensc_config_optimized"):
        try:
            return bool(_sentinel_core.is_opensc_config_optimized(content))
        except Exception as e:
            logger.debug(f"Rust is_opensc_config_optimized failed: {e}")
    return None


def compute_file_sha256_rust(filepath: str) -> Optional[str]:
    """Compute streaming SHA-256 hex digest of a regular file in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "compute_file_sha256"):
        try:
            return _sentinel_core.compute_file_sha256(filepath)
        except Exception as e:
            logger.debug(f"Rust compute_file_sha256 failed: {e}")
    return None


def verify_archive_sha256_rust(
    archive_bytes: bytes,
    expected_sha256: str,
    max_bytes: int,
) -> Optional[Tuple[bool, str]]:
    """Verify archive bytes against expected 64-hex SHA-256 in constant time using Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "verify_archive_sha256"):
        try:
            ok, msg = _sentinel_core.verify_archive_sha256(
                archive_bytes, expected_sha256, int(max_bytes)
            )
            return bool(ok), str(msg)
        except Exception as e:
            logger.debug(f"Rust verify_archive_sha256 failed: {e}")
    return None


def validate_tar_member_safety_rust(
    member_name: str,
    is_hardlink: bool,
    is_symlink: bool,
    is_device_or_fifo: bool,
    linkname: str,
    size: int,
) -> Optional[Tuple[bool, str]]:
    """Validate tar member safety against tar-slip, hardlinks, escaping symlinks, and devices in Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "validate_tar_member_safety"):
        try:
            ok, msg = _sentinel_core.validate_tar_member_safety(
                member_name,
                bool(is_hardlink),
                bool(is_symlink),
                bool(is_device_or_fifo),
                linkname or "",
                max(0, int(size)),
            )
            return bool(ok), str(msg)
        except Exception as e:
            logger.debug(f"Rust validate_tar_member_safety failed: {e}")
    return None


def validate_ocsp_url_rust(url: str, allow_non_mil: bool = False) -> bool:
    """Validate OCSP responder URL scheme and .mil boundary in native Rust (with Python fallback)."""
    if is_rust_available() and hasattr(_sentinel_core, "validate_ocsp_url"):
        try:
            return bool(_sentinel_core.validate_ocsp_url(url, bool(allow_non_mil)))
        except Exception as e:
            logger.debug(f"Rust validate_ocsp_url failed: {e}")

    from urllib.parse import urlparse
    if not url or any(ord(c) < 0x20 or ord(c) == 0x7F or c.isspace() for c in url):
        return False
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in ("http", "https") or not host or "@" in (parsed.netloc or ""):
        return False
    if allow_non_mil:
        return True
    return host == "mil" or host.endswith(".mil")


def extract_ocsp_urls_from_der_rust(
    der_bytes: bytes,
    allow_non_mil: bool = False,
) -> Optional[List[str]]:
    """Extract AIA OCSP responder URLs directly from X.509 DER bytes in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "extract_ocsp_urls_from_der"):
        try:
            return list(_sentinel_core.extract_ocsp_urls_from_der(der_bytes, bool(allow_non_mil)))
        except Exception as e:
            logger.debug(f"Rust extract_ocsp_urls_from_der failed: {e}")
    return None


def verify_ocsp_responder_cert_der_rust(
    responder_der: bytes,
    issuer_der: bytes,
) -> Optional[Tuple[bool, bool, str]]:
    """Verify OCSP responder certificate validity window and EKU authorization in native Rust."""
    if is_rust_available() and hasattr(_sentinel_core, "verify_ocsp_responder_cert_der"):
        try:
            ok_time, ok_auth, msg = _sentinel_core.verify_ocsp_responder_cert_der(
                responder_der, issuer_der
            )
            return bool(ok_time), bool(ok_auth), str(msg)
        except Exception as e:
            logger.debug(f"Rust verify_ocsp_responder_cert_der failed: {e}")
    return None


class _PyPinBuffer:
    """Pure-Python fallback for secure PIN storage with zeroization on drop."""

    def __init__(self, pin: str):
        self._buf = bytearray(pin.encode("utf-8"))
        self._len = len(self._buf)

    def length(self) -> int:
        return self._len

    def __len__(self) -> int:
        return self._len

    def is_valid_pin_format(self) -> bool:
        return 6 <= self._len <= 8 and all(48 <= b <= 57 for b in self._buf)

    def scrub(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf = bytearray()
        self._len = 0

    def __repr__(self) -> str:
        return "<PinBuffer [REDACTED: MEMORY PROTECTED]>"

    def __del__(self) -> None:
        self.scrub()


class PinBuffer:
    """Memory-hardened buffer for sensitive credentials (PINs/PUKs).

    Delegates to native Rust PinBuffer with ZeroizeOnDrop if available,
    or transparently falls back to _PyPinBuffer. Note that while native
    Rust APDU buffers and PinBuffer storage are zeroized deterministically,
    caller-supplied Python str objects remain managed by CPython's allocator.
    """

    def __new__(cls, pin: str):
        _ensure_init()
        if IS_RUST_AVAILABLE and _sentinel_core is not None and hasattr(_sentinel_core, "PinBuffer"):
            return _sentinel_core.PinBuffer(pin)
        return _PyPinBuffer(pin)
