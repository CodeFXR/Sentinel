"""DoD Certificate Bundle and Trust Store Management for Sentinel."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from core.ca_manifest import (
    DOD_CA_DER_FINGERPRINTS,
    DOD_ROOT_DER_FINGERPRINTS,
    DOD_ROOT_FILES,
    validate_and_reserialize_cert,
)
from core.platform_detector import PlatformInfo, detect_platform

logger = logging.getLogger("sentinel.certificates")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_BASE_DIR = os.path.join(SCRIPT_DIR, "certificates")
ROOTS_DIR = os.path.join(CERTS_BASE_DIR, "roots")
INTERMEDIATES_DIR = os.path.join(CERTS_BASE_DIR, "intermediates")
ALL_CAS_DIR = os.path.join(CERTS_BASE_DIR, "all_cas")

FULL_CHAIN_PEM = os.path.join(CERTS_BASE_DIR, "DoD_Full_Chain.pem")
if not os.path.isfile(FULL_CHAIN_PEM):
    FULL_CHAIN_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.pem")

FULL_CHAIN_CRT = os.path.join(CERTS_BASE_DIR, "DoD_Full_Chain.crt")
if not os.path.isfile(FULL_CHAIN_CRT):
    FULL_CHAIN_CRT = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.crt")

ROOTS_PEM = os.path.join(CERTS_BASE_DIR, "DoD_Roots.pem")
if not os.path.isfile(ROOTS_PEM):
    ROOTS_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Roots.pem")

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----")


@dataclass
class CertificateItem:
    filename: str
    cn: str
    path: str
    is_root: bool


def get_available_certificates() -> List[CertificateItem]:
    """Return all bundled DoD Root and Intermediate certificates."""
    items = []
    if os.path.isdir(ALL_CAS_DIR):
        for fname in sorted(os.listdir(ALL_CAS_DIR)):
            if fname.endswith(".crt"):
                cpath = os.path.join(ALL_CAS_DIR, fname)
                is_root = os.path.exists(os.path.join(ROOTS_DIR, fname))
                cn = os.path.splitext(fname)[0].replace("_", " ")
                items.append(CertificateItem(filename=fname, cn=cn, path=cpath, is_root=is_root))
    return items


def _extract_file_der_hashes(path: str) -> Set[str]:
    """Extract canonical DER SHA-256 hex digests for all PEM certificate blocks in a file."""
    hashes: Set[str] = set()
    if not os.path.isfile(path):
        return hashes
    try:
        with open(path, "rb") as f:
            raw = f.read()
        for body in _PEM_BLOCK_RE.findall(raw):
            cleaned = re.sub(rb"\s+", b"", body)
            der = base64.b64decode(cleaned, validate=True)
            hashes.add(hashlib.sha256(der).hexdigest().lower())
    except Exception:
        pass
    return hashes


def is_system_trust_installed(platform: Optional[PlatformInfo] = None) -> bool:
    """Verify that all 4 required DoD Root CAs are installed in source anchors AND compiled OS trust bundle."""
    plat = platform or detect_platform()
    required_root_hashes = set(DOD_ROOT_DER_FINGERPRINTS.values())

    source_ok = False
    if plat.is_debian_derivative:
        d = "/usr/local/share/ca-certificates/dod"
        found_hashes: Set[str] = set()
        if os.path.isdir(d):
            for fname in DOD_ROOT_FILES:
                found_hashes |= _extract_file_der_hashes(os.path.join(d, fname))
        if required_root_hashes.issubset(found_hashes):
            source_ok = True
        else:
            etc_hashes: Set[str] = set()
            for fname in ("DoD_Root_CA_3.pem", "DoD_Root_CA_4.pem", "DoD_Root_CA_5.pem", "DoD_Root_CA_6.pem"):
                etc_hashes |= _extract_file_der_hashes(os.path.join("/etc/ssl/certs", fname))
            source_ok = required_root_hashes.issubset(etc_hashes)
    else:
        for candidate in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Roots.pem"]:
            t = os.path.join(plat.trust_dir, candidate)
            if os.path.isfile(t):
                found_hashes = _extract_file_der_hashes(t)
                if required_root_hashes.issubset(found_hashes):
                    source_ok = True
                    break

    if not source_ok:
        return False

    # Also verify compiled OS trust store bundle when present on the host
    compiled_bundles = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
        "/var/lib/ca-certificates/ca-bundle.pem",
    ]
    for bundle in compiled_bundles:
        if os.path.isfile(bundle):
            bundle_hashes = _extract_file_der_hashes(bundle)
            return required_root_hashes.issubset(bundle_hashes)

    return True


def _get_nss_cert_der_hash(certutil: str, db_dir: str, nickname: str) -> Optional[str]:
    """Query an NSS database for nickname and return its canonical DER SHA-256 hex digest if present."""
    try:
        res = subprocess.run(
            [certutil, "-d", f"sql:{db_dir}", "-L", "-n", nickname, "-a"],
            capture_output=True,
            timeout=3,
        )
        if res.returncode != 0 or not res.stdout:
            return None
        matches = _PEM_BLOCK_RE.findall(res.stdout)
        if not matches:
            return None
        cleaned = re.sub(rb"\s+", b"", matches[0])
        der = base64.b64decode(cleaned, validate=True)
        return hashlib.sha256(der).hexdigest().lower()
    except Exception:
        return None


def _get_nss_cert_trust_flags(certutil: str, db_dir: str, nickname: str) -> Optional[str]:
    """Query an NSS database for nickname and return its trust attributes string (e.g. 'CT,,')."""
    try:
        res = subprocess.run(
            [certutil, "-d", f"sql:{db_dir}", "-L"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode != 0 or not res.stdout:
            return None
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Certificate Nickname") or line_str.startswith("SSL,S/MIME"):
                continue
            parts = line.rsplit(None, 1)
            if len(parts) == 2 and parts[0].strip() == nickname:
                return parts[1].strip()
        return None
    except Exception:
        return None


def _load_nss_ownership(db_dir: str) -> Dict[str, dict]:
    manifest_file = os.path.join(db_dir, ".sentinel_nss_manifest.json")
    if not os.path.isfile(manifest_file) or os.path.islink(manifest_file):
        return {}
    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_nss_ownership(db_dir: str, data: Dict[str, dict]) -> None:
    manifest_file = os.path.join(db_dir, ".sentinel_nss_manifest.json")
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=db_dir, delete=False, encoding="utf-8") as f_tmp:
            tmp_name = f_tmp.name
            json.dump(data, f_tmp, indent=2, sort_keys=True)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, manifest_file)
    except OSError:
        pass


def get_nss_installed_cas(db_dir: str) -> List[str]:
    """List nicknames of DoD certificates currently installed in an NSS DB."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isdir(db_dir):
        return []

    try:
        res = subprocess.run(
            [certutil, "-d", f"sql:{db_dir}", "-L"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode != 0:
            return []
        dod_cas = []
        for line in res.stdout.splitlines():
            line_s = line.strip()
            if any(term in line_s for term in ("DoD", "DOD", "WCF", "ECA")):
                nick = line.split("  ")[0].strip()
                if nick:
                    dod_cas.append(nick)
        return dod_cas
    except Exception as e:
        logger.debug(f"Failed to query NSS db {db_dir}: {e}")
        return []


def import_root_cas_to_nss(
    db_dir: str,
    log_fn=None,
    roots_dir: Optional[str] = None,
    intermediates_dir: Optional[str] = None,
) -> Tuple[int, List[str]]:
    """Import manifest-verified Root CAs with CT,, trust and non-expired Intermediate CAs into an NSS DB."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isdir(db_dir):
        return 0, ["certutil binary or db directory missing"]

    errors: List[str] = []
    success_count = 0

    if not os.path.isfile(os.path.join(db_dir, "cert9.db")):
        try:
            subprocess.run([certutil, "-N", "-d", f"sql:{db_dir}", "--empty-password"], check=True, timeout=3)
        except Exception as e:
            return 0, [f"Failed to initialize NSS database: {e}"]

    r_dir = roots_dir or ROOTS_DIR
    i_dir = intermediates_dir or INTERMEDIATES_DIR

    certs_to_import: List[Tuple[str, str, str]] = []
    if os.path.isdir(r_dir):
        for f in sorted(os.listdir(r_dir)):
            if f.endswith(".crt"):
                # Use CT,, (TLS CA trust only; never grant unnecessary email/object-signing root trust)
                certs_to_import.append((os.path.join(r_dir, f), "CT,,", f))

    if os.path.isdir(i_dir):
        for f in sorted(os.listdir(i_dir)):
            if f.endswith(".crt"):
                certs_to_import.append((os.path.join(i_dir, f), ",,", f))

    ownership = _load_nss_ownership(db_dir)

    for cpath, trust, fname in certs_to_import:
        nick = os.path.splitext(fname)[0].replace("_", " ")
        expected_der = DOD_CA_DER_FINGERPRINTS.get(fname)
        if not expected_der:
            errors.append(f"{nick}: Rejected unauthorized certificate '{fname}' (not in DoD DER manifest)")
            continue

        try:
            if os.path.islink(cpath) or not os.path.isfile(cpath):
                errors.append(f"{nick}: Rejected symlink or non-regular file '{cpath}'")
                continue
            with open(cpath, "rb") as f_cert:
                raw_bytes = f_cert.read(1024 * 1024)
        except OSError as e:
            errors.append(f"{nick}: {e}")
            continue

        validated_pem = validate_and_reserialize_cert(raw_bytes, fname, verify_whitelist=True)
        if not validated_pem:
            # Skip expired intermediates gracefully, but treat any root or tampered file failure as an error
            if fname not in DOD_ROOT_DER_FINGERPRINTS and b"-----BEGIN CERTIFICATE-----" in raw_bytes:
                file_ders = _extract_file_der_hashes(cpath)
                if file_ders == {expected_der}:
                    if log_fn:
                        log_fn(f"  [!] Skipping expired intermediate CA: {fname}")
                    continue
            errors.append(f"{nick}: Certificate failed cryptographic DER manifest or CA validation")
            continue

        # Check if nickname already exists in NSS DB before import
        existing_der = _get_nss_cert_der_hash(certutil, db_dir, nick)
        if existing_der is not None:
            if existing_der == expected_der:
                existing_trust = _get_nss_cert_trust_flags(certutil, db_dir, nick) or ""
                # For root CAs, verify 'C' is present in the SSL trust flags
                if fname in DOD_ROOT_DER_FINGERPRINTS and "C" not in existing_trust:
                    if nick in ownership and not ownership[nick].get("pre_existing"):
                        res_m = subprocess.run(
                            [certutil, "-d", f"sql:{db_dir}", "-M", "-n", nick, "-t", trust],
                            capture_output=True,
                            text=True,
                            timeout=4,
                        )
                        if res_m.returncode == 0:
                            success_count += 1
                            if log_fn:
                                log_fn(f"  [+] Repaired NSS trust attributes to {trust} for {nick}")
                            continue
                        else:
                            errors.append(f"{nick}: Failed to update trust attributes in NSS DB: {res_m.stderr.strip()}")
                            continue
                    else:
                        errors.append(f"{nick}: Pre-existing certificate in NSS DB lacks CA trust flags (has '{existing_trust}', requires '{trust}')")
                        continue

                if nick not in ownership:
                    ownership[nick] = {"pre_existing": True, "der_sha256": expected_der}
                success_count += 1
                continue
            else:
                errors.append(f"{nick}: Nickname collision in NSS DB with unexpected DER fingerprint ({existing_der})")
                continue

        try:
            res = subprocess.run(
                [certutil, "-d", f"sql:{db_dir}", "-A", "-t", trust, "-n", nick, "-i", cpath],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if res.returncode == 0:
                verified_der = _get_nss_cert_der_hash(certutil, db_dir, nick)
                if verified_der == expected_der:
                    ownership[nick] = {"pre_existing": False, "der_sha256": expected_der}
                    success_count += 1
                    if log_fn:
                        log_fn(f"  [+] Imported and verified in NSS: {nick}")
                else:
                    errors.append(f"{nick}: Post-import NSS verification failed")
            else:
                errors.append(f"{nick}: {res.stderr.strip()}")
        except Exception as e:
            errors.append(f"{nick}: {e}")

    _save_nss_ownership(db_dir, ownership)
    return success_count, errors


def remove_sentinel_cas_from_nss(db_dir: str, log_fn=None) -> int:
    """Remove only DoD CA certificates that Sentinel created and whose DER hash matches the manifest."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isfile(os.path.join(db_dir, "cert9.db")):
        return 0

    ownership = _load_nss_ownership(db_dir)
    all_allowed_ders = set(DOD_CA_DER_FINGERPRINTS.values())
    removed = 0

    candidates = list(ownership.keys()) if ownership else [
        os.path.splitext(f)[0].replace("_", " ") for f in DOD_CA_DER_FINGERPRINTS.keys()
    ]

    for nick in candidates:
        meta = ownership.get(nick, {})
        if meta.get("pre_existing"):
            continue
        current_der = _get_nss_cert_der_hash(certutil, db_dir, nick)
        if current_der is None:
            ownership.pop(nick, None)
            continue
        if current_der not in all_allowed_ders:
            continue

        try:
            res = subprocess.run(
                [certutil, "-d", f"sql:{db_dir}", "-D", "-n", nick],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                removed += 1
                ownership.pop(nick, None)
        except Exception:
            pass

    manifest_file = os.path.join(db_dir, ".sentinel_nss_manifest.json")
    if not ownership and os.path.isfile(manifest_file):
        try:
            os.remove(manifest_file)
        except OSError:
            pass
    elif ownership:
        _save_nss_ownership(db_dir, ownership)

    if removed and log_fn:
        log_fn(f"Removed {removed} Sentinel-managed DoD CA certificate(s) from {db_dir}")
    return removed
