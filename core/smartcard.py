"""Smart card reader, daemon, and on-card certificate manager for Sentinel v2."""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

from core import __version__
from core.ca_manifest import DOD_CA_DER_FINGERPRINTS, validate_and_reserialize_cert
from core.rust_bridge import (
    parse_card_certificate_rust,
    parse_pkcs15_list_rust,
    read_card_certificates_rust,
    is_cac_atr_rust,
)

logger = logging.getLogger("sentinel.smartcard")
MAX_OCSP_RESPONSE_BYTES = 1024 * 1024  # 1 MB ceiling
_CACHE_TTL_SECONDS = 6.0


@dataclass
class CardCertificate:
    id: str
    label: str
    subject: str
    issuer: str
    issuer_cn: str
    cn: str
    holder_name: str
    edipi: str
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    valid_to_str: str
    serial: str
    usage: str
    is_valid: bool
    status_text: str
    raw_der: Optional[bytes] = None
    ocsp_status: Optional[str] = None
    upn: Optional[str] = None
    aia_url: Optional[str] = None


@dataclass
class SmartCardStatus:
    service_active: bool
    reader_name: Optional[str]
    card_present: bool
    atr: Optional[str]
    card_name: Optional[str]
    token_label: Optional[str]
    token_serial: Optional[str]
    certificates: List[CardCertificate]
    pin_retries_remaining: Optional[int] = None
    pin_locked: bool = False
    pin_status_msg: Optional[str] = None

    @property
    def primary_certificate(self) -> Optional[CardCertificate]:
        for c in self.certificates:
            if "0005" in c.id or c.id in ("01", "1") or "Cert 5" in c.label or "ID" in c.usage or "PIV" in c.usage:
                return c
        return self.certificates[0] if self.certificates else None


_CERT_CACHE: Dict[str, List[CardCertificate]] = {}
_CARD_STATE_CACHE: Dict[str, SmartCardStatus] = {}
_CARD_STATE_CACHE_TS: Dict[str, float] = {}


def clear_smartcard_cache() -> None:
    """Clear in-memory certificate and card state caches."""
    _CERT_CACHE.clear()
    _CARD_STATE_CACHE.clear()
    _CARD_STATE_CACHE_TS.clear()


def is_pcscd_active() -> bool:
    """Check if pcscd daemon or activation socket is active and running."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "pcscd.socket", "pcscd"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        states = res.stdout.strip().splitlines()
        return any(s == "active" for s in states)
    except Exception as e:
        logger.debug(f"Failed to check pcscd status: {e}")
        return False


def _parse_cert_date(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    raw = raw.replace("notBefore=", "").replace("notAfter=", "").strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            pass
    return None


def format_dod_cardholder_name(cn: str) -> Tuple[str, str]:
    """Parse DoD CAC Common Name into clean holder name and EDIPI.

    Handles standard formats:
      LAST.FIRST.M.EDIPI -> First M Last
      LAST.FIRST.M.CTR.EDIPI -> First M Last
      LAST.FIRST.M.JR.EDIPI -> First M Last Jr
      LAST.FIRST.M.JR.CTR.EDIPI -> First M Last Jr
    """
    if not cn or "." not in cn:
        return cn, ""

    parts = [p.strip() for p in cn.split(".") if p.strip()]
    if not parts:
        return cn, ""

    edipi = ""
    if parts[-1].isdigit():
        edipi = parts.pop()

    component_tokens = {"CTR", "CIV", "MIL", "FN", "NAF", "VOL", "RET", "CONTRACTOR", "AFFILIATE"}
    gen_suffixes = {"JR", "SR", "II", "III", "IV", "V"}

    filtered_parts = []
    found_gen = ""
    for p in parts:
        p_upper = p.upper()
        if p_upper in component_tokens:
            continue
        if p_upper in gen_suffixes:
            found_gen = p.title() if p_upper in {"JR", "SR"} else p_upper
            continue
        filtered_parts.append(p)

    if not filtered_parts:
        return cn, edipi

    if len(filtered_parts) >= 2:
        last = filtered_parts[0].title()
        if found_gen:
            last = f"{last} {found_gen}"
        first_middle = " ".join(p.title() for p in filtered_parts[1:])
        holder_name = f"{first_middle} {last}"
    else:
        holder_name = filtered_parts[0].title()
        if found_gen:
            holder_name = f"{holder_name} {found_gen}"

    return holder_name, edipi


def _parse_x509_text(out_text: str, cert_id: str, label: str, usage: str) -> CardCertificate:
    subject = ""
    issuer = ""
    not_before_str = ""
    not_after_str = ""
    serial = ""

    for line in out_text.splitlines():
        if line.startswith("subject="):
            subject = line.replace("subject=", "").strip()
        elif line.startswith("issuer="):
            issuer = line.replace("issuer=", "").strip()
        elif line.startswith("notBefore="):
            not_before_str = line.strip()
        elif line.startswith("notAfter="):
            not_after_str = line.strip()
        elif line.startswith("serial="):
            serial = line.replace("serial=", "").strip()

    from datetime import timezone
    valid_from = _parse_cert_date(not_before_str)
    valid_to = _parse_cert_date(not_after_str)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    is_valid = bool(valid_to and valid_to > now and (not valid_from or valid_from <= now))
    if valid_from and valid_from > now:
        status_text = f"Not Yet Valid (Valid from {valid_from.strftime('%b %Y')})"
    elif valid_to:
        if valid_to < now:
            status_text = "Expired"
        elif (valid_to - now).days < 60:
            status_text = f"Expiring soon ({(valid_to - now).days} days) (Revocation Unchecked)"
        else:
            status_text = f"Date Valid through {valid_to.strftime('%b %Y')} (Revocation Unchecked)"
    else:
        status_text = "Unknown Validity"

    # Extract CN
    cn_match = re.search(r"CN\s*=\s*([^\n,]+)", subject)
    cn = cn_match.group(1).strip() if cn_match else ""

    # Extract Issuer CN
    iss_match = re.search(r"CN\s*=\s*([^\n,]+)", issuer)
    issuer_cn = iss_match.group(1).strip() if iss_match else issuer

    # Extract DoD EDIPI & clean Holder Name
    holder_name, edipi = format_dod_cardholder_name(cn)

    if not holder_name:
        sn_match = re.search(r"serialNumber\s*=\s*([^\s,]+)", subject, re.I)
        if sn_match:
            holder_name = f"PIV Credential ({sn_match.group(1)})"
        elif cn:
            holder_name = cn
        else:
            holder_name = "DoD Smart Card Credential"

    if not edipi:
        # Fallback regex for 10-digit DoD EDIPI anywhere in subject
        m = re.search(r"\b(\d{10})\b", subject)
        if m:
            edipi = m.group(1)

    return CardCertificate(
        id=cert_id,
        label=label,
        subject=subject,
        issuer=issuer,
        issuer_cn=issuer_cn,
        cn=cn,
        holder_name=holder_name,
        edipi=edipi,
        valid_from=valid_from,
        valid_to=valid_to,
        valid_to_str=valid_to.strftime("%Y-%m-%d") if valid_to else "Unknown",
        serial=serial,
        usage=usage,
        is_valid=is_valid,
        status_text=status_text,
    )


def read_card_certificates() -> List[CardCertificate]:
    """Read and parse all X.509 certificates from the inserted CAC with dynamic discovery."""
    # 1. Primary path: Direct in-process NIST SP 800-73-4 PIV APDU reader via Rust
    native_certs = read_card_certificates_rust()
    if native_certs:
        logger.debug(f"Successfully read {len(native_certs)} certificates via native PIV APDU reader.")
        return native_certs

    # 2. Secondary path: Fallback to pkcs15-tool if card uses non-PIV applet or native driver is unavailable
    certs: List[CardCertificate] = []
    pkcs15_tool = shutil.which("pkcs15-tool")
    if not pkcs15_tool:
        return certs

    known_specs = {
        "0005": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "01": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "1": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "0002": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "02": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "2": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "0003": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "03": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "3": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "0004": ("CAC Device Authentication", "Device / Card Authentication"),
        "04": ("CAC Device Authentication", "Device / Card Authentication"),
        "4": ("CAC Device Authentication", "Device / Card Authentication"),
    }

    # Attempt dynamic certificate enumeration via pkcs15-tool -c
    candidate_ids: List[Tuple[str, str, str]] = []
    try:
        res_list = subprocess.run([pkcs15_tool, "-c"], capture_output=True, text=True, timeout=5)
        parsed_pairs = parse_pkcs15_list_rust(res_list.stdout)
        for cid, clabel in parsed_pairs:
            spec = known_specs.get(cid, (clabel or f"Certificate {cid}", "Smart Card Credential"))
            candidate_ids.append((cid, spec[0], spec[1]))
    except Exception as e:
        logger.debug(f"Dynamic cert list query failed: {e}")

    # Fallback to standard probed IDs across cac and piv-II drivers
    if not candidate_ids:
        candidate_ids = [
            ("0005", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
            ("01", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
            ("0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
            ("02", "CAC Email Signature", "S/MIME Digital Email Signing"),
            ("0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
            ("03", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
            ("0004", "CAC Device Authentication", "Device / Card Authentication"),
            ("04", "CAC Device Authentication", "Device / Card Authentication"),
        ]

    seen_ids = set()
    for cid, label, usage in candidate_ids:
        if cid in seen_ids:
            continue
        try:
            res_cert = subprocess.run(
                [pkcs15_tool, "--read-certificate", cid],
                capture_output=True,
                timeout=4,
            )
            raw_der = res_cert.stdout
            if not raw_der or (b"BEGIN CERTIFICATE" not in raw_der and len(raw_der) < 64):
                continue

            # 1. Fast path: ASN.1 DER/PEM parsing via Rust native accelerator
            parsed = parse_card_certificate_rust(cid, label, usage, raw_der)
            if parsed:
                certs.append(parsed)
                seen_ids.add(cid)
                continue

            # 2. Fallback path: OpenSSL CLI subprocess
            res_x509 = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                input=raw_der,
                capture_output=True,
                timeout=3,
            )
            out = res_x509.stdout.decode(errors="replace")
            if "subject=" not in out:
                # Retry without -inform DER in case it was emitted as PEM
                res_x509 = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                    input=raw_der,
                    capture_output=True,
                    timeout=3,
                )
                out = res_x509.stdout.decode(errors="replace")

            if "subject=" in out:
                parsed = _parse_x509_text(out, cid, label, usage)
                parsed.raw_der = raw_der
                certs.append(parsed)
                seen_ids.add(cid)
        except Exception as e:
            logger.debug(f"Failed to read certificate {cid}: {e}")

    return certs


def _verify_public_key_signature(public_key, signature: bytes, tbs_bytes: bytes, hash_alg) -> bool:
    """Verify an X.509 or OCSP signature against RSA, ECDSA, or EdDSA public keys."""
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_alg is None:
                return False
            public_key.verify(signature, tbs_bytes, padding.PKCS1v15(), hash_alg)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_alg is None:
                return False
            public_key.verify(signature, tbs_bytes, ec.ECDSA(hash_alg))
            return True
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, tbs_bytes)
            return True
    except Exception:
        return False
    return False


def _verify_ocsp_response_cryptographically(
    ocsp_resp,
    single_resp,
    x509_cert,
    issuer_cert,
) -> Tuple[bool, str]:
    """Verify RFC 6960 OCSP response issuer hashes, freshness window, responder authorization, and signature."""
    from datetime import timedelta, timezone
    from cryptography import x509
    from cryptography.x509 import ocsp, ExtensionNotFound
    from cryptography.x509.oid import ExtendedKeyUsageOID

    # 1. Verify CertID issuer_name_hash and issuer_key_hash match issuer_cert
    try:
        ref_alg = type(single_resp.hash_algorithm)()
        ref_req = ocsp.OCSPRequestBuilder().add_certificate(x509_cert, issuer_cert, ref_alg).build()
        if (
            single_resp.issuer_name_hash != ref_req.issuer_name_hash
            or single_resp.issuer_key_hash != ref_req.issuer_key_hash
        ):
            return False, "OCSP CertID issuer hash mismatch against expected issuing CA"
    except Exception as e:
        return False, f"Failed to validate OCSP CertID issuer hash: {e}"

    # 2. Verify response freshness (thisUpdate / nextUpdate with 5-minute clock-skew allowance)
    now_utc = datetime.now(timezone.utc)
    skew = timedelta(minutes=5)

    this_update = getattr(single_resp, "this_update_utc", None) or getattr(single_resp, "this_update", None)
    if this_update is None:
        return False, "OCSP response missing mandatory thisUpdate timestamp"
    if this_update.tzinfo is None:
        this_update = this_update.replace(tzinfo=timezone.utc)

    if this_update > now_utc + skew:
        return False, "OCSP response thisUpdate timestamp is in the future"

    next_update = getattr(single_resp, "next_update_utc", None) or getattr(single_resp, "next_update", None)
    if next_update is not None:
        if next_update.tzinfo is None:
            next_update = next_update.replace(tzinfo=timezone.utc)
        if now_utc - skew > next_update:
            return False, "OCSP response has expired (nextUpdate passed)"
    elif now_utc - this_update > timedelta(days=7):
        return False, "OCSP response is stale (older than 7 days without nextUpdate)"

    # 3. Verify cryptographic signature and responder authorization (RFC 6960 Section 4.2.2.2)
    tbs_bytes = ocsp_resp.tbs_response_bytes
    sig_bytes = ocsp_resp.signature
    sig_hash_alg = ocsp_resp.signature_hash_algorithm

    # Case A: Signed directly by the issuing CA
    try:
        if _verify_public_key_signature(issuer_cert.public_key(), sig_bytes, tbs_bytes, sig_hash_alg):
            return True, "Verified directly by issuing CA"
    except Exception:
        pass

    # Case B: Signed by an authorized delegated OCSP responder certificate signed by issuer_cert
    responder_certs = getattr(ocsp_resp, "certificates", None) or []
    for resp_cert in responder_certs:
        try:
            try:
                from cryptography.hazmat.primitives import serialization
                from core.rust_bridge import verify_ocsp_responder_cert_der_rust
                rust_resp = verify_ocsp_responder_cert_der_rust(
                    resp_cert.public_bytes(serialization.Encoding.DER),
                    issuer_cert.public_bytes(serialization.Encoding.DER),
                )
                if rust_resp is not None:
                    ok_time, ok_auth, _ = rust_resp
                    if not (ok_time and ok_auth):
                        continue
            except Exception:
                pass

            if resp_cert.issuer != issuer_cert.subject:
                continue

            # Check responder certificate validity window
            nb = getattr(resp_cert, "not_valid_before_utc", None) or resp_cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = getattr(resp_cert, "not_valid_after_utc", None) or resp_cert.not_valid_after.replace(tzinfo=timezone.utc)
            if not (nb - skew <= now_utc <= na + skew):
                continue

            # Check id-kp-OCSPSigning Extended Key Usage
            try:
                eku = resp_cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    continue
            except ExtensionNotFound:
                continue

            # Verify delegated responder cert signature using issuer_cert public key
            if not _verify_public_key_signature(
                issuer_cert.public_key(),
                resp_cert.signature,
                resp_cert.tbs_certificate_bytes,
                resp_cert.signature_hash_algorithm,
            ):
                continue

            # Verify OCSP response signature using delegated responder public key
            if _verify_public_key_signature(resp_cert.public_key(), sig_bytes, tbs_bytes, sig_hash_alg):
                return True, "Verified via authorized delegated OCSP responder"
        except Exception:
            continue

    return False, "OCSP response signature could not be verified against issuing CA or authorized responder"


def verify_cert_ocsp(
    cert: CardCertificate,
    allow_non_mil_for_testing: bool = False,
) -> Tuple[Optional[bool], str]:
    """Verify online certificate revocation status via the OCSP responder in cert's AIA extension.

    Returns:
        (True, message) if certificate status is cryptographically confirmed GOOD.
        (False, message) if certificate status is cryptographically confirmed REVOKED.
        (None, message) if OCSP responder is unreachable, offline, AIA is absent, or response is unverified.
    """
    if not cert.raw_der:
        return None, "Raw certificate data unavailable for OCSP check"

    try:
        import urllib.request
        import urllib.error
        from pathlib import Path
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp, ExtensionNotFound, AuthorityInformationAccessOID
    except ImportError as e:
        return None, f"OCSP cryptography module unavailable: {e}"

    try:
        # Load X.509 certificate
        try:
            x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        except Exception:
            x509_cert = x509.load_pem_x509_certificate(cert.raw_der)

        # 1. Extract and validate AIA OCSP URI
        ocsp_urls: List[str] = []
        try:
            aia = x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia.value:
                if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(str(access_desc.access_location.value))
        except ExtensionNotFound:
            pass

        if not ocsp_urls:
            return None, "No OCSP responder URL found in Certificate AIA extension"

        ocsp_url = ocsp_urls[0]
        parsed_url = urlparse(ocsp_url)
        scheme = (parsed_url.scheme or "").lower()
        host = (parsed_url.hostname or "").lower().rstrip(".")
        if scheme not in ("http", "https") or not host:
            return None, f"Security policy: Rejected invalid OCSP responder URL ({ocsp_url})"
        if not allow_non_mil_for_testing and not (host == "mil" or host.endswith(".mil")):
            return None, f"Security policy: Rejected non-.mil OCSP responder host ({host})"
        try:
            from core.rust_bridge import validate_ocsp_url_rust
            rust_url_ok = validate_ocsp_url_rust(ocsp_url, allow_non_mil_for_testing)
            if rust_url_ok is False:
                return None, f"Security policy: Rejected OCSP responder URL by native validator ({ocsp_url})"
        except Exception:
            pass

        # 2. Match Issuer CA from manifest-verified bundled DoD certificates AND verify leaf signature
        issuer_cert: Optional[x509.Certificate] = None
        repo_root = Path(__file__).resolve().parent.parent
        ca_dirs = [
            repo_root / "certificates" / "intermediates",
            repo_root / "certificates" / "roots",
            repo_root / "certificates" / "all_cas",
        ]
        allowed_der_hashes = set(DOD_CA_DER_FINGERPRINTS.values())

        target_issuer_name = x509_cert.issuer
        matched_subject_but_invalid_sig = False
        for d in ca_dirs:
            if not d.is_dir():
                continue
            for cert_file in d.glob("*.crt"):
                try:
                    data = cert_file.read_bytes()
                    if validate_and_reserialize_cert(data, cert_file.name) is None:
                        continue
                    cand = x509.load_pem_x509_certificate(data)
                    cand_der_hash = hashlib.sha256(
                        cand.public_bytes(serialization.Encoding.DER)
                    ).hexdigest().lower()
                    if cand_der_hash not in allowed_der_hashes:
                        continue
                    if cand.subject == target_issuer_name:
                        if _verify_public_key_signature(
                            cand.public_key(),
                            x509_cert.signature,
                            x509_cert.tbs_certificate_bytes,
                            x509_cert.signature_hash_algorithm,
                        ):
                            issuer_cert = cand
                            break
                        else:
                            matched_subject_but_invalid_sig = True
                except Exception:
                    continue
            if issuer_cert:
                break

        if not issuer_cert:
            if matched_subject_but_invalid_sig:
                return None, "Security policy: Leaf certificate signature failed verification against DoD issuing CA"
            return None, f"Issuer CA certificate not found in verified DoD store for {cert.issuer_cn}"

        # 3. Build OCSP Request
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(x509_cert, issuer_cert, hashes.SHA256())
        ocsp_req = builder.build()
        req_data = ocsp_req.public_bytes(serialization.Encoding.DER)

        # 4. Transmit OCSP Request via HTTP POST with bounded response size
        req = urllib.request.Request(
            ocsp_url,
            data=req_data,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                "User-Agent": f"Sentinel/{__version__}",
            },
        )

        with urllib.request.urlopen(req, timeout=4.0) as resp:
            resp_data = resp.read(MAX_OCSP_RESPONSE_BYTES + 1)

        if len(resp_data) > MAX_OCSP_RESPONSE_BYTES:
            return None, "Security policy: OCSP response exceeded maximum permitted size (1 MB)"

        # 5. Parse OCSP Response
        ocsp_resp = ocsp.load_der_ocsp_response(resp_data)
        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            status_name = getattr(ocsp_resp.response_status, "name", str(ocsp_resp.response_status))
            return None, f"OCSP responder status: {status_name} (May require DoD intranet/VPN)"

        matched_single = None
        for single_resp in ocsp_resp.responses:
            if single_resp.serial_number == x509_cert.serial_number:
                matched_single = single_resp
                break

        if matched_single is None:
            return None, "OCSP response did not contain status for the requested certificate serial"

        # 6. Cryptographically verify OCSP response before trusting status
        verified_ok, verify_msg = _verify_ocsp_response_cryptographically(
            ocsp_resp,
            matched_single,
            x509_cert,
            issuer_cert,
        )
        if not verified_ok:
            logger.warning(f"Rejected unverified OCSP response: {verify_msg}")
            return None, f"Unverified OCSP response rejected: {verify_msg}"

        matched_status = matched_single.certificate_status
        rev_time = getattr(matched_single, "revocation_time_utc", None) or getattr(matched_single, "revocation_time", None)

        if matched_status == ocsp.OCSPCertStatus.GOOD:
            return True, "Good (Revocation status cryptographically verified via OCSP)"
        elif matched_status == ocsp.OCSPCertStatus.REVOKED:
            time_str = rev_time.strftime("%Y-%m-%d %H:%M:%S UTC") if rev_time else "Unknown"
            return False, f"REVOKED on {time_str}"
        elif matched_status == ocsp.OCSPCertStatus.UNKNOWN:
            return None, "Certificate status unknown to OCSP responder"
        else:
            return None, f"OCSP returned status: {matched_status}"

    except (urllib.error.URLError, TimeoutError, OSError) as e:
        logger.debug(f"OCSP responder unreachable: {e}")
        return None, "OCSP responder unreachable (Check network or CAC intranet)"
    except Exception as e:
        logger.debug(f"OCSP verification error: {e}")
        return None, f"OCSP error: {e}"


def scan_smartcard(force_refresh: bool = False) -> SmartCardStatus:
    """Comprehensive hardware & token inspection with full-state caching to prevent APDU/PKCS#11 poll contention."""
    if force_refresh:
        clear_smartcard_cache()

    active = is_pcscd_active()
    reader_name = None
    card_present = False
    atr = None
    card_name = None
    token_label = None
    token_serial = None
    certificates: List[CardCertificate] = []

    opensc_tool = shutil.which("opensc-tool")
    pkcs11_tool = shutil.which("pkcs11-tool")

    # 0. Fast-path: Direct PC/SC Lite native inspection (reader presence + ATR only, zero APDUs)
    from core.rust_bridge import query_native_pcsc_rust, read_card_metadata_rust
    native_pcsc = query_native_pcsc_rust()
    native_queried = False

    if native_pcsc and native_pcsc.available:
        native_queried = True
        active = native_pcsc.service_running
        if native_pcsc.readers:
            reader_name = native_pcsc.primary_reader or native_pcsc.readers[0]
        card_present = native_pcsc.card_present
        if native_pcsc.atr:
            atr = native_pcsc.atr
            if native_pcsc.is_cac:
                card_name = "DoD Common Access Card (CAC / PIV)"

    # 1. Fallback: Detect Readers and Card presence via opensc-tool if native PC/SC is not available
    if not native_queried and opensc_tool:
        try:
            res_list = subprocess.run([opensc_tool, "-l"], capture_output=True, text=True, timeout=3)
            for line in res_list.stdout.splitlines():
                if "Yes" in line or "No" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        card_present = (parts[1].lower() == "yes")
                        reader_name = " ".join(parts[2:]).strip()
                        active = True
                        break

            if card_present:
                res_atr = subprocess.run([opensc_tool, "-a"], capture_output=True, text=True, timeout=3)
                atr_out = res_atr.stdout.strip()
                if atr_out:
                    atr = atr_out.splitlines()[0].strip()

                res_name = subprocess.run([opensc_tool, "-n"], capture_output=True, text=True, timeout=3)
                name_out = res_name.stdout.strip()
                if name_out:
                    card_name = name_out.splitlines()[0].strip()
                elif atr and is_cac_atr_rust(atr):
                    card_name = "DoD Common Access Card (CAC / PIV)"
        except Exception as e:
            logger.debug(f"opensc-tool scan failed: {e}")

    if not card_present:
        clear_smartcard_cache()
        return SmartCardStatus(
            service_active=active,
            reader_name=reader_name,
            card_present=False,
            atr=None,
            card_name=None,
            token_label=None,
            token_serial=None,
            certificates=[],
            pin_retries_remaining=None,
            pin_locked=False,
            pin_status_msg=None,
        )

    # Return cached certificate/card metadata and PIN retry status within TTL
    state_cache_key = f"{reader_name or 'default'}:{atr or 'unknown'}"
    cache_age = time.monotonic() - _CARD_STATE_CACHE_TS.get(state_cache_key, 0.0)
    if not force_refresh and state_cache_key in _CARD_STATE_CACHE and cache_age < _CACHE_TTL_SECONDS:
        cached = _CARD_STATE_CACHE[state_cache_key]
        return SmartCardStatus(
            service_active=active,
            reader_name=reader_name or cached.reader_name,
            card_present=True,
            atr=atr or cached.atr,
            card_name=cached.card_name or card_name,
            token_label=cached.token_label,
            token_serial=cached.token_serial,
            certificates=cached.certificates,
            pin_retries_remaining=cached.pin_retries_remaining,
            pin_locked=cached.pin_locked,
            pin_status_msg=cached.pin_status_msg,
        )

    # 1.5 Query card metadata (token serial, label, model) via native NIST PIV CHUID/CCC
    native_c_name, native_t_label, native_t_serial = read_card_metadata_rust(reader_name)
    if native_c_name and not card_name:
        card_name = native_c_name
    if native_t_label and not token_label:
        token_label = native_t_label
    if native_t_serial and not token_serial:
        token_serial = native_t_serial

    if not card_name and opensc_tool:
        try:
            res_name = subprocess.run([opensc_tool, "-n"], capture_output=True, text=True, timeout=2)
            name_out = res_name.stdout.strip()
            if name_out:
                card_name = name_out.splitlines()[0].strip()
        except Exception:
            pass

    # 2. Extract Token Label & Serial from pkcs11-tool (fallback only if native inspection did not resolve serial)
    if not token_serial and pkcs11_tool:
        try:
            res_p11 = subprocess.run([pkcs11_tool, "-L"], capture_output=True, text=True, timeout=4)
            for line in res_p11.stdout.splitlines():
                if "token label" in line and not token_label:
                    token_label = line.split(":", 1)[1].strip()
                elif "serial num" in line and not token_serial:
                    token_serial = line.split(":", 1)[1].strip()
                elif "Slot" in line and not reader_name:
                    reader_name = line.split(":", 1)[1].strip()
        except Exception as e:
            logger.debug(f"pkcs11-tool scan failed: {e}")

    # 3. Read Certificates if card is present (only cache when unique token_serial or label is known)
    cache_key: Optional[str] = None
    if token_serial:
        cache_key = f"{reader_name or 'default'}:{atr or 'unknown'}:{token_serial}"
    elif token_label:
        cache_key = f"{reader_name or 'default'}:{atr or 'unknown'}:{token_label}"

    if cache_key and cache_key in _CERT_CACHE and _CERT_CACHE[cache_key]:
        certificates = _CERT_CACHE[cache_key]
    else:
        certificates = read_card_certificates()
        if certificates and cache_key:
            _CERT_CACHE[cache_key] = certificates

    pin_retries_remaining: Optional[int] = None
    pin_locked: bool = False
    pin_status_msg: Optional[str] = None

    from core.rust_bridge import query_pin_status_rust
    ok, retries, msg = query_pin_status_rust(reader_name)
    if retries == 255:
        # 0x90 0x00: PIN already verified in active session; card did not emit a numeric retry count
        pin_retries_remaining = None
        pin_locked = False
        pin_status_msg = msg
    elif ok or retries > 0 or (msg and "locked" in msg.lower()):
        pin_retries_remaining = retries
        pin_locked = (retries == 0)
        pin_status_msg = msg

    status = SmartCardStatus(
        service_active=active,
        reader_name=reader_name,
        card_present=card_present,
        atr=atr,
        card_name=card_name,
        token_label=token_label,
        token_serial=token_serial,
        certificates=certificates,
        pin_retries_remaining=pin_retries_remaining,
        pin_locked=pin_locked,
        pin_status_msg=pin_status_msg,
    )
    _CARD_STATE_CACHE[state_cache_key] = status
    _CARD_STATE_CACHE_TS[state_cache_key] = time.monotonic()
    return status


def change_card_pin(old_pin: str, new_pin: str, reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Change PIV Cardholder PIN on inserted smart card via native APDUs with fail-closed retry verification.

    Returns: (is_success, retries_remaining, status_message)
    """
    from core.rust_bridge import query_pin_status_rust, change_pin_rust

    ok_stat, retries_stat, msg_stat = query_pin_status_rust(reader_name)
    if retries_stat == 0 and msg_stat and "locked" in msg_stat.lower():
        clear_smartcard_cache()
        return False, 0, "Card PIN is locked (0 retries remaining). PUK unblock is required."
    if not ok_stat:
        clear_smartcard_cache()
        return (
            False,
            -1,
            f"Security abort: Could not verify current PIN retry counter before PIN change ({msg_stat or 'status query failed'}).",
        )
    if retries_stat <= 1:
        clear_smartcard_cache()
        return (
            False,
            retries_stat,
            "Refusing automated PIN change: only 1 PIN retry attempt remains. "
            "Authenticate once or use a PUK-capable tool to prevent card lockout.",
        )

    success, retries, msg = change_pin_rust(old_pin, new_pin, reader_name)
    clear_smartcard_cache()
    return success, retries, msg
