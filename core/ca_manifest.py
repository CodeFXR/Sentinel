"""Authoritative DoD PKI Certificate Manifest, DER Fingerprints, and Lifecycle Verifier.

Shared across unprivileged certificate/browser/OCSP modules and the privileged helper
so both system-trust and browser-trust boundaries enforce identical cryptographic checks
without importing privileged helper code into unprivileged modules.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
import shutil
import subprocess
from typing import Callable, Dict, List, Optional

# Cryptographic SHA-256 file digest manifest for official DoD certificates.
DOD_CA_FINGERPRINTS: Dict[str, str] = {
    "DOD_DERILITY_CA-1.crt": "b792d3cd0a8d2b077ea81cab0c6cd4edc018b054b89c59268d42a5590bd691ff",
    "DOD_DERILITY_CA-3.crt": "365049baa57070951e53dc9011006d94f95b31baff9404fbf2a1734675559d84",
    "DOD_DERILITY_CA-4.crt": "69e4b7ac1dbd472c2b561775e0d992d2a2ec8a9e2dad537693740f0340016805",
    "DOD_DERILITY_CA-5.crt": "8416b0a5526c15f294309ed19cc790439b09b10755b7a370f670cac64dc810d7",
    "DOD_DERILITY_CA-6.crt": "713112199a0198a97837d8a3bca13c218bc7ec6590ced816ebdd8d7ea8b3c1a5",
    "DOD_EMAIL_CA-62.crt": "aa418e09adc19edb0a0302e01120a07d68f60cf05c2c4c28aef24af93b9a7d26",
    "DOD_EMAIL_CA-63.crt": "e0471278a605146108bcfb6cd8408ec94d497c2e912d91b13dc8c4d85e6474a7",
    "DOD_EMAIL_CA-64.crt": "433098257647e0fd92b2262bf58b16dacc54a98f51cf8b5be5d47dbb5d92b1a1",
    "DOD_EMAIL_CA-65.crt": "adb54e87d349dcc5665652d83274815da10e5cd18640a5f84a4ed90b96a83bc6",
    "DOD_EMAIL_CA-70.crt": "3988b7899fb52ba764169db787d7ae357b12f76e361d20c631cb41740fca6b69",
    "DOD_EMAIL_CA-71.crt": "97b6bcd92d05f4e4c764560365b4ed728f983ab48477286e106e4100c28a275d",
    "DOD_EMAIL_CA-72.crt": "b342f980fd1a88ad4605447db67eae6163ba33cb7e108ac9ace482a0139a9988",
    "DOD_EMAIL_CA-73.crt": "93f52cbb1c9666e5b9bc7dd7b901816560ee0d82edad97137aec35531b21761f",
    "DOD_EMAIL_CA-78.crt": "4f3ee6ddd7821cb9d49d09805ce3678d1ba521efc44d6f146fe79363b3170b9b",
    "DOD_EMAIL_CA-79.crt": "ef60845fc4d2bedcb404a7d7b375229e6a6dee6c2def84866f3dd0a14acd639b",
    "DOD_EMAIL_CA-80.crt": "bf463e544dbc8b2dbe588ef957df9251af2deb9171916fc1371f0ccaa7b73633",
    "DOD_EMAIL_CA-81.crt": "87696e907b5c9bb7bb407480559bd98e07b54d0a47d748540b01ce0bac379fcf",
    "DOD_ID_CA-62.crt": "25f2aa5eb6ebff9b66ffde5c62fea0d4eb791ec7fa7ff6f2e388126c74100ed0",
    "DOD_ID_CA-63.crt": "7649a6591cebc1c6400195caacba43e76d2588a2025eba49eb2d2cafe2c097ae",
    "DOD_ID_CA-64.crt": "c81bd68f5b7453aa99c471fe79f2eeba643e9b0ff2466235b6b9deecfac841c9",
    "DOD_ID_CA-65.crt": "15896437be65f4c922b51623b40621a362483175638c567f6738b5a8d136b3cb",
    "DOD_ID_CA-70.crt": "1fd13654266223a348e79f827a3f358ccf803215955990982d32009b270d9b2e",
    "DOD_ID_CA-71.crt": "9d93bfba93a82b8532ff3985b81fcf26dd42f878e8ab397a857ee6ba52db4306",
    "DOD_ID_CA-72.crt": "d53d3673229377b608f52f622a6db780baed0692ceb16593f1f87b45257cf005",
    "DOD_ID_CA-73.crt": "a4d2016bff3e1baec36b42a4921ec3d7ef8b3130e10bb1b02cf0c01babf8a3df",
    "DOD_ID_CA-78.crt": "178f10e93fb7966d437cf40f02115237f558704337a482f020d63cd9b004ae76",
    "DOD_ID_CA-79.crt": "3d49e89b592e2eeb4389fb82747e1e67e5389c7d25d70352c9df9480f83cebd9",
    "DOD_ID_CA-80.crt": "17038dc5ccd48f4ed0677dea3758d7059d0fec7aeb0aeaa748f80d0133a8d577",
    "DOD_ID_CA-81.crt": "09a0be8af9309bb53bbc643f7178a6b3d6e12f59907a7a2116fef53ac099c5ce",
    "DOD_SW_CA-66.crt": "6c592affece2d6bfcc51a5d74a8bf72f2a730554bfb886169cef4a692c1c077f",
    "DOD_SW_CA-67.crt": "a3f6b2e15d03b2be4b38d870fc483b7b29096978cbf469b23a55469bcf528f8e",
    "DOD_SW_CA-68.crt": "5043ab9bf7978b0292ed6f3e9c5057e86eab5d9107845766e878ddec2249c38a",
    "DOD_SW_CA-69.crt": "210c46224b7375fcf246165163c30185e41ec4df0730b10b9afa2fe79c4fa538",
    "DOD_SW_CA-74.crt": "bc3e078e31530686c0a058c0911aa1ccb80cbba0fd54c19c60f06f567ada2104",
    "DOD_SW_CA-75.crt": "8ee4b5c2731dad2a18e13eab0289ab7a52622ff55272ae796a0b5d20fcdb6cde",
    "DOD_SW_CA-76.crt": "550b688a41e6841c649b876e74d4a67331832ca834195bb78411036448dfa975",
    "DOD_SW_CA-77.crt": "2a5c88ce7e20096fdf6c739dc54d842996b6e75fc6d05913b0f3b06ede151db8",
    "DOD_SW_CA-82.crt": "81498acfe45eda7f67bef9c345618fec8efa8b612fd9c9bbb016306b04f2c5b5",
    "DOD_SW_CA-83.crt": "612625a070c229a89f4137995989689cace809ab75f1879c80adaee10c45acee",
    "DOD_SW_CA-84.crt": "4c7245e536c95d8035604e516e8a32b09670f33545de7cba06075da0757364f7",
    "DOD_SW_CA-85.crt": "d9ed4f3ebec2295f4a792a008a905e540f95834531540434a66c3a697ab3de35",
    "DoD_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Root_CA_3.crt": "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177",
    "DoD_Root_CA_4.crt": "488cac7d9d9fe818945410a5d37713ac3ebbd8d5a36f71d489278c8ba334b27c",
    "DoD_Root_CA_5.crt": "07820e449f9543fa02f9f207cd0babb15d82d7f2dea34874e8e85a2a3f55a0a4",
    "DoD_Root_CA_6.crt": "6936a739b3327f15c563d106862c5b9406c6be24cb5656288ada6826783e0ff4",
    "DoD_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
    "DoW_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
}

# Canonical ASN.1 DER SHA-256 certificate fingerprints (immune to CRLF/LF line-ending variance).
DOD_CA_DER_FINGERPRINTS: Dict[str, str] = {
    "DOD_DERILITY_CA-1.crt": "67a953b9e17f77599c6e553053dcd43fd7478fdd5cbd844612ceb6064386f8df",
    "DOD_DERILITY_CA-3.crt": "83eea7e541716dcfb4b705a44e34f7e0af86d839c7cd796962a70e91d4932646",
    "DOD_DERILITY_CA-4.crt": "8112237903e9a9afdc4e5bec6970c3ef09c9a63897da4156c22a77d355ad0deb",
    "DOD_DERILITY_CA-5.crt": "70a011a6b00759f6ab1d08acb3f646d66f578e41f71f1c9586e1f470f4576870",
    "DOD_DERILITY_CA-6.crt": "4f6c4dc6800346464db209f5a05ec1f4019e7ba48f7346011d9643d2e4b3eace",
    "DOD_EMAIL_CA-62.crt": "36490d91175ca3b39b21b21941db70635c58a3fd0f51135af9f0edc15cbf55b6",
    "DOD_EMAIL_CA-63.crt": "c6a4dac9fd846474ea35c52afada31510d388ee5af694d8e7f7300eee73cbd2f",
    "DOD_EMAIL_CA-64.crt": "690c69044761d3a9ab208e4ef2c7b461f09ab524137e7d059176324df42480d8",
    "DOD_EMAIL_CA-65.crt": "d483b29aae8b40d62ad4757f2986a6d541c4241383d7928592fc61ba5d01085a",
    "DOD_EMAIL_CA-70.crt": "2ad7d00e45d128a46fdb5747d39eaa994f034086d05cb891e01bf61c7d97c083",
    "DOD_EMAIL_CA-71.crt": "9d7e0bfb84d6a5f66cfd701b786dc75db31422687212bf26c276b70df0627bdb",
    "DOD_EMAIL_CA-72.crt": "22ffd6b58540bed6f568890348da2654ca54b50f2216c9eade78812782206ba2",
    "DOD_EMAIL_CA-73.crt": "ca4733b4e471a699d025fa88cee35e07372dcaa9cfe609469c16a72ec5595cf7",
    "DOD_EMAIL_CA-78.crt": "2c95f5c815569b65cdf70d03f135f2cf130b82b33d5719a68d25a1ec19d405fc",
    "DOD_EMAIL_CA-79.crt": "3d8d7bf0c6381aa07ff5e0aa47fec6d077aeec1c2ee22183b2c2028a2ff35d68",
    "DOD_EMAIL_CA-80.crt": "8208232225e469e65e93497402be9a377d81a25938b85ccae3f3adc14078de93",
    "DOD_EMAIL_CA-81.crt": "8dc6e3657631ec33de1706c2803662786c120825d121b5dd4b1c90b126654967",
    "DOD_ID_CA-62.crt": "a3626dfa33eadf6f1ac300a733f52322c6cdc59f5d561e2188c493d016c49dd5",
    "DOD_ID_CA-63.crt": "dd2dc71d5affa281ceb4da78d58a8119ffe606d732dab5343b2b1c3de4993613",
    "DOD_ID_CA-64.crt": "fc6fd238f81a3b1755db3bc5471440a186ef3ab4e9ea6d76c2e157c22236b482",
    "DOD_ID_CA-65.crt": "80e252331942dcaaaa7de7fb450ee9610081f44bbe164fe9936a759ba4541e5b",
    "DOD_ID_CA-70.crt": "3ccc94baa9108ef0ca373b89074b8cfac6c0cf0f07ab190c570d5053032f337a",
    "DOD_ID_CA-71.crt": "f7ba690fe17cff7b191ac6d32522931c6f472df487574f0d1c576da0d2ab7049",
    "DOD_ID_CA-72.crt": "b1c14ea631f47bcd7698e7673fdf5b5b104c52631ce58913346ec7a07e154638",
    "DOD_ID_CA-73.crt": "3d6a666556365400d6e2beed9dd97082537fb74887a5c68b426eb06c327e0826",
    "DOD_ID_CA-78.crt": "bbaf5275b33aff5aa9e5bce945640ac0c08f4a4d02d7d2e26e78293e912231ce",
    "DOD_ID_CA-79.crt": "4a3a111b697959d3f620cbf9f5150e4087861d47a695860aff8136a819a71e1a",
    "DOD_ID_CA-80.crt": "ad6bb50b82da2f99c242d7971012175809b22af0112f1e695ef3c236c7d2f22e",
    "DOD_ID_CA-81.crt": "abdc810cf17cea00bbaace9418b872c25cf8bf3d7694a4e05b9f391d23b80d03",
    "DOD_SW_CA-66.crt": "79dd87d87503bd9c422b49e2bf7a23a5c0783cce85d588759f3a349ec26eb84a",
    "DOD_SW_CA-67.crt": "cca9b469b4edda4d615b58c130ecaebba5ca439adbee8be15206626e5122f4ca",
    "DOD_SW_CA-68.crt": "dcd29a5b27db87d5d617f395edad6d7fa0fe230117afbf6c4b7f31f372a2e66a",
    "DOD_SW_CA-69.crt": "3320f4876c4d0fa7118f2891a1421bb3cda7bb64be80f9bd040bcff6faa3dbee",
    "DOD_SW_CA-74.crt": "6338c57b568b1d47568ab7548a8d66cc31bc4a096a4cc10a4b45edeb09bd65f6",
    "DOD_SW_CA-75.crt": "6cbc8895834385d27678cb0012d224277b02dcfc4502bceafdfe1a0a2543f416",
    "DOD_SW_CA-76.crt": "0e0f71389c9937334989842a908206e671f356a10903e2cf398abb5e27b3f40c",
    "DOD_SW_CA-77.crt": "48e2775e6db09931c3d62a913889affc653aa9d9142ac4c10bd11f6968fc4a31",
    "DOD_SW_CA-82.crt": "7aafb4a72e96483d9db2b4226dcead0bb01a95c236768c7a0f681abf5f168e81",
    "DOD_SW_CA-83.crt": "cc88db853e8f8c2c61f40f281ebca7ed08a082e1ac10679b785db9f76e9b7015",
    "DOD_SW_CA-84.crt": "560eb4465753bd286bf65fd0d16256fd126daa0d1d5abbe9ff7a5688ae830357",
    "DOD_SW_CA-85.crt": "6fa364cfc7ecdc69e581d20f0bcea306f8d8a52142b3dadda949276db1061098",
    "DoD_Root_CA_3.crt": "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2",
    "DoD_Root_CA_4.crt": "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74",
    "DoD_Root_CA_5.crt": "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9",
    "DoD_Root_CA_6.crt": "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93",
}

DOD_ROOT_FILES = ("DoD_Root_CA_3.crt", "DoD_Root_CA_4.crt", "DoD_Root_CA_5.crt", "DoD_Root_CA_6.crt")
DOD_ROOT_DER_FINGERPRINTS: Dict[str, str] = {k: DOD_CA_DER_FINGERPRINTS[k] for k in DOD_ROOT_FILES}
ROOT_CA_FILENAMES = set(DOD_ROOT_FILES) | {"DoD_Roots.pem", "DoW_Roots.pem"}
ALLOWED_CERT_FILENAMES = set(DOD_CA_FINGERPRINTS.keys())

SAFE_CERT_FILENAME = re.compile(r"^[a-zA-Z0-9_.-]+\.(crt|pem)$")
PEM_CERT_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----")


def extract_der_from_pem_body(b64_body: bytes) -> Optional[bytes]:
    """Decode base64 body of a PEM certificate block into raw ASN.1 DER bytes."""
    try:
        cleaned = re.sub(rb"\s+", b"", b64_body)
        der = base64.b64decode(cleaned, validate=True)
        if len(der) >= 64 and der[0] == 0x30:
            return der
    except Exception:
        pass
    return None


def verify_x509_ca_properties(der_bytes: bytes, require_self_signed: bool = False) -> Optional[bytes]:
    """Verify ASN.1 X.509 certificate structure, CA basic constraints, expiry, and self-signed root status.

    Returns canonical PEM bytes on success, or None if validation fails.
    """
    if shutil.which("openssl"):
        try:
            proc_check = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-ext",
                    "basicConstraints",
                    "-checkend",
                    "0",
                ],
                input=der_bytes,
                capture_output=True,
                timeout=5,
            )
            if proc_check.returncode != 0:
                return None
            out_text = proc_check.stdout.decode(errors="replace")
            if "CA:TRUE" not in out_text:
                return None

            subj_line = ""
            iss_line = ""
            for line in out_text.splitlines():
                if line.startswith("subject="):
                    subj_line = line[len("subject="):].strip()
                elif line.startswith("issuer="):
                    iss_line = line[len("issuer="):].strip()

            if not subj_line or not iss_line:
                return None
            if require_self_signed and subj_line != iss_line:
                return None

            proc_pem = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                input=der_bytes,
                capture_output=True,
                timeout=5,
            )
            if proc_pem.returncode == 0 and b"-----BEGIN CERTIFICATE-----" in proc_pem.stdout:
                return proc_pem.stdout.strip()
        except Exception:
            pass

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(der_bytes)
        if not cert.subject or not cert.issuer:
            return None
        if require_self_signed and cert.subject != cert.issuer:
            return None
        now = datetime.now(timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if not_after <= now:
            return None
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            return None
        return cert.public_bytes(serialization.Encoding.PEM).strip()
    except Exception:
        return None


def validate_and_reserialize_cert(
    data: bytes,
    fname: str,
    verify_whitelist: bool = True,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Optional[bytes]:
    """Validate X.509 certificate data, DER fingerprints, and CA properties, returning canonical PEM."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    try:
        from core.rust_bridge import validate_and_reserialize_ca_rust
        rust_res = validate_and_reserialize_ca_rust(data, fname, verify_whitelist)
        if rust_res is not None:
            pem_bytes, err_msg = rust_res
            if err_msg:
                _log(err_msg)
                return None
            return pem_bytes
    except Exception:
        pass

    pem_bodies = PEM_CERT_PATTERN.findall(data)
    if not pem_bodies:
        _log(f"Security: Rejected {fname}: contains no valid PEM certificate blocks")
        return None

    is_root_target = fname in DOD_ROOT_DER_FINGERPRINTS or fname in ("DoD_Roots.pem", "DoW_Roots.pem")
    all_allowed_ders = set(DOD_CA_DER_FINGERPRINTS.values())
    root_allowed_ders = set(DOD_ROOT_DER_FINGERPRINTS.values())

    reserialized_certs = []
    seen_der_hashes = []

    for idx, body in enumerate(pem_bodies):
        der_bytes = extract_der_from_pem_body(body)
        if not der_bytes:
            _log(f"Security: Rejected {fname}: block {idx + 1} has invalid base64 or ASN.1 sequence")
            return None

        der_sha256 = hashlib.sha256(der_bytes).hexdigest().lower()
        seen_der_hashes.append(der_sha256)

        if verify_whitelist:
            if fname in DOD_CA_DER_FINGERPRINTS:
                expected_der = DOD_CA_DER_FINGERPRINTS[fname]
                if der_sha256 != expected_der:
                    _log(
                        f"Security: DER fingerprint mismatch for '{fname}'! "
                        f"Expected {expected_der}, got {der_sha256}"
                    )
                    return None
            elif fname in ("DoD_Roots.pem", "DoW_Roots.pem"):
                if der_sha256 not in root_allowed_ders:
                    _log(f"Security: Non-root certificate found inside root bundle '{fname}' ({der_sha256})")
                    return None
            elif fname in ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Full_Chain.pem", "DoW_Full_Chain.crt"):
                if der_sha256 not in all_allowed_ders:
                    _log(f"Security: Unauthorized certificate block {idx + 1} in '{fname}' ({der_sha256})")
                    return None
            else:
                _log(f"Security: Rejected unauthorized certificate filename '{fname}'")
                return None

        validated_pem = verify_x509_ca_properties(der_bytes, require_self_signed=is_root_target)
        if not validated_pem:
            if fname in ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Full_Chain.pem", "DoW_Full_Chain.crt"):
                _log(f"Skipping expired/retired intermediate block {idx + 1} in bundle '{fname}'")
                continue
            _log(f"Security: Rejected {fname}: certificate block {idx + 1} failed X.509 CA/validity verification")
            return None

        reserialized_certs.append(validated_pem)

    if verify_whitelist and fname in ("DoD_Roots.pem", "DoW_Roots.pem"):
        if set(seen_der_hashes) != root_allowed_ders:
            _log(f"Security: Root bundle '{fname}' is missing one or more required DoD Root CAs")
            return None

    if not reserialized_certs:
        return None

    return b"\n".join(reserialized_certs) + b"\n"


def verify_file_matches_manifest(filepath: str, fname: Optional[str] = None) -> bool:
    """Return True only if filepath is a regular file whose content matches Sentinel's DoD CA manifest."""
    try:
        from core.rust_bridge import verify_ca_file_manifest_rust
        rust_match = verify_ca_file_manifest_rust(filepath, fname)
        if rust_match is not None:
            return rust_match
    except Exception:
        pass

    if not os.path.isfile(filepath) or os.path.islink(filepath):
        return False
    target_name = fname or os.path.basename(filepath)
    if target_name not in ALLOWED_CERT_FILENAMES:
        return False
    try:
        with open(filepath, "rb") as f:
            raw = f.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            return False
        raw_sha256 = hashlib.sha256(raw).hexdigest().lower()
        if raw_sha256 == DOD_CA_FINGERPRINTS.get(target_name):
            return True
        if target_name in DOD_CA_DER_FINGERPRINTS:
            pem_bodies = PEM_CERT_PATTERN.findall(raw)
            if len(pem_bodies) == 1:
                der = extract_der_from_pem_body(pem_bodies[0])
                if der and hashlib.sha256(der).hexdigest().lower() == DOD_CA_DER_FINGERPRINTS[target_name]:
                    return True
    except Exception:
        return False
    return False


def check_bundled_ca_expirations(certs_dir: str, warn_days: int = 180) -> Dict[str, List[str]]:
    """Inspect bundled DoD certificates and return lists of valid, expiring_soon, and expired CAs."""
    try:
        from core.rust_bridge import check_ca_bundle_expirations_rust
        rust_exp = check_ca_bundle_expirations_rust(certs_dir, warn_days)
        if rust_exp is not None:
            valid, expiring, expired = rust_exp
            return {"valid": valid, "expiring_soon": expiring, "expired": expired}
    except Exception:
        pass

    result: Dict[str, List[str]] = {"valid": [], "expiring_soon": [], "expired": []}
    all_cas_dir = os.path.join(certs_dir, "all_cas")
    if not os.path.isdir(all_cas_dir):
        return result

    try:
        from cryptography import x509

        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=warn_days)
        for fname in sorted(os.listdir(all_cas_dir)):
            if not fname.endswith(".crt"):
                continue
            fpath = os.path.join(all_cas_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                not_after = getattr(cert, "not_valid_after_utc", None)
                if not_after is None:
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                date_str = not_after.strftime("%Y-%m-%d")
                if not_after <= now:
                    result["expired"].append(f"{fname} ({date_str})")
                elif not_after <= threshold:
                    result["expiring_soon"].append(f"{fname} ({date_str})")
                else:
                    result["valid"].append(f"{fname} ({date_str})")
            except Exception:
                continue
    except Exception:
        pass
    return result


def get_certs_dir(override: Optional[str] = None) -> str:
    """Discover certificates directory across system, local, and user installs."""
    system_store = "/usr/share/sentinel/certificates"
    if os.path.isdir(system_store) and os.path.isdir(os.path.join(system_store, "all_cas")):
        try:
            if os.stat(system_store).st_uid == 0:
                return system_store
        except Exception:
            pass

    if override and os.path.isdir(override) and os.path.isdir(os.path.join(override, "all_cas")):
        if not any(c in override for c in ("\r", "\n", "\0")):
            return os.path.abspath(override)

    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        "/usr/share/sentinel/certificates",
        "/usr/libexec/sentinel/certificates",
        os.path.join(script_dir, "certificates"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "certificates"),
    ]

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            u_home = pwd.getpwnam(sudo_user).pw_dir
            candidates.append(os.path.join(u_home, ".local", "share", "sentinel", "certificates"))
            candidates.append(os.path.join(u_home, ".local", "share", "sentinel_cac_manager", "certificates"))
        except Exception:
            pass

    for c in candidates:
        if os.path.isdir(c) and os.path.isdir(os.path.join(c, "all_cas")):
            return c

    return os.path.join(script_dir, "certificates")
