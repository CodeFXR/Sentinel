"""Certificate inspection used by both the app and the bundle build tool.

Deliberately dependency-free: standard library plus the `openssl` binary that
every supported distribution's package list already installs. Nothing here
imports Textual or asyncio, which keeps it usable from a maintenance script as
well as from the running application, without the two drifting apart.

The one rule this module exists to enforce: only self-signed certificates may
enter a trust-anchor directory. An issuing CA installed as a root is promoted
to a root of trust, which is a materially larger trust surface than intended.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def split_pem(text: str) -> list[str]:
    """Return each certificate block in a PEM file, in file order."""
    return PEM_CERT_RE.findall(text)


def _field(cert_path: str, flag: str, prefix: str) -> str | None:
    """Read one X.509 name field. `flag` is the openssl argument, `prefix` the
    expected start of the output line (openssl prints "subject=...", not
    "-subject")."""
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", flag],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def subject(pem: str, workdir: str, name: str) -> str | None:
    path = _materialise(pem, workdir, name)
    try:
        return _field(path, "-subject", "subject=")
    finally:
        _discard(path)


def common_name(pem: str, workdir: str, name: str) -> str:
    subject_dn = subject(pem, workdir, name) or ""
    match = re.search(r"CN\s*=\s*([^,]+)", subject_dn)
    return match.group(1).strip() if match else "(no CN)"


def is_self_signed(pem: str, workdir: str, name: str) -> bool:
    """True when subject == issuer and the signature verifies under its own key.

    Subject/issuer equality alone is not sufficient. A self-issued certificate
    signs itself but is issued by a different entity, and a cross-certificate
    can share a subject with a genuine root. Verifying the signature with the
    certificate's own public key is the check that actually means "trust
    anchor".
    """
    path = _materialise(pem, workdir, name)
    try:
        subject_dn = _field(path, "-subject", "subject=")
        issuer_dn = _field(path, "-issuer", "issuer=")
        if not subject_dn or subject_dn != issuer_dn:
            return False
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", path, path],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    finally:
        _discard(path)


def is_expired(pem: str, workdir: str, name: str) -> bool:
    """True when the certificate is outside its validity window."""
    path = _materialise(pem, workdir, name)
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-checkend", "0"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode != 0
    finally:
        _discard(path)


def fingerprint(pem: str) -> str:
    import hashlib
    return hashlib.sha256(pem.strip().encode()).hexdigest()


def verify_roots_only(text: str) -> tuple[list[str], list[str]]:
    """Audit a PEM bundle for trust-anchor eligibility.

    Returns (good_common_names, problems). A bundle is safe to install only when
    `problems` is empty. Requires openssl; returns a problem rather than raising
    when openssl is missing, because failing closed is the correct behaviour for
    a trust-anchor install.
    """
    pems = split_pem(text)
    if not pems:
        return [], ["bundle contains no certificates"]

    if not openssl_available():
        return [], [
            "openssl is not installed, so the bundle cannot be verified; "
            "refusing to install unverified trust anchors"
        ]

    good: list[str] = []
    problems: list[str] = []
    seen: set[str] = set()

    with tempfile.TemporaryDirectory() as workdir:
        for index, pem in enumerate(pems):
            cn = common_name(pem, workdir, f"c{index}")
            digest = fingerprint(pem)
            if digest in seen:
                problems.append(f"duplicate certificate: {cn}")
                continue
            seen.add(digest)

            if not is_self_signed(pem, workdir, f"c{index}"):
                problems.append(
                    f"not self-signed, would become a root of trust if installed: {cn}"
                )
                continue
            if is_expired(pem, workdir, f"c{index}"):
                problems.append(f"expired: {cn}")
                continue
            good.append(cn)

    return good, problems


def _materialise(pem: str, workdir: str, name: str) -> str:
    path = f"{workdir.rstrip('/')}/{name}.pem"
    with open(path, "w", encoding="ascii") as fh:
        fh.write(pem.rstrip() + "\n")
    return path


def _discard(path: str) -> None:
    try:
        import os
        os.unlink(path)
    except OSError:
        pass
