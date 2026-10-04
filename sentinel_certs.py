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


def not_after(pem: str, workdir: str, name: str) -> str | None:
    """The certificate's expiry, as an ISO-8601 UTC timestamp.

    Read rather than parsed by hand, because openssl's `notAfter` format has
    changed between versions and a hand-rolled parser is a second thing that can
    be subtly wrong. Returns None when openssl cannot answer.
    """
    path = _materialise(pem, workdir, name)
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-enddate"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if line.startswith("notAfter="):
                return _to_iso(line.split("=", 1)[1].strip())
        return None
    finally:
        _discard(path)


def _to_iso(openssl_date: str) -> str | None:
    """`Dec 30 16:13:04 2029 GMT` -> `2029-12-30T16:13:04Z`.

    Deliberately not using `datetime.strptime` against a guessed format: openssl
    emits `notAfter=Dec 30 16:13:04 2029 GMT` on every platform Sentinel
    supports, and returning the original string unchanged if the shape is
    unfamiliar is safer than raising on a trust-anchor path.
    """
    match = re.match(
        r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})",
        openssl_date,
    )
    if not match:
        return openssl_date
    months = {
        "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
        "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
    }
    month, day, hour, minute, second, year = match.groups()
    if month not in months:
        return openssl_date
    return (f"{year}-{months[month]}-{int(day):02d}"
            f"T{hour}:{minute}:{second}Z")


def sha256_fingerprint(pem: str) -> str:
    """The X.509 certificate's own SHA-256, as openssl reports it.

    Distinct from `fingerprint`, which hashes the PEM text. The text hash changes
    if the file is rewrapped or re-indented; this one is a property of the
    certificate, so it is what a manifest should record and what a person can
    compare against a certificate viewer.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem.rstrip() + "\n")
        path = fh.name
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return ""
        for line in result.stdout.splitlines():
            if "=" in line:
                return line.split("=", 1)[1].strip()
        return ""
    finally:
        _discard(path)


# --- manifest -----------------------------------------------------------------
# The manifest exists to answer one question offline: is the bundle in front of
# me the one Sentinel shipped, and is it the current one?
#
# Without it, "is my copy up to date?" has no answer that does not involve a
# network round trip to a DoD site, which is exactly the manual step this tool
# exists to remove. With it, the answer is a local file comparison.
#
# Format is one certificate per line, space separated, in bundle order:
#
#     <sha256-of-PEM>  <notAfter ISO-8601>  <X.509 SHA-256 fingerprint>  <CN>
#
# The order matters and is part of the contract: the bundle is generated in a
# fixed order from the source material, so a reordered bundle is a changed
# bundle even though it contains the same certificates. Comment lines start with
# `#` and carry the provenance a reader needs in order to trust the rest.

MANIFEST_NAME = "DoD_Roots.manifest"

MANIFEST_HEADER = """\
# Sentinel DoD trust anchors -- manifest for DoD_Roots.pem
#
# One line per certificate, in bundle order:
#   <sha256 of the PEM text>  <expiry, ISO-8601 UTC>  <X.509 SHA-256>  <common name>
#
# `sentinel verify-bundle` checks the bundle against this file. It needs no
# network access, so "are my certificates current" is answerable on a machine
# with no internet -- which is the normal case on a unit.
#
# Provenance: the roots are extracted from the DoD PKI bundles published at
#   https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/
# and every extracted certificate must be self-signed before it is included, so
# this file can never contain an issuing CA promoted to a root of trust.
#
# To refresh: run tools/refresh_roots.py, which rebuilds DoD_Roots.pem from the
# source bundles in this repository and rewrites this manifest alongside it.
"""


def render_manifest(text: str, workdir: str | None = None) -> str:
    """Build the manifest text for a PEM bundle."""
    import hashlib

    owned = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="sentinel-manifest-")
    lines = [MANIFEST_HEADER]
    try:
        for index, pem in enumerate(split_pem(text)):
            lines.append(
                f"{hashlib.sha256(pem.strip().encode()).hexdigest()}  "
                f"{not_after(pem, workdir, f'm{index}') or 'unknown'}  "
                f"{sha256_fingerprint(pem)}  "
                f"{common_name(pem, workdir, f'm{index}')}"
            )
    finally:
        if owned:
            import shutil as _shutil
            _shutil.rmtree(workdir, ignore_errors=True)
    return "\n".join(lines) + "\n"


def parse_manifest(text: str) -> list[dict]:
    """Read a manifest into records. Comment and blank lines are ignored.

    A line with too few fields to be a record is skipped rather than raising: a
    manifest is a convenience for verification, and refusing to check the bundle
    because one line is corrupt would be a worse outcome than checking the rest.
    """
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        records.append({
            "pem_sha256": parts[0],
            "not_after": parts[1],
            "fingerprint": parts[2],
            "common_name": parts[3].strip(),
        })
    return records


def compare_to_manifest(bundle_text: str, manifest_text: str) -> list[str]:
    """Differences between a PEM bundle and its manifest. Empty means identical.

    Reports four kinds of difference, because they need different responses:

    * a certificate present in the bundle but not the manifest, or the reverse --
      the bundle has been changed;
    * a certificate whose X.509 fingerprint differs under the same name -- a
      root was *replaced*, which is the case that matters most and the one a
      count comparison would miss;
    * the same certificates in a different order, which means the bundle was
      produced by something other than the recorded build;
    * a count mismatch on its own.
    """
    import hashlib

    problems: list[str] = []
    if not openssl_available():
        return ["openssl is not installed, so the bundle cannot be checked"]

    bundle = split_pem(bundle_text)
    expected = parse_manifest(manifest_text)

    if not expected:
        return ["the manifest contains no certificate records, so it cannot be used"]

    with tempfile.TemporaryDirectory() as workdir:
        actual = []
        for index, pem in enumerate(bundle):
            actual.append({
                "pem_sha256": hashlib.sha256(
                    pem.strip().encode()).hexdigest(),
                "not_after": not_after(pem, workdir, f"b{index}") or "unknown",
                "fingerprint": sha256_fingerprint(pem),
                "common_name": common_name(pem, workdir, f"b{index}"),
            })

        by_name = {r["common_name"]: r for r in actual}
        for record in expected:
            found = by_name.get(record["common_name"])
            if found is None:
                problems.append(
                    f"missing from the bundle: {record['common_name']} "
                    f"(expected {record['fingerprint']})"
                )
                continue
            if found["fingerprint"] != record["fingerprint"]:
                problems.append(
                    f"replaced: {record['common_name']} is "
                    f"{found['fingerprint']} but the manifest records "
                    f"{record['fingerprint']}"
                )
            elif found["pem_sha256"] != record["pem_sha256"]:
                problems.append(
                    f"same certificate, different encoding: {record['common_name']}"
                )

        expected_names = {r["common_name"] for r in expected}
        for record in actual:
            if record["common_name"] not in expected_names:
                problems.append(
                    f"not in the manifest: {record['common_name']} "
                    f"({record['fingerprint']})"
                )

    # Order is checked only once every certificate has been accounted for.
    # Reporting both "replaced" and "reordered" for one substitution is noise
    # that buries the finding, so a bundle already known to differ is described
    # once, in the most specific terms available.
    if not problems and len(bundle) == len(expected):
        actual_order = [r["common_name"] for r in actual]
        expected_order = [r["common_name"] for r in expected]
        if actual_order != expected_order:
            problems.append(
                "the same certificates in a different order: the bundle was not "
                f"produced by the recorded build (expected "
                f"{', '.join(expected_order)}; found {', '.join(actual_order)})"
            )

    if len(bundle) != len(expected) and not problems:
        problems.append(
            f"the bundle has {len(bundle)} certificates, the manifest {len(expected)}"
        )
    return problems


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
