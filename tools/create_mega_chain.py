"""Build DoD_Mega_Chain.pem from the bundled PKCS#7 certificate bundles.

Maintenance-only. Run manually when DoD publishes a new bundle version, then
commit the regenerated DoD_Mega_Chain.pem. Never invoked at runtime.

Every input is verified against the SHA-256 manifest that ships inside each
bundle's `.sha256` file before it is parsed. The manifests are binary
containers with the manifest embedded as ASCII text, and the hex digests are
UPPERCASE in the v5.17/v5.6 bundles and lowercase in the v5.12 ECA bundle, so
the pattern is case-insensitive and the digests are compared lowercased.
"""

import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE_DIRS = (
    "certificates_pkcs7_v5_12_eca",
    "Certificates_PKCS7_v5_17_WCF",
    "Certificates_PKCS7_v5.6_DoD",
)
OUTPUT = os.path.join(ROOT, "DoD_Mega_Chain.pem")
DIGEST_RE = re.compile(rb"([0-9a-fA-F]{64})\s+(\S+)")


def _manifest_entries(path):
    with open(path, "rb") as fh:
        return [
            (want.decode().lower(), name.decode())
            for want, name in DIGEST_RE.findall(fh.read())
        ]


def verify_bundle(name):
    """Verify every file covered by the bundle manifest. Returns True if intact."""
    directory = os.path.join(ROOT, name)
    manifests = [f for f in os.listdir(directory) if f.endswith(".sha256")]
    if not manifests:
        print(f"  [FAIL] {name}: no .sha256 manifest, refusing to trust it")
        return False

    ok = True
    for want, filename in _manifest_entries(os.path.join(directory, manifests[0])):
        target = os.path.join(directory, filename)
        if not os.path.exists(target):
            print(f"  [FAIL] {name}/{filename}: listed in manifest but missing")
            ok = False
            continue
        with open(target, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        if got != want:
            print(f"  [FAIL] {name}/{filename}: SHA-256 mismatch")
            ok = False
    print(f"  [{'OK' if ok else 'FAIL'}] {name}: manifest checked")
    return ok


def extract_p7b(path):
    """Return PEM text from a PKCS#7 bundle, trying PEM then DER framing."""
    for extra in ([], ["-inform", "DER"]):
        result = subprocess.run(
            ["openssl", "pkcs7", "-in", path, *extra, "-print_certs"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and "BEGIN CERTIFICATE" in result.stdout:
            return result.stdout
    return None


def main():
    print("Verifying bundled certificate material...")
    if not all(verify_bundle(name) for name in BUNDLE_DIRS):
        print("\nABORT: trust material failed verification. Not building a chain.")
        return 1

    print(f"\nBuilding {OUTPUT}")
    written = failed = 0
    with open(OUTPUT, "w") as out:
        for name in BUNDLE_DIRS:
            directory = os.path.join(ROOT, name)
            for filename in sorted(os.listdir(directory)):
                if not filename.endswith(".p7b"):
                    continue
                path = os.path.join(directory, filename)
                pem = extract_p7b(path)
                if pem is None:
                    print(f"  [SKIP] {name}/{filename}: not parseable as PKCS#7")
                    failed += 1
                    continue
                out.write(pem)
                written += pem.count("BEGIN CERTIFICATE")

    print(f"\nWrote {written} certificates ({failed} files skipped) to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
