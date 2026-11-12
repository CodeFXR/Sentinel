#!/usr/bin/env python3
"""Privileged helper script for Sentinel.
Runs elevated tasks (system certs, systemctl, opensc.conf, enterprise policies)
under a single pkexec / sudo invocation so the user only authenticates ONCE.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Optional

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_DIR = os.path.dirname(_THIS_DIR) if os.path.basename(_THIS_DIR) == "core" else _THIS_DIR
for _p in (SCRIPT_DIR, _THIS_DIR, os.path.join(_THIS_DIR, "core")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from core.ca_manifest import (
        DOD_CA_FINGERPRINTS,
        DOD_CA_DER_FINGERPRINTS,
        DOD_ROOT_FILES,
        SAFE_CERT_FILENAME,
        extract_der_from_pem_body,
        get_certs_dir,
        validate_and_reserialize_cert,
        verify_file_matches_manifest,
    )
    from core.ownership import (
        get_file_ownership_entry,
        get_firefox_policy_snapshot,
        record_firefox_policy_snapshot,
        record_installed_file,
        remove_file_ownership_entry,
        remove_firefox_policy_snapshot,
    )
except ImportError:
    from ca_manifest import (  # type: ignore
        DOD_CA_FINGERPRINTS,
        DOD_CA_DER_FINGERPRINTS,
        DOD_ROOT_FILES,
        SAFE_CERT_FILENAME,
        extract_der_from_pem_body,
        get_certs_dir,
        validate_and_reserialize_cert,
        verify_file_matches_manifest,
    )
    from ownership import (  # type: ignore
        get_file_ownership_entry,
        get_firefox_policy_snapshot,
        record_firefox_policy_snapshot,
        record_installed_file,
        remove_file_ownership_entry,
        remove_firefox_policy_snapshot,
    )

SAFE_MODULE_PATH = re.compile(r"^/[a-zA-Z0-9_./\-]+\.so(\.[0-9]+)*$")


def find_default_opensc_module() -> str:
    """Discover the system's opensc-pkcs11.so path dynamically."""
    patterns = [
        "/usr/lib64/opensc-pkcs11.so*",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so*",
        "/usr/lib/opensc-pkcs11.so*",
        "/usr/lib/pkcs11/opensc-pkcs11.so*",
        "/usr/lib64/pkcs11/opensc-pkcs11.so*",
        "/usr/lib/*-linux-gnu/opensc-pkcs11.so*",
    ]
    for pattern in patterns:
        for m in sorted(glob.glob(pattern)):
            if os.path.isfile(m):
                return m
    return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"


def validate_pkcs11_module_path(module_path: Optional[str]) -> Optional[str]:
    """Validate that a PKCS#11 module path is safe, normalized, under /usr/lib* or /lib*, exists, is root-owned, and is not world-writable."""
    if not module_path:
        module_path = find_default_opensc_module()
    try:
        from core.rust_bridge import validate_pkcs11_module_path_rust
        rust_res = validate_pkcs11_module_path_rust(module_path)
        if rust_res is not None:
            canonical, err_msg = rust_res
            if err_msg:
                log(f"Security: {err_msg}")
                return None
            return canonical
    except Exception:
        pass
    if any(c in module_path for c in ("\r", "\n", "\0", '"', "'", ";", "`", "$")):
        log(f"Security: Rejected PKCS#11 module path containing control/meta characters: {module_path!r}")
        return None
    if ".." in module_path.split("/"):
        log(f"Security: Rejected PKCS#11 module path containing '..' traversal: {module_path!r}")
        return None
    if not SAFE_MODULE_PATH.match(module_path) or not module_path.startswith(("/usr/lib", "/lib", "/usr/local/lib")):
        log(f"Security: Rejected PKCS#11 module path failing format/prefix validation: {module_path!r}")
        return None
    real_path = os.path.realpath(module_path)
    if not real_path.startswith(("/usr/lib", "/lib", "/usr/local/lib")) or not os.path.isfile(real_path):
        log(f"Security: Rejected non-existent or out-of-prefix PKCS#11 module path: {module_path!r}")
        return None
    try:
        st = os.stat(real_path)
        if st.st_uid != 0:
            log(f"Security: Rejected non-root-owned PKCS#11 module: {real_path}")
            return None
        if st.st_mode & stat.S_IWOTH:
            log(f"Security: Rejected world-writable PKCS#11 module: {real_path}")
            return None
    except OSError:
        return None
    return real_path


CERTS_DIR = get_certs_dir()
ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
if not os.path.isfile(FULL_CHAIN_PEM):
    FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
if not os.path.isfile(FULL_CHAIN_CRT):
    FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

OPENSC_DIRECTIVE = "card_drivers = piv-II, cac, cac1;"


def log(msg):
    print(f"[SENTINEL-ROOT] {msg}", flush=True)


def is_opensc_config_optimized(content: str) -> bool:
    """Return True if an uncommented card_drivers line in opensc.conf includes piv-II."""
    try:
        from core.rust_bridge import is_opensc_config_optimized_rust
        rust_opt = is_opensc_config_optimized_rust(content)
        if rust_opt is not None:
            return rust_opt
    except Exception:
        pass
    for line in content.splitlines():
        uncommented = line.split("#", 1)[0].strip()
        if "card_drivers" in uncommented and ("piv-II" in uncommented or "PIV-II" in uncommented):
            return True
    return False


def reset_smartcard_atr():
    """Trigger a warm card reset to avoid requiring physical card re-insertion after pcscd restart."""
    tool = shutil.which("opensc-tool")
    if tool:
        try:
            check = subprocess.run([tool, "-l"], capture_output=True, text=True, timeout=3)
            if check.returncode == 0 and "Reader" in check.stdout:
                res = subprocess.run([tool, "--reset", "warm"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    log("Executed warm ATR reset on inserted smart card.")
        except Exception as e:
            log(f"Warm ATR reset note: {e}")


def ensure_system_helper():
    """Ensure privileged_helper.py and core modules are installed in root-owned /usr/libexec/sentinel/ (0755 root:root)."""
    try:
        sys_dir = "/usr/libexec/sentinel"
        sys_core_dir = os.path.join(sys_dir, "core")
        os.makedirs(sys_core_dir, exist_ok=True)
        sys_helper = os.path.join(sys_dir, "privileged_helper.py")
        current_script = os.path.abspath(__file__)
        if current_script != sys_helper and os.path.isfile(current_script):
            with tempfile.NamedTemporaryFile(dir=sys_dir, delete=False) as f_tmp:
                temp_dst = f_tmp.name
                with open(current_script, "rb") as f_src:
                    f_tmp.write(f_src.read())
            os.chmod(temp_dst, 0o755)
            try:
                os.chown(temp_dst, 0, 0)
            except Exception:
                pass
            os.replace(temp_dst, sys_helper)

        src_core_dir = os.path.dirname(current_script) if os.path.basename(os.path.dirname(current_script)) == "core" else os.path.join(os.path.dirname(current_script), "core")
        if os.path.isdir(src_core_dir):
            for mod_name in ["ca_manifest.py", "ownership.py", "rust_bridge.py", "__init__.py", "libsentinel_core.so"]:
                src_mod = os.path.join(src_core_dir, mod_name)
                if os.path.isfile(src_mod):
                    dst_mod = os.path.join(sys_core_dir, mod_name)
                    with tempfile.NamedTemporaryFile(dir=sys_core_dir, delete=False) as f_tmp:
                        tmp_m = f_tmp.name
                        with open(src_mod, "rb") as f_s:
                            f_tmp.write(f_s.read())
                    os.chmod(tmp_m, 0o755 if mod_name.endswith(".so") else 0o644)
                    try:
                        os.chown(tmp_m, 0, 0)
                    except Exception:
                        pass
                    os.replace(tmp_m, dst_mod)
        log("Synchronized protected privileged helper and core modules to /usr/libexec/sentinel/")
    except Exception as e:
        log(f"System helper sync note: {e}")


def enable_pcscd() -> bool:
    log("Enabling and starting pcscd daemon...")
    res = subprocess.run(["systemctl", "enable", "--now", "pcscd.socket", "pcscd"], capture_output=True, text=True)
    if res.returncode == 0:
        log("pcscd service and socket enabled and started.")
        reset_smartcard_atr()
        return True
    else:
        log(f"pcscd service warning: {res.stderr.strip()}")
        reset_smartcard_atr()
        return False


def fix_opensc_hang() -> bool:
    log("Configuring OpenSC reader compatibility...")
    candidates = ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]
    target_conf = None
    for c in candidates:
        if os.path.isfile(c) or os.path.isdir(os.path.dirname(c)):
            target_conf = c
            break
    if not target_conf:
        target_conf = "/etc/opensc.conf"

    original = ""
    if os.path.isfile(target_conf):
        try:
            with open(target_conf, "r", encoding="utf-8", errors="replace") as f:
                original = f.read()
        except OSError:
            pass

    # Check if card_drivers is already set in active (uncommented) configuration
    if is_opensc_config_optimized(original):
        log(f"OpenSC already optimized in {target_conf}")
        return True

    # Backup if exists (prevent symlink overwrite attacks)
    bak = f"{target_conf}.sentinel-bak"
    if os.path.isfile(target_conf) and not os.path.exists(bak) and not os.path.islink(bak):
        try:
            fd_bak = os.open(bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with open(fd_bak, "w", encoding="utf-8") as f_bak:
                f_bak.write(original)
            log(f"Backed up original configuration to {bak}")
        except Exception as e:
            log(f"Backup notice: {e}")

    # OpenSC requires card_drivers to be inside an app default { ... } block and end with a semicolon
    if "app default {" in original:
        idx = original.find("app default {") + len("app default {")
        updated = (
            original[:idx]
            + f"\n\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.\n\t{OPENSC_DIRECTIVE}\n"
            + original[idx:]
        )
    elif original.strip():
        updated = original.rstrip() + f"\n\napp default {{\n\t# Added by Sentinel.\n\t{OPENSC_DIRECTIVE}\n}}\n"
    else:
        updated = (
            "app default {\n"
            "\t# Added by Sentinel.\n"
            "\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.\n"
            f"\t{OPENSC_DIRECTIVE}\n"
            "}\n"
        )

    try:
        conf_dir = os.path.dirname(target_conf)
        os.makedirs(conf_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=conf_dir, delete=False, encoding="utf-8") as f_tmp:
            tmp_name = f_tmp.name
            f_tmp.write(updated)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target_conf)
        log(f"Optimized {target_conf} with CAC/PIV drivers.")
        return True
    except Exception as e:
        log(f"Failed to update {target_conf}: {e}")
        return False


_extract_der_from_pem_body = extract_der_from_pem_body
_file_content_matches_sentinel_manifest = verify_file_matches_manifest
_validate_and_reserialize_cert = validate_and_reserialize_cert


def _remove_or_restore_sentinel_cert_file(filepath: str) -> bool:
    """Remove filepath only if Sentinel installed it and it did not exist before,
    restoring any pre-Sentinel file or symlink backup."""
    bak_path = f"{filepath}.pre-sentinel-bak"
    sym_path = f"{filepath}.pre-sentinel-symlink"

    if not os.path.exists(filepath) and not os.path.islink(filepath):
        remove_file_ownership_entry(filepath)
        return False

    entry = get_file_ownership_entry(filepath)
    existed_before = False
    was_symlink = False
    symlink_target = None
    if entry:
        existed_before = bool(entry.get("existed_before", False))
        was_symlink = bool(entry.get("was_symlink", False))
        symlink_target = entry.get("symlink_target")

    if os.path.islink(filepath):
        if not entry and not os.path.exists(sym_path):
            log(f"Preserving untracked administrator symlink: {filepath}")
            return False
        if was_symlink and symlink_target:
            remove_file_ownership_entry(filepath)
            return True

    if not _file_content_matches_sentinel_manifest(filepath):
        log(f"Preserving administrator/non-Sentinel file: {filepath}")
        remove_file_ownership_entry(filepath)
        return False

    if existed_before:
        if was_symlink:
            target_to_restore = symlink_target
            if not target_to_restore and os.path.isfile(sym_path):
                try:
                    with open(sym_path, "r", encoding="utf-8") as f_s:
                        target_to_restore = f_s.read().strip()
                except OSError:
                    pass
            if target_to_restore:
                try:
                    if os.path.exists(filepath) or os.path.islink(filepath):
                        os.remove(filepath)
                    os.symlink(target_to_restore, filepath)
                    log(f"Restored pre-existing administrator symlink from {sym_path} to {filepath}")
                    if os.path.isfile(sym_path):
                        os.remove(sym_path)
                    remove_file_ownership_entry(filepath)
                    return True
                except OSError as e:
                    log(f"Failed to restore symlink {filepath}: {e}")
                    return False
        elif os.path.isfile(bak_path) and not os.path.islink(bak_path):
            try:
                os.replace(bak_path, filepath)
                log(f"Restored pre-existing administrator file from {bak_path} to {filepath}")
                remove_file_ownership_entry(filepath)
                return True
            except OSError as e:
                log(f"Failed to restore backup {bak_path}: {e}")
                return False
        else:
            log(f"Preserving pre-existing DoD certificate present before installation: {filepath}")
            remove_file_ownership_entry(filepath)
            return False

    try:
        if os.path.isfile(bak_path) and not os.path.islink(bak_path):
            os.replace(bak_path, filepath)
            log(f"Restored pre-existing administrator file from {bak_path} to {filepath}")
        else:
            os.remove(filepath)
        if os.path.isfile(sym_path):
            try:
                os.remove(sym_path)
            except OSError:
                pass
        remove_file_ownership_entry(filepath)
        return True
    except OSError:
        return False


def _read_and_validate_cert(src_path: str, expected_dir: str, verify_whitelist: bool = True) -> Optional[bytes]:
    """Securely read and validate certificate bytes without following symlinks (CWE-59).

    Enforces source confinement, rejects symlinks, verifies regular file status,
    validates canonical X.509 DER SHA-256 fingerprint against authorized DoD manifest,
    validates X.509 CA constraints and validity, and returns canonical reserialized PEM bytes.
    """
    fname = os.path.basename(src_path)
    if not SAFE_CERT_FILENAME.match(fname):
        log(f"Security: Rejected certificate filename '{fname}' (invalid characters or extension)")
        return None

    if os.path.islink(src_path):
        log(f"Security: Rejected symlink in certificates directory: {src_path} (CWE-59)")
        return None

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(src_path, flags)
    except OSError as e:
        log(f"Security: Could not securely open {src_path} without following links: {e}")
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            log(f"Security: Rejected non-regular file: {src_path}")
            return None

        if st.st_size < 64 or st.st_size > 1048576:
            log(f"Security: Rejected cert {src_path} with unexpected size ({st.st_size} bytes)")
            return None

        try:
            real_src = os.path.realpath(f"/proc/self/fd/{fd}")
            real_expected = os.path.realpath(expected_dir)
            if os.path.commonpath([real_expected, real_src]) != real_expected:
                log(f"Security: Confinement violation: {src_path} resolved outside {expected_dir}")
                return None
        except Exception as e:
            log(f"Security: Confinement check error: {e}")
            return None

        raw_data = os.read(fd, st.st_size)
    finally:
        os.close(fd)

    if verify_whitelist and fname not in DOD_CA_FINGERPRINTS and fname not in DOD_CA_DER_FINGERPRINTS:
        log(f"Security: Rejected unauthorized certificate '{fname}' (not in authorized DoD manifest)")
        return None

    return _validate_and_reserialize_cert(raw_data, fname, verify_whitelist=verify_whitelist)


def _write_secure_cert(src_path: str, dst_path: str, expected_dir: str, verify_whitelist: bool = True) -> bool:
    """Read, validate, and write certificate bytes with explicit non-executable mode 0644,
    failing closed if pre-existing file/symlink backup cannot be created or verified."""
    data = _read_and_validate_cert(src_path, expected_dir, verify_whitelist=verify_whitelist)
    if not data:
        log(f"Skipping unvalidated or insecure certificate source: {src_path}")
        return False

    dst_dir = os.path.dirname(dst_path)
    os.makedirs(dst_dir, exist_ok=True)

    bak_path = f"{dst_path}.pre-sentinel-bak"
    sym_path = f"{dst_path}.pre-sentinel-symlink"

    existed_before = os.path.exists(dst_path) or os.path.islink(dst_path)
    was_symlink = os.path.islink(dst_path)
    symlink_target = None

    if existed_before:
        prior_entry = get_file_ownership_entry(dst_path)
        if prior_entry:
            existed_before = bool(prior_entry.get("existed_before", False))
            was_symlink = bool(prior_entry.get("was_symlink", False))
            symlink_target = prior_entry.get("symlink_target")
        elif was_symlink:
            try:
                symlink_target = os.readlink(dst_path)
                if not os.path.exists(sym_path):
                    with tempfile.NamedTemporaryFile(mode="w", dir=dst_dir, delete=False, encoding="utf-8") as f_sym:
                        tmp_sym = f_sym.name
                        f_sym.write(symlink_target)
                    os.chmod(tmp_sym, 0o600)
                    os.replace(tmp_sym, sym_path)
            except OSError as e:
                log(f"Security: Failed to preserve pre-existing symlink for {dst_path}: {e}")
                return False
        elif os.path.isfile(dst_path):
            if not _file_content_matches_sentinel_manifest(dst_path):
                needs_backup = not (os.path.isfile(bak_path) and not os.path.islink(bak_path))
                if needs_backup:
                    try:
                        with open(dst_path, "rb") as f_orig:
                            orig_bytes = f_orig.read()
                        orig_sha = hashlib.sha256(orig_bytes).hexdigest().lower()

                        fd_bak = os.open(bak_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                        with open(fd_bak, "wb") as f_bak:
                            f_bak.write(orig_bytes)

                        with open(bak_path, "rb") as f_verify:
                            verify_sha = hashlib.sha256(f_verify.read()).hexdigest().lower()
                        if verify_sha != orig_sha:
                            log(f"Security: Backup verification failed for {dst_path}")
                            try:
                                os.remove(bak_path)
                            except OSError:
                                pass
                            return False
                        log(f"Backed up pre-existing certificate to {bak_path}")
                    except OSError as e:
                        log(f"Security: Failed to create verified backup for {dst_path}: {e}")
                        return False

    temp_dst = None
    try:
        with tempfile.NamedTemporaryFile(dir=dst_dir, delete=False) as f_out:
            temp_dst = f_out.name
            f_out.write(data)
        os.chmod(temp_dst, 0o644)
        new_sha256 = hashlib.sha256(data).hexdigest().lower()
        os.replace(temp_dst, dst_path)

        record_installed_file(
            target_path=dst_path,
            installed_sha256=new_sha256,
            pre_existing_backup=bak_path if os.path.isfile(bak_path) else None,
            existed_before=existed_before,
            was_symlink=was_symlink,
            symlink_target=symlink_target,
        )
        return True
    except Exception as e:
        log(f"Error writing certificate to {dst_path}: {e}")
        if temp_dst and os.path.exists(temp_dst):
            try:
                os.remove(temp_dst)
            except Exception:
                pass
        return False


def deploy_shared_certificates(src_certs_dir: str, target_base: str = "/usr/share/sentinel/certificates") -> bool:
    """Deploy validated DoD certificates into target_base using _write_secure_cert.
    Ensures every certificate written matches the cryptographic DoD CA manifest."""
    log(f"Deploying manifest-verified DoD certificates to {target_base}...")
    if not os.path.isdir(src_certs_dir):
        log(f"Source certificates directory not found: {src_certs_dir}")
        return False

    all_ok = True
    subdirs = ["roots", "intermediates", "all_cas", ""]
    for sub in subdirs:
        s_dir = os.path.join(src_certs_dir, sub) if sub else src_certs_dir
        d_dir = os.path.join(target_base, sub) if sub else target_base
        if not os.path.isdir(s_dir):
            continue
        os.makedirs(d_dir, exist_ok=True)
        for fname in sorted(os.listdir(s_dir)):
            if fname.endswith((".crt", ".pem")) and os.path.isfile(os.path.join(s_dir, fname)):
                src_f = os.path.join(s_dir, fname)
                dst_f = os.path.join(d_dir, fname)
                if not _write_secure_cert(src_f, dst_f, s_dir, verify_whitelist=True):
                    all_ok = False
    return all_ok


def _clean_sentinel_owned_certs_in_dir(target_dir: str, keep_roots: bool = False) -> int:
    """Remove only certificates whose filename AND content match Sentinel's DoD manifest.

    Never deletes third-party or administrator-modified certificates in shared directories,
    even if they share a filename with a DoD certificate.
    """
    if not os.path.isdir(target_dir):
        return 0

    removed = 0
    known_sentinel_files = set(DOD_CA_FINGERPRINTS.keys()) | set(DOD_CA_DER_FINGERPRINTS.keys())
    root_set = set(DOD_ROOT_FILES)

    for existing in list(os.listdir(target_dir)):
        if keep_roots and existing in root_set:
            continue
        if existing in known_sentinel_files:
            p = os.path.join(target_dir, existing)
            if _remove_or_restore_sentinel_cert_file(p):
                removed += 1

    # Only remove directory if we are not keeping roots and the directory is now completely empty
    if not keep_roots:
        try:
            if not os.listdir(target_dir):
                os.rmdir(target_dir)
        except OSError:
            pass

    return removed


def install_system_certificates(distro_family: str) -> bool:
    """Install ONLY self-signed DoD Root CAs into the operating system trust store.

    Intermediate CAs are deliberately excluded from the system root store to enforce
    proper PKI trust anchor separation and prevent intermediate authority elevation.
    """
    log("Installing DoD Root CAs into system trust store (trust anchor separation enforced)...")
    roots_dir = os.path.join(CERTS_DIR, "roots")
    if not os.path.isdir(roots_dir):
        roots_dir = CERTS_DIR

    count = 0
    success = True
    if distro_family == "debian":
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        # Clean only Sentinel-known legacy files in dow or stale Sentinel intermediates in dod
        _clean_sentinel_owned_certs_in_dir("/usr/local/share/ca-certificates/dow", keep_roots=False)
        _clean_sentinel_owned_certs_in_dir(target_dir, keep_roots=True)

        # Deploy ALL 4 self-signed Root CAs; fail if any required root is missing or invalid
        for fname in DOD_ROOT_FILES:
            src = os.path.join(roots_dir, fname)
            if not os.path.isfile(src):
                src = os.path.join(CERTS_DIR, fname)
            if os.path.isfile(src):
                dst = os.path.join(target_dir, fname)
                if _write_secure_cert(src, dst, os.path.dirname(src)):
                    count += 1
                else:
                    success = False
            else:
                log(f"ERROR: Required root certificate missing: {fname}")
                success = False

        if count != len(DOD_ROOT_FILES):
            success = False

        log(f"Installed {count}/{len(DOD_ROOT_FILES)} DoD Root CAs into {target_dir}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Ran update-ca-certificates: {res.stdout.strip()}")
        if res.returncode != 0:
            success = False
    elif distro_family == "fedora":
        target_dir = "/etc/pki/ca-trust/source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Ran update-ca-trust successfully.")
        if res.returncode != 0:
            success = False
    elif distro_family == "arch":
        target_dir = "/etc/ca-certificates/trust-source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Ran trust extract-compat on Arch Linux.")
        if res.returncode != 0:
            success = False
    elif distro_family == "suse":
        target_dir = "/etc/pki/trust/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Ran update-ca-certificates on openSUSE.")
        if res.returncode != 0:
            success = False
    else:
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        for fname in DOD_ROOT_FILES:
            src = os.path.join(roots_dir, fname)
            if os.path.isfile(src):
                if _write_secure_cert(src, os.path.join(target_dir, fname), os.path.dirname(src)):
                    count += 1
                else:
                    success = False
            else:
                success = False
        if count != len(DOD_ROOT_FILES):
            success = False
        res = subprocess.run(["update-ca-certificates"], capture_output=True)
        log("Updated system ca certificates.")
        if res.returncode != 0:
            success = False

    return success


def merge_firefox_policy_file(target: str, module_path: str, cert_path: str) -> bool:
    """Safely deep-merge Sentinel CAC settings into a Firefox policies.json file,
    failing closed on malformed existing JSON or invalid structures, and detecting concurrent edits."""
    try:
        target_dir = os.path.dirname(target)
        os.makedirs(target_dir, exist_ok=True)

        if os.path.islink(target):
            log(f"Security: Rejected Firefox policy target because it is a symlink: {target}")
            return False

        existed_before = os.path.isfile(target)
        existing_data = {}
        pre_read_sha = None

        if existed_before:
            try:
                with open(target, "rb") as f_raw:
                    raw_bytes = f_raw.read()
                pre_read_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
                loaded = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(loaded, dict):
                    log(f"Security: Rejected {target}: root JSON element is not an object/dict")
                    return False
                existing_data = loaded
            except Exception as e:
                log(f"Security: Refusing to modify malformed Firefox policy in {target}: {e}")
                return False

        policies = existing_data.get("policies")
        if policies is not None and not isinstance(policies, dict):
            log(f"Security: Rejected {target}: 'policies' key is not a dict")
            return False
        if policies is None:
            policies = {}

        for k in ("Certificates", "SecurityDevices", "Preferences"):
            if k in policies and not isinstance(policies[k], dict):
                log(f"Security: Rejected {target}: '{k}' is not a dict")
                return False

        # Record pre-Sentinel snapshot (fail-closed if snapshot write fails when file existed)
        snap_path = f"{target}.pre-sentinel-snap"
        if not os.path.exists(snap_path) and not os.path.islink(snap_path):
            try:
                snap_payload = json.dumps(
                    {
                        "existed_before": existed_before,
                        "initial_sha256": pre_read_sha,
                        "prior_data": json.loads(json.dumps(existing_data)),
                    },
                    indent=2,
                )
                fd_snap = os.open(snap_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with open(fd_snap, "w", encoding="utf-8") as f_snap:
                    f_snap.write(snap_payload)
            except OSError as e:
                if existed_before:
                    log(f"Security: Failed to create snapshot for {target}: {e}")
                    return False

        record_firefox_policy_snapshot(
            policy_path=target,
            existed_before=existed_before,
            prior_policies_dict=policies if existed_before else None,
            initial_sha256=pre_read_sha,
        )

        # Deep merge Certificates
        certs_block = policies.get("Certificates", {})
        if not isinstance(certs_block, dict):
            certs_block = {}
        certs_block["ImportEnterpriseRoots"] = True
        install_list = certs_block.get("Install", [])
        if not isinstance(install_list, list):
            install_list = []
        if cert_path not in install_list:
            install_list.append(cert_path)
        certs_block["Install"] = install_list
        policies["Certificates"] = certs_block

        # Deep merge SecurityDevices
        sec_devices = policies.get("SecurityDevices", {})
        if not isinstance(sec_devices, dict):
            sec_devices = {}
        sec_devices["DoD CAC"] = module_path

        # Preserve pre-existing "DoW CAC" if it existed prior to Sentinel
        prior_snap = get_firefox_policy_snapshot(target)
        prior_p = prior_snap.get("prior_policies") if prior_snap else None
        prior_sec = prior_p.get("SecurityDevices") if isinstance(prior_p, dict) else None
        if not (prior_sec and "DoW CAC" in prior_sec):
            sec_devices.pop("DoW CAC", None)
        policies["SecurityDevices"] = sec_devices

        # Deep merge Preferences
        prefs = policies.get("Preferences", {})
        if not isinstance(prefs, dict):
            prefs = {}
        prefs["security.default_personal_cert"] = "Ask Every Time"
        prefs["security.enterprise_roots.enabled"] = True
        policies["Preferences"] = prefs

        existing_data["policies"] = policies
        content = json.dumps(existing_data, indent=2)

        temp_dst = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=target_dir, delete=False, encoding="utf-8") as f_out:
                temp_dst = f_out.name
                f_out.write(content)
            os.chmod(temp_dst, 0o644)

            # Compare-and-swap (CAS) check
            if existed_before and pre_read_sha:
                try:
                    with open(target, "rb") as f_cur:
                        cur_sha = hashlib.sha256(f_cur.read()).hexdigest().lower()
                    if cur_sha != pre_read_sha:
                        log(f"Security: Concurrent modification detected on {target}; aborting write")
                        try:
                            os.remove(temp_dst)
                        except OSError:
                            pass
                        return False
                except OSError as e:
                    log(f"Security: Failed CAS check on {target}: {e}")
                    try:
                        os.remove(temp_dst)
                    except OSError:
                        pass
                    return False

            os.replace(temp_dst, target)
            log(f"Configured Firefox policy in {target}")
            return True
        except Exception as e:
            if temp_dst and os.path.exists(temp_dst):
                try:
                    os.remove(temp_dst)
                except OSError:
                    pass
            log(f"Firefox policy write error for {target}: {e}")
            return False
    except Exception as e:
        log(f"Firefox policy note for {target}: {e}")
        return False


def revert_firefox_policy_file(target: str) -> bool:
    """Remove only Sentinel-managed keys from a Firefox policies.json file using pre-Sentinel ownership snapshot.

    Preserves all unrelated enterprise policies (Homepage, Proxy, Extensions,
    Telemetry, third-party SecurityDevices or Certificates) AND preserves any
    ImportEnterpriseRoots / Preferences keys that existed prior to Sentinel.
    """
    snap_path = f"{target}.pre-sentinel-snap"
    prior_policies = {}
    existed_before = False

    snap_entry = get_firefox_policy_snapshot(target)
    if snap_entry:
        existed_before = bool(snap_entry.get("existed_before", False))
        if isinstance(snap_entry.get("prior_policies"), dict):
            prior_policies = snap_entry["prior_policies"]
    elif os.path.isfile(snap_path) and not os.path.islink(snap_path):
        try:
            with open(snap_path, "r", encoding="utf-8") as f_snap:
                snap = json.load(f_snap)
            if isinstance(snap, dict) and snap.get("existed_before"):
                existed_before = True
                p_data = snap.get("prior_data")
                if isinstance(p_data, dict) and isinstance(p_data.get("policies"), dict):
                    prior_policies = p_data["policies"]
        except Exception:
            prior_policies = {}

    if not os.path.isfile(target):
        if os.path.isfile(snap_path):
            try:
                os.remove(snap_path)
            except OSError:
                pass
        remove_firefox_policy_snapshot(target)
        return True

    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return True

        policies = data.get("policies")
        if isinstance(policies, dict):
            prior_sec = prior_policies.get("SecurityDevices") if isinstance(prior_policies.get("SecurityDevices"), dict) else {}
            prior_certs = prior_policies.get("Certificates") if isinstance(prior_policies.get("Certificates"), dict) else {}
            prior_prefs = prior_policies.get("Preferences") if isinstance(prior_policies.get("Preferences"), dict) else {}
            prior_install = prior_certs.get("Install") if isinstance(prior_certs.get("Install"), list) else []

            # 1. Clean SecurityDevices (preserve if "DoD CAC" or "DoW CAC" was set prior to Sentinel)
            sec_devices = policies.get("SecurityDevices")
            if isinstance(sec_devices, dict):
                if "DoD CAC" in prior_sec:
                    sec_devices["DoD CAC"] = prior_sec["DoD CAC"]
                else:
                    sec_devices.pop("DoD CAC", None)
                if "DoW CAC" in prior_sec:
                    sec_devices["DoW CAC"] = prior_sec["DoW CAC"]
                else:
                    sec_devices.pop("DoW CAC", None)
                if not sec_devices and "SecurityDevices" not in prior_policies:
                    policies.pop("SecurityDevices", None)

            # 2. Clean Certificates (preserve any Install path or ImportEnterpriseRoots that existed before Sentinel)
            certs_block = policies.get("Certificates")
            if isinstance(certs_block, dict):
                install_list = certs_block.get("Install")
                if isinstance(install_list, list):
                    install_list = [
                        c
                        for c in install_list
                        if c in prior_install
                        or not any(
                            k in str(c)
                            for k in ("DoD_Full_Chain", "DoW_Full_Chain", "DoD_Roots", "DoW_Roots", "/usr/share/sentinel/")
                        )
                    ]
                    if install_list:
                        certs_block["Install"] = install_list
                    elif "Install" not in prior_certs:
                        certs_block.pop("Install", None)

                if (
                    "Install" not in certs_block
                    and certs_block.get("ImportEnterpriseRoots") is True
                    and "ImportEnterpriseRoots" not in prior_certs
                ):
                    if len(certs_block) == 1:
                        certs_block.pop("ImportEnterpriseRoots", None)

                if not certs_block and "Certificates" not in prior_policies:
                    policies.pop("Certificates", None)

            # 3. Clean Preferences added by Sentinel (restore/preserve if present in prior_prefs)
            prefs = policies.get("Preferences")
            if isinstance(prefs, dict):
                if "security.default_personal_cert" in prior_prefs:
                    prefs["security.default_personal_cert"] = prior_prefs["security.default_personal_cert"]
                elif prefs.get("security.default_personal_cert") == "Ask Every Time":
                    prefs.pop("security.default_personal_cert", None)

                if "security.enterprise_roots.enabled" in prior_prefs:
                    prefs["security.enterprise_roots.enabled"] = prior_prefs["security.enterprise_roots.enabled"]
                elif prefs.get("security.enterprise_roots.enabled") is True:
                    prefs.pop("security.enterprise_roots.enabled", None)

                if not prefs and "Preferences" not in prior_policies:
                    policies.pop("Preferences", None)

        other_top_keys = [k for k in data.keys() if k != "policies"]
        if not policies and not other_top_keys and not existed_before:
            os.remove(target)
            log(f"Removed empty Firefox policy file: {target}")
        else:
            target_dir = os.path.dirname(target)
            content = json.dumps(data, indent=2)
            with tempfile.NamedTemporaryFile(mode="w", dir=target_dir, delete=False, encoding="utf-8") as f_out:
                tmp_name = f_out.name
                f_out.write(content)
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, target)
            log(f"Cleaned Sentinel entries while preserving existing enterprise policies in {target}")

        if os.path.isfile(snap_path):
            try:
                os.remove(snap_path)
            except OSError:
                pass
        remove_firefox_policy_snapshot(target)
        return True
    except Exception as e:
        log(f"Note reverting policy {target}: {e}")
        return False


def install_firefox_policies(module_path: str, distro_family: str) -> bool:
    validated_mod = validate_pkcs11_module_path(module_path)
    if not validated_mod:
        return False

    log("Installing Firefox Enterprise Policies with safe deep merge...")
    cert_path = (
        "/usr/share/sentinel/certificates/DoD_Full_Chain.pem"
        if os.path.isfile("/usr/share/sentinel/certificates/DoD_Full_Chain.pem")
        else FULL_CHAIN_PEM
    )

    # Always write to /etc/firefox/policies/policies.json (standard non-package-clobbered location).
    # Only touch /usr/lib*/firefox/distribution or snap if their parent directory already exists,
    # avoiding creating stray /usr/lib64 directories on Debian/Ubuntu.
    policy_targets = ["/etc/firefox/policies/policies.json"]
    for optional_dir in [
        "/usr/lib/firefox/distribution",
        "/usr/lib64/firefox/distribution",
        "/var/snap/firefox/common/policies",
    ]:
        if os.path.isdir(optional_dir):
            policy_targets.append(os.path.join(optional_dir, "policies.json"))
    if os.path.isdir("/var/snap/firefox/common") and "/var/snap/firefox/common/policies/policies.json" not in policy_targets:
        policy_targets.append("/var/snap/firefox/common/policies/policies.json")

    any_ok = False
    for target in policy_targets:
        if merge_firefox_policy_file(target, validated_mod, cert_path):
            any_ok = True
    return any_ok


def install_p11_kit_module(module_path: str) -> bool:
    validated_mod = validate_pkcs11_module_path(module_path)
    if not validated_mod:
        return False

    log("Installing system-wide p11-kit module...")
    mod_dir = "/etc/pkcs11/modules"
    os.makedirs(mod_dir, exist_ok=True)
    # Use sentinel-opensc.module so we never shadow the distribution's own opensc.module
    mod_file = os.path.join(mod_dir, "sentinel-opensc.module")
    content = f"# Added by Sentinel\nmodule: {validated_mod}\n"
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=mod_dir, delete=False, encoding="utf-8") as f_out:
            tmp_name = f_out.name
            f_out.write(content)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, mod_file)
        log(f"Wrote system p11-kit config: {mod_file}")

        # Clean up legacy opensc.module only if it was written by Sentinel
        legacy_mod = os.path.join(mod_dir, "opensc.module")
        if os.path.isfile(legacy_mod):
            try:
                with open(legacy_mod, "r", encoding="utf-8", errors="replace") as f_leg:
                    c = f_leg.read()
                    if "Sentinel" in c or "Sentinel CAC Manager" in c:
                        os.remove(legacy_mod)
            except OSError:
                pass
        return True
    except Exception as e:
        log(f"p11-kit config note: {e}")
        return False


def connect_snap_firefox():
    if shutil.which("snap"):
        log("Connecting snap firefox:pcscd interface...")
        subprocess.run(["snap", "connect", "firefox:pcscd"], capture_output=True)


def install_system_packages(distro_family: str) -> bool:
    log("Checking and installing system packages via package manager...")
    pkg_ok = True
    if distro_family == "debian":
        pkgs = [
            "pcscd",
            "libpcsclite1",
            "pcsc-tools",
            "opensc",
            "libccid",
            "libnss3-tools",
            "openssl",
            "p11-kit",
            "p11-kit-modules",
            "python3-cryptography",
        ]
        log(f"Running apt-get install for {len(pkgs)} packages...")
        res = subprocess.run(["apt-get", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via apt.")
        else:
            log(f"apt-get error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "fedora":
        pkgs = [
            "pcsc-lite",
            "pcsc-tools",
            "opensc",
            "openssl",
            "nss-tools",
            "p11-kit",
            "ccid",
            "python3-cryptography",
        ]
        log(f"Running dnf install for {len(pkgs)} packages...")
        res = subprocess.run(["dnf", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via dnf.")
        else:
            log(f"dnf error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "arch":
        pkgs = ["pcsclite", "pcsc-tools", "opensc", "openssl", "nss", "p11-kit", "ccid", "python-cryptography"]
        log(f"Running pacman -S --needed for {len(pkgs)} packages...")
        res = subprocess.run(["pacman", "-S", "--needed", "--noconfirm"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via pacman.")
        else:
            log(f"pacman error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "suse":
        pkgs = [
            "pcsc-lite",
            "pcsc-tools",
            "opensc",
            "openssl",
            "mozilla-nss-tools",
            "p11-kit",
            "pcsc-ccid",
            "python3-cryptography",
        ]
        log(f"Running zypper install for {len(pkgs)} packages...")
        res = subprocess.run(["zypper", "--non-interactive", "install"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via zypper.")
        else:
            log(f"zypper error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False

    log("Reloading and triggering udev rules for smart card readers...")
    try:
        subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
        subprocess.run(["udevadm", "trigger", "--action=add", "--subsystem-match=usb"], capture_output=True)
    except Exception as e:
        log(f"udevadm trigger note: {e}")

    return pkg_ok


def cleanup_legacy_smartcard_logon(distro_family: str) -> bool:
    """Cleanly roll back any legacy v2.0.0 PAM/SSSD workstation logon configuration."""
    ok = True
    legacy_sssd_dropin = "/etc/sssd/conf.d/sentinel-smartcard.conf"
    had_sssd_dropin = os.path.isfile(legacy_sssd_dropin)
    if had_sssd_dropin:
        try:
            os.remove(legacy_sssd_dropin)
            log(f"Removed legacy {legacy_sssd_dropin}")
        except OSError:
            ok = False

    sssd_ca_db = "/etc/sssd/pki/sssd_auth_ca_db.pem"
    if os.path.isfile(sssd_ca_db):
        try:
            with open(sssd_ca_db, "rb") as f_db:
                raw = f_db.read(5 * 1024 * 1024)
            sha = hashlib.sha256(raw).hexdigest().lower()
            if sha in (DOD_CA_FINGERPRINTS.get("DoD_Roots.pem"), DOD_CA_FINGERPRINTS.get("DoD_Full_Chain.pem")):
                os.remove(sssd_ca_db)
                log(f"Removed Sentinel-installed {sssd_ca_db}")
        except OSError:
            pass

    # Only restore authselect backup on Fedora if Sentinel's legacy configuration was actually present
    if distro_family == "fedora" and had_sssd_dropin and shutil.which("authselect"):
        if os.path.isdir("/var/lib/authselect/backups/sentinel_backup"):
            res = subprocess.run(
                ["authselect", "backup-restore", "sentinel_backup"],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                log("Restored pre-Sentinel authselect profile from sentinel_backup")
            else:
                ok = False
    elif distro_family == "debian" and shutil.which("pam-auth-update"):
        if os.path.isfile("/usr/share/pam-configs/sss-smart-card-optional"):
            res = subprocess.run(
                ["pam-auth-update", "--package", "--remove", "sss-smart-card-optional"],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                ok = False

    return ok


def uninstall_system_configuration(distro_family: str) -> bool:
    """Revert Sentinel system configuration, remove Sentinel-installed DoD CAs, and restore policies."""
    log("Reverting Sentinel system configuration and removing trust...")
    all_ok = True

    # 1. Remove ONLY Sentinel-owned system CA certificates (never rmtree shared directories)
    if distro_family == "debian":
        for d in ["/usr/local/share/ca-certificates/dod", "/usr/local/share/ca-certificates/dow"]:
            if os.path.isdir(d):
                removed = _clean_sentinel_owned_certs_in_dir(d, keep_roots=False)
                log(f"Removed {removed} Sentinel-managed certificate(s) from {d}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Rebuilt system CA trust store: {res.stdout.strip()}")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "fedora":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/ca-trust/source/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-trust.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "arch":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/ca-certificates/trust-source/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with trust extract-compat.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "suse":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/trust/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-certificates.")
        if res.returncode != 0:
            all_ok = False

    # Remove ONLY manifest-verified certificate files in /usr/share/sentinel/certificates (never rmtree)
    for sub in [
        "/usr/share/sentinel/certificates/roots",
        "/usr/share/sentinel/certificates/intermediates",
        "/usr/share/sentinel/certificates/all_cas",
        "/usr/share/sentinel/certificates",
    ]:
        if os.path.isdir(sub):
            _clean_sentinel_owned_certs_in_dir(sub, keep_roots=False)
    if os.path.isdir("/usr/share/sentinel") and not os.listdir("/usr/share/sentinel"):
        try:
            os.rmdir("/usr/share/sentinel")
        except OSError:
            pass

    # 2. Revert Firefox enterprise policies non-destructively
    policy_targets = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/var/snap/firefox/common/policies/policies.json",
    ]
    for target in policy_targets:
        if not revert_firefox_policy_file(target):
            all_ok = False

    # 3. Revert system p11-kit module
    for p11_file in ["/etc/pkcs11/modules/sentinel-opensc.module", "/etc/pkcs11/modules/opensc.module"]:
        if os.path.isfile(p11_file):
            try:
                with open(p11_file, "r", encoding="utf-8", errors="replace") as f:
                    c = f.read()
                if "Sentinel" in c or os.path.basename(p11_file) == "sentinel-opensc.module":
                    os.remove(p11_file)
                    log(f"Removed system p11-kit module config: {p11_file}")
            except Exception:
                pass

    # 4. Revert OpenSC config if backup exists
    for conf_cand in ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]:
        bak = f"{conf_cand}.sentinel-bak"
        if os.path.isfile(bak):
            try:
                shutil.copy2(bak, conf_cand)
                os.remove(bak)
                log(f"Restored original OpenSC configuration from {bak}")
            except Exception as e:
                log(f"Note restoring OpenSC config: {e}")

    # 5. Clean up any legacy SSSD/PAM smart card logon state from earlier versions
    if not cleanup_legacy_smartcard_logon(distro_family):
        all_ok = False

    # 6. Remove Polkit policy and helper from /usr/libexec/sentinel
    polkit_policy = "/usr/share/polkit-1/actions/com.codefxr.sentinel.policy"
    if os.path.isfile(polkit_policy):
        try:
            os.remove(polkit_policy)
            log(f"Removed {polkit_policy}")
        except OSError:
            pass

    helper_path = "/usr/libexec/sentinel/privileged_helper.py"
    if os.path.isfile(helper_path):
        try:
            os.remove(helper_path)
            log("Removed /usr/libexec/sentinel/privileged_helper.py")
            sys_core = "/usr/libexec/sentinel/core"
            if os.path.isdir(sys_core):
                shutil.rmtree(sys_core)
            if os.path.isdir("/usr/libexec/sentinel") and not os.listdir("/usr/libexec/sentinel"):
                os.rmdir("/usr/libexec/sentinel")
        except Exception:
            pass

    log("System-level uninstallation and trust rollback complete.")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Sentinel Root Helper")
    parser.add_argument("--family", default="debian", help="distro family (debian/fedora/arch/suse)")
    parser.add_argument("--module", default=None, help="path to opensc module")
    parser.add_argument("--certs-dir", default=None, help="path to source certificates directory")
    parser.add_argument("--deploy-shared-certs", default=None, help="deploy validated cert bundle to /usr/share/sentinel/certificates")
    parser.add_argument("--all", action="store_true", help="run all root setup steps")
    parser.add_argument("--packages", action="store_true", help="install system packages")
    parser.add_argument("--certs", action="store_true", help="install system certs only")
    parser.add_argument("--service", action="store_true", help="enable pcscd only")
    parser.add_argument("--reader-fix", action="store_true", help="fix opensc.conf only")
    parser.add_argument("--policies", action="store_true", help="install policies only")
    parser.add_argument("--disable-logon", action="store_true", help="roll back legacy v2.0.0 PAM/SSSD logon")
    parser.add_argument("--sync-helper", action="store_true", help="install/sync helper into /usr/libexec/sentinel")
    parser.add_argument("--uninstall", action="store_true", help="revert system changes and remove DoD trust")

    args = parser.parse_args()

    if os.geteuid() != 0:
        log("ERROR: This helper must be run as root (via pkexec or sudo).")
        return 1

    if args.deploy_shared_certs:
        ok = deploy_shared_certificates(args.deploy_shared_certs)
        return 0 if ok else 1

    if args.uninstall:
        ok = uninstall_system_configuration(args.family)
        return 0 if ok else 1

    if args.disable_logon:
        ok = cleanup_legacy_smartcard_logon(args.family)
        return 0 if ok else 1

    global CERTS_DIR, ALL_CAS_DIR, FULL_CHAIN_PEM, FULL_CHAIN_CRT
    if args.certs_dir:
        CERTS_DIR = get_certs_dir(args.certs_dir)
        ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
        FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
        if not os.path.isfile(FULL_CHAIN_PEM):
            FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
        FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
        if not os.path.isfile(FULL_CHAIN_CRT):
            FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

    # Only sync system helper when explicitly requested during administrative install (SEC-02)
    if args.sync_helper:
        ensure_system_helper()

    pkgs_ok = True
    if args.packages or args.all:
        pkgs_ok = install_system_packages(args.family)

    svc_ok = True
    if args.all or args.service:
        svc_ok = enable_pcscd()

    reader_ok = True
    if args.all or args.reader_fix:
        reader_ok = fix_opensc_hang()

    certs_ok = True
    if args.all or args.certs:
        certs_ok = install_system_certificates(args.family)

    policies_ok = True
    if args.all or args.policies:
        mod_path = validate_pkcs11_module_path(args.module)
        if not mod_path:
            log("ERROR: Invalid PKCS#11 module path supplied.")
            return 3
        ff_ok = install_firefox_policies(mod_path, args.family)
        p11_ok = install_p11_kit_module(mod_path)
        policies_ok = ff_ok and p11_ok
        connect_snap_firefox()

    reset_smartcard_atr()

    if not pkgs_ok:
        log("ERROR: System middleware package installation failed.")
        return 4

    if not svc_ok:
        log("ERROR: pcscd service or socket activation failed.")
        return 5

    if not reader_ok:
        log("ERROR: OpenSC configuration optimization failed.")
        return 6

    if not certs_ok:
        log("ERROR: Certificate installation into system trust store encountered errors.")
        return 2

    if not policies_ok:
        log("ERROR: Browser policy or PKCS#11 module installation encountered errors.")
        return 3

    log("Elevated system configuration complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
