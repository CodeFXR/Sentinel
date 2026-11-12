"""Comprehensive browser configuration manager for Firefox, Chrome, Chromium, Edge, and Snap."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.platform_detector import (
    get_firefox_profile_dirs,
    get_nssdb_dir,
    is_snap_firefox_installed,
    find_opensc_module,
)

logger = logging.getLogger("sentinel.browsers")


@dataclass
class BrowserStatus:
    firefox_installed: bool
    firefox_profiles_count: int
    firefox_policy_active: bool
    firefox_prompt_configured: bool
    firefox_module_loaded: bool
    chrome_installed: bool
    chrome_db_exists: bool
    chrome_module_loaded: bool
    snap_firefox_detected: bool
    snap_connected: bool


def is_browser_running(name: str) -> bool:
    """Check if a browser process is currently running."""
    try:
        res = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True, timeout=2)
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def get_firefox_policies_json_content(module_path: str, cert_path: str) -> str:
    """Generate enterprise policies.json for Firefox."""
    data = {
        "policies": {
            "Certificates": {
                "ImportEnterpriseRoots": True,
                "Install": [cert_path],
            },
            "SecurityDevices": {
                "DoD CAC": module_path,
            },
            "Preferences": {
                "security.default_personal_cert": "Ask Every Time",
                "security.enterprise_roots.enabled": True,
            },
        }
    }
    return json.dumps(data, indent=2)


def configure_firefox_user_js(profile_dir: str) -> bool:
    """Configure security.default_personal_cert = 'Ask Every Time' in profile user.js, recording pre-existing state."""
    user_js = os.path.join(profile_dir, "user.js")
    snap_file = os.path.join(profile_dir, ".sentinel_user_js_snap.json")
    header = "// Added by Sentinel"
    pref_lines = [
        'user_pref("security.default_personal_cert", "Ask Every Time");',
        'user_pref("security.enterprise_roots.enabled", true);',
    ]

    existing = ""
    existed_before = os.path.isfile(user_js)
    if existed_before:
        try:
            with open(user_js, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()
        except OSError:
            pass

    if not os.path.exists(snap_file) and not os.path.islink(snap_file):
        try:
            prior_present = [line for line in pref_lines if line in existing]
            fd_snap = os.open(snap_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(fd_snap, "w", encoding="utf-8") as fs:
                json.dump({"existed_before": existed_before, "prior_lines": prior_present}, fs)
        except OSError:
            pass

    to_add = []
    for line in pref_lines:
        if line not in existing:
            to_add.append(line)

    if not to_add:
        return True

    try:
        with open(user_js, "a", encoding="utf-8") as f:
            if not existing.endswith("\n") and existing:
                f.write("\n")
            if header not in existing and "// Added by Sentinel CAC Manager" not in existing:
                f.write(f"{header}\n")
            for line in to_add:
                f.write(f"{line}\n")
        return True
    except OSError as e:
        logger.error(f"Failed to write user.js in {profile_dir}: {e}")
        return False


def revert_firefox_user_js(profile_dir: str) -> bool:
    """Remove only Sentinel-added lines from a Firefox profile user.js, preserving pre-existing user preferences."""
    user_js = os.path.join(profile_dir, "user.js")
    snap_file = os.path.join(profile_dir, ".sentinel_user_js_snap.json")
    prior_lines: set[str] = set()
    if os.path.isfile(snap_file) and not os.path.islink(snap_file):
        try:
            with open(snap_file, "r", encoding="utf-8") as fs:
                snap = json.load(fs)
            if isinstance(snap, dict) and isinstance(snap.get("prior_lines"), list):
                prior_lines = set(snap["prior_lines"])
        except Exception:
            prior_lines = set()

    if not os.path.isfile(user_js):
        if os.path.isfile(snap_file):
            try:
                os.remove(snap_file)
            except OSError:
                pass
        return True

    sentinel_lines = {
        "// Added by Sentinel",
        "// Added by Sentinel CAC Manager",
        'user_pref("security.default_personal_cert", "Ask Every Time");',
        'user_pref("security.enterprise_roots.enabled", true);',
    } - prior_lines

    try:
        with open(user_js, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        kept = [ln for ln in lines if ln.strip() not in sentinel_lines]
        if not any(ln.strip() for ln in kept):
            os.remove(user_js)
        else:
            with open(user_js, "w", encoding="utf-8") as f:
                f.writelines(kept)
        if os.path.isfile(snap_file):
            try:
                os.remove(snap_file)
            except OSError:
                pass
        return True
    except OSError:
        return False


def configure_firefox_pkcs11_txt(profile_dir: str, module_path: str) -> bool:
    """Ensure DoD CAC security device is loaded in profile pkcs11.txt."""
    pkcs11_txt = os.path.join(profile_dir, "pkcs11.txt")
    if not os.path.isfile(pkcs11_txt):
        content = (
            "library=\n"
            "name=NSS Internal PKCS #11 Module\n"
            f"parameters=configdir='sql:{profile_dir}' certPrefix='' keyPrefix='' secmod='' flags= optimizeSpace\n"
            "NSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={slotFlags=[ECC,RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] askpw=any timeout=30})\n\n"
            f"library={module_path}\n"
            "name=DoD CAC\n\n"
        )
        try:
            with open(pkcs11_txt, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except OSError as e:
            logger.error(f"Failed to create pkcs11.txt in {profile_dir}: {e}")
            return False

    try:
        with open(pkcs11_txt, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if "name=DoD CAC" in content or "name=DoW CAC" in content or module_path in content or "p11-kit-proxy" in content:
            return True

        block = f"\nlibrary={module_path}\nname=DoD CAC\n\n"
        with open(pkcs11_txt, "a", encoding="utf-8") as f:
            f.write(block)
        return True
    except OSError as e:
        logger.error(f"Failed to update pkcs11.txt in {profile_dir}: {e}")
        return False


def revert_firefox_pkcs11_txt(profile_dir: str) -> bool:
    """Remove DoD CAC / DoW CAC blocks from a Firefox profile pkcs11.txt."""
    pkcs11_txt = os.path.join(profile_dir, "pkcs11.txt")
    if not os.path.isfile(pkcs11_txt):
        return True

    try:
        with open(pkcs11_txt, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Remove paragraphs where name=DoD CAC or name=DoW CAC
        cleaned = re.sub(
            r"\n?library=[^\n]+\nname=Do[DW] CAC\n*",
            "\n",
            content,
        )
        with open(pkcs11_txt, "w", encoding="utf-8") as f:
            f.write(cleaned)
        return True
    except OSError:
        return False


def configure_p11_kit_user_module(module_path: str, home_dir: Optional[str] = None) -> bool:
    """Create ~/.config/pkcs11/modules/sentinel-opensc.module for user-level p11-kit."""
    home = home_dir or os.path.expanduser("~")
    user_mod_dir = os.path.join(home, ".config", "pkcs11", "modules")
    os.makedirs(user_mod_dir, exist_ok=True)
    mod_file = os.path.join(user_mod_dir, "sentinel-opensc.module")
    content = f"# Configured by Sentinel\nmodule: {module_path}\n"
    try:
        with open(mod_file, "w", encoding="utf-8") as f:
            f.write(content)
        # Clean up legacy opensc.module if created by Sentinel
        legacy_mod = os.path.join(user_mod_dir, "opensc.module")
        if os.path.isfile(legacy_mod):
            try:
                with open(legacy_mod, "r", encoding="utf-8", errors="replace") as fl:
                    c = fl.read()
                    if "Sentinel" in c or "Sentinel CAC Manager" in c:
                        os.remove(legacy_mod)
            except OSError:
                pass
        return True
    except OSError as e:
        logger.error(f"Failed to write p11-kit user module: {e}")
        return False


def configure_snap_firefox(module_path: str, log_fn=None) -> bool:
    """Set up Snap Firefox confinement permissions and mirrored driver."""
    if not is_snap_firefox_installed():
        return False

    home = os.path.expanduser("~")
    snap_common = os.path.join(home, "snap", "firefox", "common")
    if not os.path.isdir(snap_common):
        try:
            os.makedirs(snap_common, exist_ok=True)
        except OSError as e:
            logger.warning(f"Snap Firefox common directory missing and could not be created: {e}")
            return False

    target_driver = os.path.join(snap_common, "opensc-pkcs11.so")
    try:
        shutil.copy2(module_path, target_driver)
        if log_fn:
            log_fn(f"[Snap] Staged OpenSC driver to {target_driver}")
        return os.path.isfile(target_driver)
    except Exception as e:
        logger.warning(f"Failed to copy opensc driver to Snap common: {e}")
        return False


def configure_chrome_nssdb(module_path: str, log_fn=None) -> Tuple[bool, str]:
    """Configure ~/.pki/nssdb for Chrome, Chromium, Edge, and Brave with postcondition verification."""
    nssdb = get_nssdb_dir()
    os.makedirs(nssdb, exist_ok=True)

    certutil = shutil.which("certutil")
    modutil = shutil.which("modutil")

    if not os.path.isfile(os.path.join(nssdb, "cert9.db")):
        if not certutil:
            return False, "certutil binary not found (install nss-tools / libnss3-tools)"
        try:
            subprocess.run([certutil, "-N", "-d", f"sql:{nssdb}", "--empty-password"], check=True, timeout=3)
            if log_fn:
                log_fn("[Chrome] Initialized ~/.pki/nssdb")
        except Exception as e:
            return False, f"Failed to initialize ~/.pki/nssdb: {e}"

    if not modutil:
        return False, "modutil binary not found (install nss-tools / libnss3-tools)"

    try:
        res_list = subprocess.run([modutil, "-dbdir", f"sql:{nssdb}", "-list"], capture_output=True, text=True, timeout=6)
        list_out = res_list.stdout
        if ("DoD CAC" in list_out and module_path in list_out) or "p11-kit-proxy" in list_out:
            if log_fn:
                log_fn("[Chrome] Smart card module already active in ~/.pki/nssdb")
        else:
            if "DoD CAC" in list_out or "DoW CAC" in list_out:
                for mod_name in ("DoD CAC", "DoW CAC"):
                    subprocess.run(
                        [modutil, "-force", "-dbdir", f"sql:{nssdb}", "-delete", mod_name],
                        input=b"\n",
                        capture_output=True,
                        timeout=6,
                    )
            res_add = subprocess.run(
                [modutil, "-force", "-dbdir", f"sql:{nssdb}", "-add", "DoD CAC", "-libfile", module_path],
                input=b"\n",
                capture_output=True,
                timeout=6,
            )
            if res_add.returncode == 0:
                res_verify = subprocess.run(
                    [modutil, "-dbdir", f"sql:{nssdb}", "-list"],
                    capture_output=True,
                    text=True,
                    timeout=6,
                )
                if "DoD CAC" not in res_verify.stdout or module_path not in res_verify.stdout:
                    return False, "Postcondition failed: 'DoD CAC' module or library path missing from modutil -list"
                if log_fn:
                    log_fn("[Chrome] Successfully registered and verified DoD CAC module in ~/.pki/nssdb")
            else:
                err = res_add.stderr.decode(errors="replace").strip()
                if log_fn:
                    log_fn(f"[Chrome] modutil error: {err}")
                return False, f"Failed to register PKCS#11 module in ~/.pki/nssdb: {err}"
    except Exception as e:
        logger.warning(f"Chrome modutil error: {e}")
        return False, f"Chrome modutil error: {e}"

    from core.certificates import import_root_cas_to_nss
    count, errors = import_root_cas_to_nss(nssdb, log_fn)
    if log_fn:
        log_fn(f"[Chrome] Imported {count} DoD CA certificates into ~/.pki/nssdb")
    if errors:
        return False, f"Chrome NSS CA import errors: {'; '.join(errors)}"

    return True, "Chrome NSS DB configured successfully"


def uninstall_all_browsers(home_dir: Optional[str] = None, log_fn=None) -> bool:
    """Revert user-level browser configurations: NSS module, imported CAs, user.js, pkcs11.txt, and Snap driver."""
    from core.certificates import remove_sentinel_cas_from_nss

    home = home_dir or os.path.expanduser("~")
    nssdb = os.path.join(home, ".pki", "nssdb")
    modutil = shutil.which("modutil")
    all_ok = True

    # 1. Remove DoD CAC module and Sentinel CAs from ~/.pki/nssdb
    if os.path.isdir(nssdb):
        if modutil:
            for mod_name in ("DoD CAC", "DoW CAC"):
                try:
                    res = subprocess.run(
                        [modutil, "-force", "-dbdir", f"sql:{nssdb}", "-delete", mod_name],
                        input=b"\n",
                        capture_output=True,
                        timeout=6,
                    )
                    if res.returncode == 0 and log_fn:
                        log_fn(f"Removed '{mod_name}' PKCS#11 module from {nssdb}")
                except Exception:
                    all_ok = False
        remove_sentinel_cas_from_nss(nssdb, log_fn=log_fn)

    # 2. Revert Firefox profiles (user.js, pkcs11.txt, cert9.db)
    search_roots = [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]
    profiles: List[str] = []
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        try:
            for entry in os.listdir(root):
                cand = os.path.join(root, entry)
                if os.path.isdir(cand) and (
                    os.path.isfile(os.path.join(cand, "cert9.db"))
                    or os.path.isfile(os.path.join(cand, "prefs.js"))
                    or os.path.isfile(os.path.join(cand, "user.js"))
                ):
                    profiles.append(cand)
        except OSError:
            all_ok = False

    for p in profiles:
        if not revert_firefox_user_js(p):
            all_ok = False
        if not revert_firefox_pkcs11_txt(p):
            all_ok = False
        remove_sentinel_cas_from_nss(p, log_fn=log_fn)

    # 3. Remove staged Snap driver if present
    snap_driver = os.path.join(home, "snap", "firefox", "common", "opensc-pkcs11.so")
    if os.path.isfile(snap_driver):
        try:
            os.remove(snap_driver)
            if log_fn:
                log_fn(f"Removed staged Snap driver: {snap_driver}")
        except OSError:
            all_ok = False

    # 4. Remove user p11-kit module configs created by Sentinel
    for mod_fname in ("sentinel-opensc.module", "opensc.module"):
        mod_path = os.path.join(home, ".config", "pkcs11", "modules", mod_fname)
        if os.path.isfile(mod_path):
            try:
                with open(mod_path, "r", encoding="utf-8", errors="replace") as f:
                    if "Sentinel" in f.read() or mod_fname == "sentinel-opensc.module":
                        os.remove(mod_path)
            except OSError:
                all_ok = False

    return all_ok


def configure_all_browsers(log_fn=None) -> Dict[str, Any]:
    """Execute complete browser configuration for Firefox, Chrome, and derivatives."""
    results = {
        "firefox_profiles": 0,
        "firefox_ok": False,
        "chrome_ok": False,
        "snap_ok": True,
        "errors": [],
    }

    if is_browser_running("firefox"):
        if log_fn:
            log_fn(
                "[WARNING] Firefox is currently running! Please restart Firefox after configuration "
                "to load the new smart card device."
            )
    for b_proc in ["chrome", "chromium", "brave", "edge"]:
        if is_browser_running(b_proc):
            if log_fn:
                log_fn(
                    f"[WARNING] {b_proc} is currently running! Please restart it after configuration "
                    "to release NSS database locks."
                )
            break

    module_path = find_opensc_module()
    if not module_path:
        err = "opensc-pkcs11.so not found! Please install opensc package first."
        if log_fn:
            log_fn(f"[ERROR] {err}")
        results["errors"].append(err)
        return results

    if log_fn:
        log_fn(f"Using OpenSC PKCS#11 module: {module_path}")

    # 1. User-level p11-kit module
    if configure_p11_kit_user_module(module_path):
        if log_fn:
            log_fn("[+] Configured user p11-kit module (~/.config/pkcs11/modules/sentinel-opensc.module)")
    else:
        results["errors"].append("Failed to configure user p11-kit module (~/.config/pkcs11/modules/sentinel-opensc.module)")

    # 2. Configure Firefox User Profiles
    profiles = get_firefox_profile_dirs()
    results["firefox_profiles"] = len(profiles)
    if log_fn:
        log_fn(f"Found {len(profiles)} Firefox profile(s) to configure.")

    ff_profile_errors = 0
    for p in profiles:
        p_name = os.path.basename(p)
        if log_fn:
            log_fn(f"-> Configuring Firefox Profile: {p_name}")

        if configure_firefox_user_js(p):
            if log_fn:
                log_fn("   [OK] Set 'Ask Every Time' & enterprise roots in user.js")
        else:
            results["errors"].append(f"Failed to write user.js in {p_name}")
            ff_profile_errors += 1

        if configure_firefox_pkcs11_txt(p, module_path):
            if log_fn:
                log_fn("   [OK] Loaded DoD CAC module in pkcs11.txt")
        else:
            results["errors"].append(f"Failed to update pkcs11.txt in {p_name}")
            ff_profile_errors += 1

        from core.certificates import import_root_cas_to_nss
        cnt, errs = import_root_cas_to_nss(p, log_fn=None)
        if log_fn:
            log_fn(f"   [OK] Imported {cnt} DoD CAs into cert9.db")
        if errs:
            results["errors"].extend(errs)
            ff_profile_errors += len(errs)

    b_stat_after = check_browsers_status()
    results["firefox_ok"] = (ff_profile_errors == 0) and (
        b_stat_after.firefox_policy_active or b_stat_after.firefox_module_loaded
    )

    # 3. Configure Snap Firefox if present
    if is_snap_firefox_installed():
        snap_ok = configure_snap_firefox(module_path, log_fn)
        results["snap_ok"] = snap_ok
        if not snap_ok:
            results["errors"].append("Failed to stage OpenSC PKCS#11 driver into Snap Firefox common directory")

    # 4. Configure Chrome / Chromium / Edge NSS DB
    c_ok, c_msg = configure_chrome_nssdb(module_path, log_fn)
    results["chrome_ok"] = c_ok
    if not c_ok:
        results["errors"].append(c_msg)

    return results


def check_browsers_status() -> BrowserStatus:
    """Inspect and report health of Firefox and Chrome smart card configurations."""
    profiles = get_firefox_profile_dirs()
    ff_installed = bool(shutil.which("firefox")) or bool(profiles)

    ff_policy_active = False
    policy_candidates = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/var/snap/firefox/common/policies/policies.json",
    ]
    for pc in policy_candidates:
        if os.path.isfile(pc):
            try:
                with open(pc, "r", encoding="utf-8") as f:
                    pol_data = json.load(f)
                if isinstance(pol_data, dict) and isinstance(pol_data.get("policies"), dict):
                    p_block = pol_data["policies"]
                    sec = p_block.get("SecurityDevices", {})
                    if isinstance(sec, dict):
                        for dev_name in ("DoD CAC", "DoW CAC"):
                            if dev_name in sec:
                                dev_path = sec[dev_name]
                                if dev_path and os.path.isfile(dev_path):
                                    ff_policy_active = True
                                    break
                    if ff_policy_active:
                        certs_cfg = p_block.get("Certificates", {})
                        if isinstance(certs_cfg, dict) and "Install" in certs_cfg:
                            inst_list = certs_cfg.get("Install", [])
                            if isinstance(inst_list, list):
                                for c_p in inst_list:
                                    if not os.path.isfile(c_p):
                                        ff_policy_active = False
                                        break
                        if ff_policy_active:
                            break
            except Exception:
                pass

    ff_prompt = False
    ff_module = False
    for p in profiles:
        ujs = os.path.join(p, "user.js")
        if os.path.isfile(ujs):
            try:
                with open(ujs, encoding="utf-8", errors="replace") as f:
                    if "Ask Every Time" in f.read():
                        ff_prompt = True
            except Exception:
                pass

        p11 = os.path.join(p, "pkcs11.txt")
        if os.path.isfile(p11):
            try:
                with open(p11, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    if "DoW CAC" in content or "DoD CAC" in content or "opensc-pkcs11" in content or "p11-kit-proxy" in content:
                        lib_match = re.search(r"library\s*=\s*([^\r\n]+)", content)
                        if lib_match:
                            lib_p = lib_match.group(1).strip()
                            if os.path.isfile(lib_p):
                                ff_module = True
                        else:
                            ff_module = True
            except Exception:
                pass

    nssdb = get_nssdb_dir()
    chrome_installed = bool(
        shutil.which("google-chrome")
        or shutil.which("chromium")
        or shutil.which("microsoft-edge")
        or shutil.which("brave-browser")
    )
    chrome_db_exists = os.path.isfile(os.path.join(nssdb, "cert9.db"))
    chrome_module = False
    if chrome_db_exists and shutil.which("modutil"):
        try:
            res = subprocess.run(
                [shutil.which("modutil"), "-dbdir", f"sql:{nssdb}", "-list"],
                capture_output=True,
                text=True,
                timeout=6,
            )
            out_str = res.stdout
            if "DoW CAC" in out_str or "DoD CAC" in out_str or "p11-kit-proxy" in out_str or "OpenSC" in out_str:
                lib_match = re.search(r"library name:\s*([^\r\n]+)", out_str, re.IGNORECASE)
                if lib_match:
                    lib_p = lib_match.group(1).strip()
                    if os.path.isfile(lib_p) or lib_p.endswith("p11-kit-proxy.so"):
                        chrome_module = True
                else:
                    chrome_module = True
        except Exception:
            pass

    snap_detected = is_snap_firefox_installed()
    snap_connected = False
    if snap_detected:
        try:
            res = subprocess.run(["snap", "connections", "firefox"], capture_output=True, text=True, timeout=4)
            if "pcscd" in res.stdout and "firefox:pcscd" in res.stdout:
                snap_connected = True
        except Exception:
            pass

    return BrowserStatus(
        firefox_installed=ff_installed,
        firefox_profiles_count=len(profiles),
        firefox_policy_active=ff_policy_active,
        firefox_prompt_configured=ff_prompt,
        firefox_module_loaded=ff_module,
        chrome_installed=chrome_installed,
        chrome_db_exists=chrome_db_exists,
        chrome_module_loaded=chrome_module,
        snap_firefox_detected=snap_detected,
        snap_connected=snap_connected,
    )
