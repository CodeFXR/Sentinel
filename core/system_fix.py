"""System-wide configuration orchestrator and package installer for Sentinel."""

from __future__ import annotations

import json
import logging
import os
import queue
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.browsers import (
    check_browsers_status,
    configure_all_browsers,
    uninstall_all_browsers,
)
from core.platform_detector import PlatformInfo, detect_platform, find_opensc_module
from core.smartcard import scan_smartcard

logger = logging.getLogger("sentinel.system_fix")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_SCRIPT = os.path.join(SCRIPT_DIR, "core", "privileged_helper.py")
SYSTEM_HELPER = "/usr/libexec/sentinel/privileged_helper.py"


def get_helper_script(require_root_owned: bool = True) -> Optional[str]:
    """Return protected root-owned helper in /usr/libexec/sentinel/privileged_helper.py.

    Always requires both the helper and its parent directory to be owned by root (UID 0)
    and not group- or world-writable, preventing execution of user-writable code as root.
    """
    candidates = [SYSTEM_HELPER]
    if not require_root_owned:
        candidates.append(HELPER_SCRIPT)

    for cand in candidates:
        if os.path.isfile(cand) and not os.path.islink(cand):
            try:
                st = os.stat(cand)
                parent_st = os.stat(os.path.dirname(os.path.abspath(cand)))
                if (
                    st.st_uid == 0
                    and parent_st.st_uid == 0
                    and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                    and not (parent_st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                ):
                    return cand
            except OSError:
                pass

    return None


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
        if "card_drivers" in uncommented and ("piv-II" in uncommented or "PIV-II" in uncommented or ("cac" in uncommented and "piv" in uncommented)):
            return True
    return False


def check_missing_packages(plat: Optional[PlatformInfo] = None) -> List[str]:
    """Check which required binaries or packages are missing."""
    missing = []
    binary_checks = [
        ("pcscd", "pcscd"),
        ("opensc-tool", "opensc"),
        ("pkcs11-tool", "opensc"),
        ("certutil", "libnss3-tools / nss-tools"),
        ("modutil", "libnss3-tools / nss-tools"),
    ]
    for bname, pkgname in binary_checks:
        if not shutil.which(bname):
            missing.append(pkgname)
    return sorted(list(set(missing)))


def run_privileged_helper(
    args: List[str],
    log_fn: Optional[Callable[[str], None]] = None,
    timeout: int = 60,
) -> Tuple[bool, str]:
    """Run privileged_helper.py via pkexec (or directly if root) with non-blocking timeout handling."""
    is_root = os.geteuid() == 0
    helper_path = get_helper_script(require_root_owned=not is_root)
    if not helper_path:
        return (
            False,
            "Protected helper /usr/libexec/sentinel/privileged_helper.py is not installed or not root-owned. "
            "Run './install' first.",
        )

    if is_root:
        cmd = ["python3", helper_path, *args]
    else:
        if not shutil.which("pkexec"):
            return False, "pkexec binary not found. Please run with sudo."
        # Execute the root-owned helper directly so Polkit binds to com.codefxr.sentinel.policy
        if os.access(helper_path, os.X_OK):
            cmd = ["pkexec", helper_path, *args]
        else:
            cmd = ["pkexec", "python3", helper_path, *args]

    if log_fn:
        log_fn("Requesting authorization (Polkit prompt)...")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=not sys.stdin.isatty(),
        )
    except Exception as e:
        return False, f"Failed to spawn elevated helper process: {e}"

    output_lines: List[str] = []
    line_queue: queue.Queue[Optional[str]] = queue.Queue()

    def _reader():
        try:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    line_queue.put(line)
        except Exception:
            pass
        finally:
            line_queue.put(None)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    deadline = time.monotonic() + timeout
    timed_out = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break

        try:
            line = line_queue.get(timeout=min(max(remaining, 0.05), 0.2))
            if line is None:
                break
            line_str = line.strip()
            if line_str:
                output_lines.append(line_str)
                if log_fn:
                    log_fn(line_str)
        except queue.Empty:
            if proc.poll() is not None:
                while True:
                    try:
                        rem_line = line_queue.get_nowait()
                        if rem_line is None:
                            break
                        line_str = rem_line.strip()
                        if line_str:
                            output_lines.append(line_str)
                            if log_fn:
                                log_fn(line_str)
                    except queue.Empty:
                        break
                break

    if timed_out:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass
        return False, f"Authorization or elevated execution timed out after {timeout} seconds."

    try:
        proc.wait(timeout=5)
    except Exception:
        pass
    if proc.stdout:
        try:
            proc.stdout.close()
        except Exception:
            pass

    if proc.returncode == 0:
        return True, "\n".join(output_lines)
    else:
        err_detail = f"Process exited with code {proc.returncode}"
        if output_lines:
            err_detail += f": {output_lines[-1]}"
        return False, err_detail


def run_full_setup(
    progress_callback: Optional[Callable[[float, str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Automate end-to-end DoD CAC setup with strict postcondition verification."""
    plat = detect_platform()
    result: Dict[str, Any] = {
        "success": False,
        "platform": plat.name,
        "step": "",
        "message": "",
        "details": {},
    }

    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    def _progress(frac: float, msg: str):
        _log(f"[{int(frac * 100)}%] {msg}")
        if progress_callback:
            progress_callback(frac, msg)

    _log(f"Starting Automated DoD CAC Setup on {plat.name} ({plat.family})...")

    # Step 1: Detect OpenSC module
    _progress(0.10, "Detecting middleware modules...")
    module_path = find_opensc_module()
    if not module_path:
        module_path = (
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
            if plat.is_debian_derivative
            else "/usr/lib64/opensc-pkcs11.so"
        )
    _log(f"Detected OpenSC module: {module_path}")

    # Step 2: Elevated System Configuration
    _progress(0.30, "Applying elevated system settings (CAs, daemon, reader fix)...")
    system_certs_dir = "/usr/share/sentinel/certificates"
    certs_dir = os.path.join(SCRIPT_DIR, "certificates")
    helper_args = [
        "--all",
        "--family",
        plat.family,
        "--module",
        module_path,
    ]
    if not (os.path.isdir(system_certs_dir) and os.path.isdir(os.path.join(system_certs_dir, "all_cas"))):
        if os.path.isdir(certs_dir):
            helper_args.extend(["--certs-dir", certs_dir])
    ok, helper_msg = run_privileged_helper(helper_args, log_fn=_log, timeout=60)
    if not ok:
        result["message"] = f"Elevated setup failed: {helper_msg}"
        _log(f"[ERROR] {result['message']}")
        return result

    # Step 3: Configure Browsers (Firefox & Chrome)
    _progress(0.60, "Configuring Firefox and Chrome security devices...")
    browser_res = configure_all_browsers(log_fn=_log)
    result["details"]["browsers"] = browser_res

    if shutil.which("opensc-tool"):
        try:
            subprocess.run(["opensc-tool", "--reset", "warm"], capture_output=True, timeout=4)
        except Exception:
            pass

    # Step 4: Rigorous Postcondition Verification
    _progress(0.85, "Verifying system trust and browser postconditions...")
    card_stat = scan_smartcard(force_refresh=True)
    b_stat = check_browsers_status()

    result["details"]["card_status"] = card_stat
    result["details"]["browser_status"] = b_stat

    from core.certificates import is_system_trust_installed
    trust_verified = is_system_trust_installed(plat)
    browser_errors = list(browser_res.get("errors", []))

    ff_ready = b_stat.firefox_policy_active or b_stat.firefox_module_loaded
    chrome_ready = b_stat.chrome_module_loaded

    if not card_stat.service_active:
        browser_errors.append("Smart card daemon (pcscd) is not active after setup.")
    if b_stat.firefox_installed and not ff_ready:
        browser_errors.append("Firefox policy and PKCS#11 security device could not be verified.")
    if b_stat.chrome_installed and not chrome_ready:
        browser_errors.append("Chrome/Chromium NSS database (~/.pki/nssdb) PKCS#11 module could not be verified.")
    if not b_stat.firefox_installed and not b_stat.chrome_installed:
        if not b_stat.firefox_policy_active and not b_stat.chrome_db_exists:
            browser_errors.append("Neither Firefox nor Chrome/NSS could be verified as configured.")

    if not trust_verified:
        result["success"] = False
        result["message"] = "DoD Root CA trust could not be verified in the operating system root store."
        _log(f"[ERROR] {result['message']}")
    elif browser_errors:
        result["success"] = False
        result["partial"] = True
        result["message"] = f"Setup completed with warnings/errors: {'; '.join(browser_errors)}"
        _progress(0.95, "Setup completed with warnings.")
        _log(f"[WARNING] {result['message']}")
    else:
        result["success"] = True
        if card_stat.card_present:
            result["message"] = (
                "All 4 DoD Root CAs, pcscd daemon, and browser configuration files verified; "
                "inserted CAC is ready for authentication."
            )
        else:
            result["message"] = (
                "All 4 DoD Root CAs, pcscd daemon, and browser configuration files verified. "
                "Insert a DoD CAC into your reader to authenticate."
            )
        _progress(1.0, "Setup Complete! System trust and browser modules verified.")
        _log(f"[SUCCESS] {result['message']}")

    return result


def install_desktop_integration(
    project_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    home_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """Install application menu shortcut and CLI commands in ~/.local."""
    if not project_dir:
        project_dir = SCRIPT_DIR

    home = home_dir or os.path.expanduser("~")
    bin_dir = os.path.join(home, ".local", "bin")
    app_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "256x256", "apps")
    script_target = os.path.join(project_dir, "sentinel.py")
    if not os.path.isfile(script_target):
        script_target = os.path.join(project_dir, "sentinel_cac_manager.py")
    launcher_path = os.path.join(bin_dir, "sentinel")
    compat_launcher_path = os.path.join(bin_dir, "sentinel-cac-manager")
    desktop_file = os.path.join(app_dir, "sentinel.desktop")
    compat_desktop_file = os.path.join(app_dir, "sentinel_cac_manager.desktop")

    for p_name, p_val in (
        ("project_dir", project_dir),
        ("home", home),
        ("bin_dir", bin_dir),
        ("app_dir", app_dir),
        ("icon_dir", icon_dir),
        ("script_target", script_target),
    ):
        if any(c in p_val for c in ("\r", "\n", "\0")):
            err = f"Failed to install desktop integration: Invalid {p_name}: path must not contain newline characters (CWE-74)"
            if log_fn:
                log_fn(f"[ERROR] {err}")
            return False, err

    if not os.path.isdir(project_dir):
        err = f"Failed to install desktop integration: project_dir '{project_dir}' is not an existing directory"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err

    if not os.path.isfile(script_target):
        err = f"Failed to install desktop integration: Entrypoint '{script_target}' not found"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err

    try:
        os.makedirs(bin_dir, exist_ok=True)
        os.makedirs(app_dir, exist_ok=True)
        os.makedirs(icon_dir, exist_ok=True)

        for candidate_icon in ["sentinel.png", "sentinel_cac_manager.png", "sentinel_icon.png", "sentinel_icon_v2.png"]:
            icon_src = os.path.join(project_dir, candidate_icon)
            if os.path.isfile(icon_src):
                shutil.copy2(icon_src, os.path.join(icon_dir, "sentinel.png"))
                shutil.copy2(icon_src, os.path.join(icon_dir, "sentinel_cac_manager.png"))
                if log_fn:
                    log_fn(f"Installed application icon to {icon_dir}/sentinel.png")
                break

        icon_path = os.path.join(icon_dir, "sentinel.png")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(icon_dir, "sentinel_cac_manager.png")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(project_dir, "sentinel.png")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(project_dir, "sentinel_cac_manager.png")

        def escape_desktop_value(val: str) -> str:
            return val.replace("\\", "\\\\")

        def escape_desktop_exec_arg(val: str) -> str:
            escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")
            return f'"{escaped}"'

        escaped_script = escape_desktop_exec_arg(script_target)
        escaped_project_dir = escape_desktop_value(project_dir)
        escaped_icon_path = escape_desktop_value(icon_path)

        desktop_content = f"""[Desktop Entry]
Name=Sentinel
GenericName=DoD Smart Card Manager
Comment=Automate DoD CAC Middleware, Certificates, and Browser Authentication
Exec=python3 {escaped_script} --gui
Path={escaped_project_dir}
Icon={escaped_icon_path}
Terminal=false
Type=Application
Categories=Utility;Security;
Keywords=CAC;PIV;DoD;SmartCard;Military;Security;Authentication;
StartupNotify=true
StartupWMClass=com.codefxr.sentinel
"""
        with tempfile.NamedTemporaryFile(mode="w", dir=app_dir, delete=False, encoding="utf-8") as f_dt:
            desktop_tmp = f_dt.name
            f_dt.write(desktop_content)
        os.chmod(desktop_tmp, 0o644)
        os.replace(desktop_tmp, desktop_file)

        # Compatibility copy for legacy desktop file name
        with tempfile.NamedTemporaryFile(mode="w", dir=app_dir, delete=False, encoding="utf-8") as f_cdt:
            compat_dt_tmp = f_cdt.name
            f_cdt.write(desktop_content)
        os.chmod(compat_dt_tmp, 0o644)
        os.replace(compat_dt_tmp, compat_desktop_file)

        legacy_desktop = os.path.join(app_dir, "sentinel_v2.desktop")
        if os.path.isfile(legacy_desktop):
            try:
                os.remove(legacy_desktop)
            except Exception:
                pass

        if shutil.which("update-desktop-database") and home_dir is None:
            subprocess.run(["update-desktop-database", app_dir], capture_output=True)

        quoted_script = shlex.quote(script_target)
        launcher_script = f"""#!/usr/bin/env bash
exec python3 {quoted_script} "$@"
"""
        if not os.path.exists(launcher_path) or os.path.islink(launcher_path):
            with tempfile.NamedTemporaryFile(mode="w", dir=bin_dir, delete=False, encoding="utf-8") as f_ln:
                launcher_tmp = f_ln.name
                f_ln.write(launcher_script)
            os.chmod(launcher_tmp, 0o755)
            os.replace(launcher_tmp, launcher_path)

        with tempfile.NamedTemporaryFile(mode="w", dir=bin_dir, delete=False, encoding="utf-8") as f_cln:
            compat_tmp = f_cln.name
            f_cln.write(launcher_script)
        os.chmod(compat_tmp, 0o755)
        os.replace(compat_tmp, compat_launcher_path)

        for old_alias in ["sentinel-v2", "sentinel2"]:
            old_p = os.path.join(bin_dir, old_alias)
            if os.path.islink(old_p) or os.path.isfile(old_p):
                try:
                    os.remove(old_p)
                except OSError:
                    pass

        if log_fn:
            log_fn(f"Created command launcher at {launcher_path}")

        desktop_dir = os.path.join(home, "Desktop")
        if os.path.isdir(desktop_dir):
            try:
                user_desktop_file = os.path.join(desktop_dir, "sentinel_cac_manager.desktop")
                with tempfile.NamedTemporaryFile(mode="w", dir=desktop_dir, delete=False, encoding="utf-8") as f_ud:
                    user_desktop_tmp = f_ud.name
                    f_ud.write(desktop_content)
                os.chmod(user_desktop_tmp, 0o755)
                os.replace(user_desktop_tmp, user_desktop_file)
                legacy_user_desktop = os.path.join(desktop_dir, "sentinel_v2.desktop")
                if os.path.isfile(legacy_user_desktop):
                    os.remove(legacy_user_desktop)
                if shutil.which("gio") and home_dir is None:
                    subprocess.run(
                        ["gio", "set", user_desktop_file, "metadata::trusted", "true"],
                        capture_output=True,
                    )
            except Exception:
                pass

        if log_fn:
            log_fn(f"Installed desktop entry to {desktop_file}")

        return True, "Desktop entry and command shortcuts installed successfully."
    except Exception as e:
        err = f"Failed to install desktop integration: {e}"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err


def uninstall_desktop_integration(
    home_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Remove user-level launchers, shortcuts, icons, browser modules/prefs, and user services."""
    home = home_dir or os.path.expanduser("~")
    bin_dir = os.path.join(home, ".local", "bin")
    app_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "256x256", "apps")
    desktop_dir = os.path.join(home, "Desktop")

    # Revert user-space browser configurations (NSS module, imported CAs, user.js, pkcs11.txt)
    browsers_ok = True
    try:
        browsers_ok = uninstall_all_browsers(home_dir=home, log_fn=log_fn)
    except Exception as e:
        browsers_ok = False
        logger.debug(f"Browser cleanup note: {e}")

    files_to_remove = [
        os.path.join(app_dir, "sentinel.desktop"),
        os.path.join(app_dir, "sentinel_cac_manager.desktop"),
        os.path.join(app_dir, "sentinel_v2.desktop"),
        os.path.join(icon_dir, "sentinel.png"),
        os.path.join(icon_dir, "sentinel_cac_manager.png"),
        os.path.join(bin_dir, "sentinel"),
        os.path.join(bin_dir, "sentinel-cac-manager"),
        os.path.join(bin_dir, "sentinel-v2"),
        os.path.join(bin_dir, "sentinel2"),
        os.path.join(desktop_dir, "sentinel.desktop"),
        os.path.join(desktop_dir, "sentinel_cac_manager.desktop"),
        os.path.join(desktop_dir, "sentinel_v2.desktop"),
        os.path.join(home, ".config", "pkcs11", "modules", "sentinel-opensc.module"),
        os.path.join(home, ".config", "pkcs11", "modules", "opensc.module"),
        os.path.join(home, ".config", "sentinel", "config.json"),
    ]

    sentinel_bin = os.path.join(bin_dir, "sentinel")
    if os.path.islink(sentinel_bin):
        try:
            target = os.readlink(sentinel_bin)
            if "sentinel" in target:
                files_to_remove.append(sentinel_bin)
        except OSError:
            pass

    removed_count = 0
    removal_failed = False
    for f in files_to_remove:
        if os.path.islink(f) or os.path.isfile(f):
            try:
                os.remove(f)
                removed_count += 1
            except OSError:
                removal_failed = True

    if shutil.which("update-desktop-database") and os.path.isdir(app_dir) and home_dir is None:
        subprocess.run(["update-desktop-database", app_dir], capture_output=True)

    svc_ok = True
    try:
        from core.agent import uninstall_systemd_user_service
        svc_ok, _ = uninstall_systemd_user_service(home_dir=home, log_fn=log_fn)
    except Exception as e:
        svc_ok = False
        logger.debug(f"Could not cleanly uninstall user service: {e}")

    overall_ok = browsers_ok and not removal_failed and svc_ok
    msg = f"Removed {removed_count} user desktop, browser, and launcher items."
    if not overall_ok:
        msg = f"{msg} (One or more user cleanup actions reported warnings/errors.)"
    if log_fn:
        log_fn(msg)
    return overall_ok, msg


def run_full_uninstall(log_callback: Optional[Callable[[str], None]] = None) -> bool:
    """Run full uninstallation: revert user browser/desktop config first, then system trust and policies."""
    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    _log("Starting Sentinel full uninstallation and rollback...")
    plat = detect_platform()

    # Step 1: Revert user desktop and browser integration (NSS DB, Firefox prefs, launchers)
    user_ok, user_msg = uninstall_desktop_integration(log_fn=_log)
    if not user_ok:
        _log(f"[WARNING] User-level rollback reported issues: {user_msg}")

    # Step 2: Elevated uninstallation (system CAs, enterprise policies, OpenSC config, helper)
    ok, helper_msg = run_privileged_helper(["--uninstall", "--family", plat.family], log_fn=_log, timeout=60)
    if not ok:
        _log(f"[ERROR] Privileged rollback failed: {helper_msg}")
        return False

    if not user_ok:
        _log("[ERROR] System rollback succeeded, but user-level browser/desktop cleanup was incomplete.")
        return False

    _log("[SUCCESS] Full uninstallation and rollback completed successfully.")
    return True


def check_smartcard_logon_status(home_dir: Optional[str] = None) -> dict:
    """Inspect workstation screen locking status."""
    from core.agent import is_lock_on_removal_enabled
    lock_removal_enabled = is_lock_on_removal_enabled(home_dir=home_dir)

    return {
        "logon_enabled": False,
        "lock_removal_enabled": lock_removal_enabled,
        "sssd_configured": False,
        "platform_supported": False,
    }


def set_lock_on_removal(
    enabled: bool,
    log_fn: Optional[Callable[[str], None]] = None,
    home_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """Configure screen lock on smart card removal across desktop environments."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    base_home = Path(home_dir) if home_dir else Path.home()
    try:
        conf_dir = base_home / ".config" / "sentinel"
        conf_dir.mkdir(parents=True, exist_ok=True)
        conf_file = conf_dir / "config.json"
        data = {}
        if conf_file.is_file():
            try:
                data = json.loads(conf_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        data["lock_on_removal"] = enabled
        conf_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _log(f"Updated Sentinel config lock_on_removal={enabled}")
    except Exception as e:
        _log(f"Warning: Could not write Sentinel user config: {e}")

    # Only invoke host gsettings when operating on the real user session (never in isolated home_dir tests)
    if home_dir is None:
        gsettings = shutil.which("gsettings")
        if gsettings:
            action = "lock-screen" if enabled else "none"
            try:
                subprocess.run(
                    [gsettings, "set", "org.gnome.settings-daemon.peripherals.smartcard", "removal-action", action],
                    capture_output=True,
                    timeout=2,
                )
                _log(f"Configured GNOME smartcard removal-action to '{action}'")
            except Exception as e:
                _log(f"Note: Could not set gsettings removal-action: {e}")

    status_str = "enabled" if enabled else "disabled"
    return True, f"Screen lock on smart card removal {status_str}."


def check_scdaemon_conflict() -> Tuple[bool, str]:
    """Check if GnuPG scdaemon is running and potentially locking CCID smart card readers.

    Returns: (is_conflicted, detail_message)
    """
    pgrep = shutil.which("pgrep")
    if not pgrep:
        return False, "pgrep not available"

    try:
        res = subprocess.run([pgrep, "-x", "scdaemon"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            # Check if disable-ccid is configured in scdaemon configs
            has_disable_ccid = False
            for conf_path in [
                Path.home() / ".gnupg" / "scdaemon.conf",
                Path("/etc/gnupg/scdaemon.conf"),
            ]:
                if conf_path.is_file():
                    try:
                        content = conf_path.read_text(encoding="utf-8", errors="replace")
                        for line in content.splitlines():
                            line_strip = line.split("#", 1)[0].strip()
                            if "disable-ccid" in line_strip:
                                has_disable_ccid = True
                                break
                    except Exception:
                        pass
            if not has_disable_ccid:
                return True, "GnuPG scdaemon is active without 'disable-ccid'; may lock USB CCID reader."
    except Exception as e:
        logger.debug(f"scdaemon check failed: {e}")

    return False, "No scdaemon conflict detected."


def fix_scdaemon_conflict(log_fn: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Configure disable-ccid in ~/.gnupg/scdaemon.conf and reload GnuPG scdaemon."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    gnupg_dir = Path.home() / ".gnupg"
    try:
        gnupg_dir.mkdir(parents=True, exist_ok=True)
        gnupg_dir.chmod(0o700)
        conf_file = gnupg_dir / "scdaemon.conf"
        content = ""
        if conf_file.is_file():
            content = conf_file.read_text(encoding="utf-8", errors="replace")

        lines = content.splitlines()
        has_disable_ccid = any("disable-ccid" in line.split("#", 1)[0] for line in lines)
        if not has_disable_ccid:
            lines.append("disable-ccid")
            conf_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            conf_file.chmod(0o600)
            _log("Added 'disable-ccid' to ~/.gnupg/scdaemon.conf")

        # Terminate active scdaemon so gpg-agent re-evaluates the updated configuration
        gpgconf = shutil.which("gpgconf")
        if gpgconf:
            subprocess.run([gpgconf, "--kill", "scdaemon"], capture_output=True, timeout=3)
            _log("Reloaded GnuPG daemon components")

        return True, "Successfully configured GnuPG scdaemon to share CCID reader with pcscd."
    except Exception as e:
        return False, f"Failed to configure scdaemon: {e}"
