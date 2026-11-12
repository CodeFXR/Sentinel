"""Background event daemon for Sentinel.

Monitors smart card reader insertion and removal events using native Rust
blocking PC/SC notification with zero CPU polling overhead, and emits
desktop notifications.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Tuple

from core.rust_bridge import wait_for_card_event_rust
from core.smartcard import scan_smartcard

logger = logging.getLogger("sentinel.agent")

SYSTEMD_USER_SERVICE_CONTENT = """[Unit]
Description=Sentinel Card Monitor Daemon
After=default.target

[Service]
Type=simple
ExecStart=%h/.local/bin/sentinel --agent
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
"""


def install_systemd_user_service(
    home_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Install and enable sentinel-agent systemd user service."""
    def _log(msg: str):
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    home = home_dir or os.path.expanduser("~")
    user_systemd_dir = Path(home) / ".config" / "systemd" / "user"
    user_systemd_dir.mkdir(parents=True, exist_ok=True)
    service_file = user_systemd_dir / "sentinel-agent.service"

    try:
        service_file.write_text(SYSTEMD_USER_SERVICE_CONTENT, encoding="utf-8")
        _log(f"Wrote user service unit to {service_file}")
    except OSError as e:
        err = f"Failed to write systemd user service file: {e}"
        _log(f"[-] {err}")
        return False, err

    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            subprocess.run([systemctl, "--user", "daemon-reload"], check=True, capture_output=True)
            subprocess.run([systemctl, "--user", "enable", "--now", "sentinel-agent.service"], check=True, capture_output=True)
            _log("[+] Enabled and started sentinel-agent systemd user service.")
        except subprocess.CalledProcessError as e:
            warn = f"Warning: Could not enable systemd user unit automatically: {e}"
            _log(f"[-] {warn}")
            return False, warn

    return True, "Sentinel background agent installed and enabled."


def uninstall_systemd_user_service(
    home_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Stop, disable, and remove sentinel-agent systemd user service."""
    def _log(msg: str):
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    systemctl = shutil.which("systemctl")
    if systemctl and home_dir is None:
        try:
            subprocess.run([systemctl, "--user", "stop", "sentinel-agent.service"], capture_output=True)
            subprocess.run([systemctl, "--user", "disable", "sentinel-agent.service"], capture_output=True)
            check_act = subprocess.run([systemctl, "--user", "is-active", "sentinel-agent.service"], capture_output=True, text=True)
            if check_act.returncode == 0 and check_act.stdout.strip() == "active":
                return False, "sentinel-agent service is still active after stop attempt."
        except Exception as e:
            logger.debug(f"systemctl user stop note: {e}")

    home = home_dir or os.path.expanduser("~")
    service_file = Path(home) / ".config" / "systemd" / "user" / "sentinel-agent.service"
    if service_file.is_file():
        try:
            service_file.unlink()
            _log(f"Removed {service_file}")
        except OSError as e:
            _log(f"[-] Could not remove {service_file}: {e}")
            return False, f"Could not remove {service_file}: {e}"

    if service_file.exists():
        return False, f"Service file {service_file} still exists after removal attempt."

    if systemctl and home_dir is None:
        try:
            subprocess.run([systemctl, "--user", "daemon-reload"], capture_output=True)
        except Exception:
            pass

    return True, "Sentinel background agent service uninstalled."


def is_lock_on_removal_enabled(home_dir: Optional[str] = None) -> bool:
    """Check if workstation screen should lock upon smart card removal."""
    try:
        base_home = Path(home_dir) if home_dir else Path.home()
        conf_file = base_home / ".config" / "sentinel" / "config.json"
        if conf_file.is_file():
            import json
            data = json.loads(conf_file.read_text(encoding="utf-8"))
            if "lock_on_removal" in data:
                return bool(data["lock_on_removal"])
    except Exception:
        pass

    if home_dir is None:
        gsettings = shutil.which("gsettings")
        if gsettings:
            try:
                res = subprocess.run(
                    [gsettings, "get", "org.gnome.settings-daemon.peripherals.smartcard", "removal-action"],
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                if "lock-screen" in res.stdout:
                    return True
            except Exception:
                pass

    return False


def lock_session() -> bool:
    """Trigger desktop screen lock across systemd sessions (Wayland and X11)."""
    loginctl = shutil.which("loginctl")
    if loginctl:
        try:
            subprocess.run([loginctl, "lock-session"], capture_output=True, timeout=2)
            logger.info("Executed loginctl lock-session following smart card removal.")
            return True
        except Exception as e:
            logger.debug(f"Failed to execute loginctl lock-session: {e}")
    return False


def send_desktop_notification(
    title: str,
    body: str,
    urgency: str = "normal",
    icon: Optional[str] = None,
) -> bool:
    """Emit desktop notification via notify-send utility."""
    notify_send = shutil.which("notify-send")
    if not notify_send:
        logger.debug("notify-send not installed on host; skipping desktop notification.")
        return False

    repo_root = Path(__file__).resolve().parent.parent
    icon_candidate = str(repo_root / "sentinel.png")
    if not os.path.isfile(icon_candidate):
        icon_candidate = str(repo_root / "sentinel_cac_manager.png")
    app_icon = icon or (icon_candidate if os.path.isfile(icon_candidate) else "dialog-password-symbolic")

    try:
        subprocess.run(
            [
                notify_send,
                "-a", "Sentinel",
                "-u", urgency,
                "-i", app_icon,
                title,
                body,
            ],
            capture_output=True,
            timeout=3,
        )
        return True
    except Exception as e:
        logger.debug(f"Failed to dispatch desktop notification: {e}")
        return False


def run_agent(stop_event: Optional[threading.Event] = None) -> None:
    """Run event-driven smart card listener loop until interrupted or stop_event is set."""
    logger.info("Starting Sentinel background event daemon...")

    # Set up signal handlers if running on the main thread
    if threading.current_thread() is threading.main_thread():
        def _handle_signal(_signum, _frame):
            logger.info("Received termination signal. Shutting down Sentinel agent...")
            if stop_event:
                stop_event.set()
            else:
                sys.exit(0)

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    # Initial state probe
    initial_status = scan_smartcard()
    last_present = initial_status.card_present
    logger.info(f"Initial reader status: card_present={last_present}")

    while True:
        if stop_event and stop_event.is_set():
            logger.info("Stop event received. Exiting Sentinel agent.")
            break

        event = wait_for_card_event_rust(timeout_ms=2000)
        if event is None:
            time.sleep(0.5)
            continue

        reader_name, is_present = event
        if is_present == last_present:
            continue

        last_present = is_present
        if is_present:
            logger.info(f"Smart card inserted in reader: {reader_name}")
            status = scan_smartcard(force_refresh=True)
            holder = "DoD Cardholder"
            if status.primary_certificate and status.primary_certificate.holder_name:
                holder = status.primary_certificate.holder_name
            elif status.certificates and status.certificates[0].holder_name:
                holder = status.certificates[0].holder_name

            retries_str = f"{status.pin_retries_remaining} remaining" if status.pin_retries_remaining is not None else "Active"
            send_desktop_notification(
                title="DoD Smart Card Detected",
                body=f"Cardholder: {holder}\nPIN Retries: {retries_str}\nReader: {reader_name}",
                urgency="normal",
            )
        else:
            logger.info(f"Smart card removed from reader: {reader_name}")
            locked = False
            if is_lock_on_removal_enabled():
                locked = lock_session()

            body_msg = f"DoD Common Access Card was removed from {reader_name}."
            if locked:
                body_msg += "\nWorkstation session locked."

            send_desktop_notification(
                title="Smart Card Removed",
                body=body_msg,
                urgency="normal" if locked else "low",
            )
