"""Command Line Interface for Sentinel v2."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
from typing import Optional

from core import __version__


def _clean_term(text: Optional[str], default: str = "Unknown") -> str:
    """Sanitize strings for terminal output to prevent control sequence injection (CWE-150)."""
    if not text:
        return default
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(text))


ASCII_BANNER = r"""
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) / 
  /___/\__/_//_/\__/_/_//_/\__/_/  
"""


def print_banner():
    print(ASCII_BANNER.rstrip("\n"))
    print(f"       DoD CAC Identity and Middleware Automator (v{__version__})\n")


def cmd_status():
    from core.platform_detector import detect_platform
    from core.smartcard import scan_smartcard
    from core.browsers import check_browsers_status
    from core.certificates import is_system_trust_installed
    from core.system_fix import check_missing_packages
    from core.rust_bridge import is_rust_available, get_rust_version

    plat = detect_platform()
    card_stat = scan_smartcard()
    b_stat = check_browsers_status()
    certs_installed = is_system_trust_installed(plat)
    missing = check_missing_packages(plat)

    print("-" * 65)
    print(f" SYSTEM DIAGNOSTICS: {plat.name} ({plat.family})")
    print("-" * 65)
    print(f"  Package Manager:       {plat.package_manager}")
    print(f"  Missing Dependencies:  {', '.join(missing) if missing else 'None (All Installed)'}")
    rust_stat = f"[RUST v{get_rust_version()}]" if is_rust_available() else "[PYTHON FALLBACK]"
    print(f"  Native Core Engine:    {rust_stat}")
    print(f"  PCSC Daemon (pcscd):   {'[ACTIVE]' if card_stat.service_active else '[INACTIVE]'}")
    print(f"  DoD System Trust:      {'[INSTALLED]' if certs_installed else '[NOT INSTALLED]'}")
    from core.ca_manifest import check_bundled_ca_expirations, get_certs_dir
    ca_exp_stat = check_bundled_ca_expirations(get_certs_dir())
    if ca_exp_stat["expired"]:
        ca_summary = f"[WARNING: {len(ca_exp_stat['expired'])} EXPIRED]"
    elif ca_exp_stat["expiring_soon"]:
        ca_summary = f"[NOTICE: {len(ca_exp_stat['expiring_soon'])} EXPIRING SOON]"
    else:
        ca_summary = f"[VALID: {len(ca_exp_stat['valid'])} UNEXPIRED]"
    print(f"  Bundled DoD CAs:       {ca_summary}")
    print(f"  Firefox Profiles:      {b_stat.firefox_profiles_count} detected")
    print(f"  Firefox Policy:        {'[ACTIVE]' if b_stat.firefox_policy_active else '[NOT CONFIGURED]'}")
    print(f"  Firefox Prompting:     {'[Ask Every Time]' if b_stat.firefox_prompt_configured else '[Select Auto]'}")
    print(f"  Firefox CAC Module:    {'[LOADED]' if b_stat.firefox_module_loaded else '[NOT LOADED]'}")
    print(f"  Chrome / Edge NSS DB:  {'[CONFIGURED]' if b_stat.chrome_module_loaded else '[NOT CONFIGURED]'}")
    if b_stat.snap_firefox_detected:
        print(f"  Snap Firefox:          {'[CONNECTED]' if b_stat.snap_connected else '[DISCONNECTED]'}")

    from core.system_fix import check_smartcard_logon_status, check_scdaemon_conflict
    logon_info = check_smartcard_logon_status()
    lock_str = "[ACTIVE]" if logon_info["lock_removal_enabled"] else "[INACTIVE]"
    print(f"  Lock on Removal:       {lock_str}")
    scd_conflict, _ = check_scdaemon_conflict()
    scd_str = "[CONFLICT: LOCK DETECTED]" if scd_conflict else "[NO CONFLICT]"
    print(f"  GnuPG scdaemon Lock:   {scd_str}")

    print("-" * 65)
    print(" SMART CARD HARDWARE")
    print("-" * 65)
    print(f"  Reader:                {_clean_term(card_stat.reader_name, 'No smart card reader found')}")
    print(f"  Card Inserted:         {'YES' if card_stat.card_present else 'NO'}")
    if card_stat.card_present:
        print(f"  Card Type:             {_clean_term(card_stat.card_name, 'Common Access Card')}")
        print(f"  Token Label:           {_clean_term(card_stat.token_label)}")
        print(f"  Cardholder Name:       {_clean_term(card_stat.primary_certificate.holder_name if card_stat.primary_certificate else None)}")
        print(f"  EDIPI / DoD ID:        {_clean_term(card_stat.primary_certificate.edipi if card_stat.primary_certificate else None)}")
        print(f"  ATR:                   {_clean_term(card_stat.atr, 'N/A')}")
        if card_stat.pin_locked:
            print("  PIN Status:            [LOCKED] (Contact servicing ID Card facility)")
        elif card_stat.pin_retries_remaining is not None:
            print(f"  PIN Status:            {card_stat.pin_retries_remaining} verification retries remaining")
        elif card_stat.pin_status_msg:
            print(f"  PIN Status:            {_clean_term(card_stat.pin_status_msg)}")
        print(f"  On-Card Certificates:  {len(card_stat.certificates)}")
        for c in card_stat.certificates:
            print(f"    * [{_clean_term(c.id)}] {_clean_term(c.label)}: Issuer: {_clean_term(c.issuer_cn)} | {_clean_term(c.status_text)}")
    print("-" * 65)


def cmd_card_info():
    from core.smartcard import scan_smartcard

    card_stat = scan_smartcard()
    if not card_stat.card_present:
        print("No smart card detected in reader.")
        return
    print("\n--- Inserted Smart Card Details ---")
    print(f"Reader:          {_clean_term(card_stat.reader_name, 'Unknown')}")
    print(f"Card Model:      {_clean_term(card_stat.card_name, 'Unknown')}")
    print(f"Token Serial:    {_clean_term(card_stat.token_serial, 'Unknown')}")
    print(f"Token Label:     {_clean_term(card_stat.token_label, 'Unknown')}")
    if card_stat.pin_locked:
        print("PIN Status:      [LOCKED] (RAPIDS/DEERS unblock required)")
    elif card_stat.pin_retries_remaining is not None:
        print(f"PIN Status:      {card_stat.pin_retries_remaining} retries remaining")
    elif card_stat.pin_status_msg:
        print(f"PIN Status:      {_clean_term(card_stat.pin_status_msg)}")
    print(f"\n--- Certificates ({len(card_stat.certificates)}) ---")
    for c in card_stat.certificates:
        print(f"  Object ID:     {_clean_term(c.id, 'N/A')}")
        print(f"  Label:         {_clean_term(c.label, 'Unknown')}")
        print(f"  Subject:       {_clean_term(c.subject, 'Unknown')}")
        print(f"  Holder Name:   {_clean_term(c.holder_name, 'Unknown')}")
        print(f"  EDIPI:         {_clean_term(c.edipi, 'Unknown')}")
        print(f"  Issuer:        {_clean_term(c.issuer, 'Unknown')}")
        print(f"  Validity:      {_clean_term(c.valid_to_str, 'Unknown')} ({_clean_term(c.status_text, 'Unknown')})")
        print(f"  Usage:         {_clean_term(c.usage, 'Unknown')}")
        print("  " + "-" * 40)


def cmd_setup() -> bool:
    from core.system_fix import run_full_setup

    print("Initiating Full Automated DoD CAC Setup...")
    res = run_full_setup(
        progress_callback=lambda frac, msg: print(f"[{int(frac * 100)}%] {msg}"),
        log_callback=lambda msg: print(f"  {msg}"),
    )
    if res["success"]:
        print("\nSUCCESS: DoD CAC setup completed successfully!")
        print("Open Firefox or Chrome and navigate to your .mil portal.")
        return True
    else:
        print(f"\nFAILED: {res['message']}")
        return False


def cmd_pin_status() -> int:
    from core.smartcard import scan_smartcard
    card_stat = scan_smartcard()
    if not card_stat.card_present:
        print("[-] No smart card detected in reader.")
        return 1
    if card_stat.pin_locked:
        print("[-] PIV PIN is LOCKED. Cardholder must visit a RAPIDS/DEERS facility to unblock.")
        return 2
    if card_stat.pin_retries_remaining is not None:
        print(f"[+] PIV PIN verification retries remaining: {card_stat.pin_retries_remaining}")
        return 0
    print(f"[-] PIN status unverified: {card_stat.pin_status_msg or 'Communication failure'}")
    return 1


def cmd_change_pin() -> bool:
    import getpass
    from core.rust_bridge import PinBuffer
    from core.smartcard import scan_smartcard, change_card_pin

    card_stat = scan_smartcard(force_refresh=True)
    if not card_stat.card_present:
        print("[-] No smart card detected in reader.")
        return False

    if card_stat.pin_locked:
        print("[-] PIV PIN is LOCKED. Cardholder must visit a RAPIDS/DEERS facility to unblock.")
        return False

    if card_stat.pin_retries_remaining == 1:
        print(
            "[-] Refusing automated PIN change: only 1 PIN retry attempt remains.\n"
            "    Authenticate once or use a PUK-capable tool to prevent card lockout."
        )
        return False

    if card_stat.pin_retries_remaining is not None:
        print(f"[*] Card detected with {card_stat.pin_retries_remaining} verification retries remaining.")
        if card_stat.pin_retries_remaining == 2:
            print(
                "[!] WARNING: Only 2 PIN verification retries remain on this token.\n"
                "    An incorrect current PIN will drop the counter to 1 retry."
            )
            try:
                ans = input("Type 'YES' to proceed with PIV PIN change: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                return False
            if ans != "YES":
                print("[-] PIN change cancelled.")
                return False

    curr_buf = None
    new_buf = None
    try:
        curr_pin = getpass.getpass("Enter current PIV PIN: ").strip()
        curr_buf = PinBuffer(curr_pin)
        if not curr_pin or not curr_buf.is_valid_pin_format():
            print("[-] Error: Current PIN must be 6 to 8 numeric digits.")
            return False

        new_pin = getpass.getpass("Enter new PIV PIN (6-8 digits): ").strip()
        new_buf = PinBuffer(new_pin)
        if not new_buf.is_valid_pin_format():
            print("[-] Error: New PIV PIN must be 6 to 8 numeric digits.")
            return False

        if curr_pin == new_pin:
            print("[-] Error: New PIN must be different from current PIN.")
            return False

        confirm_pin = getpass.getpass("Confirm new PIV PIN: ").strip()
        if new_pin != confirm_pin:
            print("[-] Error: Confirmation PIN does not match.")
            return False

        print("[*] Transmitting CHANGE REFERENCE DATA APDU to smart card...")
        ok, _retries, msg = change_card_pin(curr_pin, new_pin, card_stat.reader_name)
        if ok:
            print(f"[+] SUCCESS: {msg}")
            return True
        else:
            print(f"[-] FAILED: {msg}")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        return False
    finally:
        if curr_buf is not None:
            curr_buf.scrub()
        if new_buf is not None:
            new_buf.scrub()


def cmd_agent():
    from core.agent import run_agent
    print("[*] Starting Sentinel background event monitor...")
    print("[*] Monitoring reader insertion and removal events (Ctrl+C to exit)...")
    run_agent()


def cmd_install_agent() -> bool:
    from core.agent import install_systemd_user_service
    print("[*] Configuring user systemd daemon for Sentinel...")
    ok, msg = install_systemd_user_service(log_fn=print)
    if ok:
        print(f"[+] SUCCESS: {msg}")
    else:
        print(f"[-] FAILED: {msg}")
    return ok


def cmd_lock_on_removal(enabled: bool) -> bool:
    from core.system_fix import set_lock_on_removal
    action_str = "enabling" if enabled else "disabling"
    print(f"[*] {action_str.capitalize()} screen lock on smart card removal...")
    ok, msg = set_lock_on_removal(enabled, log_fn=print)
    if ok:
        print(f"[+] SUCCESS: {msg}")
    else:
        print(f"[-] FAILED: {msg}")
    return ok


def cmd_export_certs(target_dir: str) -> bool:
    import base64
    from core.smartcard import scan_smartcard

    out_dir = Path(target_dir).resolve()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[-] Error creating output directory {out_dir}: {e}")
        return False

    print("[*] Scanning smart card for digital certificates...")
    status = scan_smartcard(force_refresh=True)
    if not status.card_present:
        print("[-] No smart card detected in reader.")
        return False
    if not status.certificates:
        print("[-] No digital certificates found on card.")
        return False

    exported = 0
    for cert in status.certificates:
        if not cert.raw_der:
            continue
        clean_holder = re.sub(r"[^a-zA-Z0-9_-]", "_", cert.holder_name or "CAC").strip("_")
        clean_label = re.sub(r"[^a-zA-Z0-9_-]", "_", cert.label or f"Cert_{cert.id}").strip("_")
        filename = f"{clean_holder}_{clean_label}.pem"
        file_path = out_dir / filename

        b64 = base64.b64encode(cert.raw_der).decode("ascii")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        pem_content = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

        try:
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(file_path), flags, 0o644)
            with open(fd, "wb") as f:
                f.write(pem_content.encode("utf-8"))
            print(f"[+] Exported: {cert.label} ({cert.id}) -> {file_path}")
            exported += 1
        except Exception as e:
            print(f"[-] Failed to write {filename}: {e}")

    if exported > 0:
        print(f"[+] Successfully exported {exported} certificate(s) to {out_dir}")
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Sentinel - Automated DoD CAC Manager for Linux")
    parser.add_argument("--version", "-v", action="version", version=f"Sentinel v{__version__}")
    parser.add_argument("--status", "--check", action="store_true", help="display system and card status")
    parser.add_argument("--setup-all", "--automate", action="store_true", help="run full automated setup")
    parser.add_argument("--card-info", action="store_true", help="display details of inserted smart card")
    parser.add_argument("--pin-status", action="store_true", help="display PIV PIN verification retry counter")
    parser.add_argument("--change-pin", action="store_true", help="interactively change PIV smart card PIN")
    parser.add_argument("--lock-on-removal", action="store_true", help="enable automatic screen lock when card is removed")
    parser.add_argument("--no-lock-on-removal", action="store_true", help="disable screen lock when card is removed")
    parser.add_argument("--agent", action="store_true", help="run background smart card event monitor daemon")
    parser.add_argument("--install-agent", action="store_true", help="install and enable user systemd service for agent")
    parser.add_argument("--browsers", action="store_true", help="configure Firefox and Chrome browsers only")
    parser.add_argument("--certs", action="store_true", help="install DoD certificates only")
    parser.add_argument("--reader-fix", action="store_true", help="apply Broadcom reader hang fix only")
    parser.add_argument("--scdaemon-fix", action="store_true", help="configure GnuPG scdaemon with disable-ccid to resolve reader lock conflict")
    parser.add_argument("--export-certs", nargs="?", const=".", metavar="DIR", help="export digital certificates from inserted CAC to directory (default: current dir)")
    parser.add_argument("--gui", action="store_true", help="launch graphical interface")
    parser.add_argument("--installer", action="store_true", help="launch graphical setup wizard")
    parser.add_argument("--check-update", action="store_true", help="check GitHub Releases for a newer version")
    parser.add_argument("--update", action="store_true", help="verify SHA-256 and install latest GitHub release")
    parser.add_argument("--uninstall", action="store_true", help="revert system changes and uninstall Sentinel")

    args = parser.parse_args()

    if args.installer:
        try:
            from ui.installer_window import run_installer_gui
            run_installer_gui()
            sys.exit(0)
        except (ImportError, ValueError) as err:
            print(f"[-] Error: Could not launch setup wizard ({err}).")
            print("[-] Required GUI libraries (GTK4 / Libadwaita / PyGObject) are not installed.")
            print("[-] Run './install' to install all system dependencies.")
            sys.exit(1)

    if args.gui:
        try:
            from ui.app import run_gui
            run_gui()
            sys.exit(0)
        except (ImportError, ValueError) as err:
            print(f"[-] Error: Could not launch GUI ({err}).")
            print("[-] Required GUI libraries (GTK4 / Libadwaita / PyGObject) are not installed.")
            print("[-] Run './install' to install all system dependencies.")
            sys.exit(1)

    print_banner()

    if args.uninstall:
        from core.system_fix import run_full_uninstall
        ok = run_full_uninstall(log_callback=print)
        sys.exit(0 if ok else 1)
    elif args.check_update or args.update:
        from core.updater import check_for_updates, perform_update
        info = check_for_updates()
        print(f"Current version: v{info.current_version}")
        print(f"Latest release:  {info.tag_name}")
        print(f"Status:          {_clean_term(info.status_message)}")
        if info.update_available:
            print(f"Release URL:     {_clean_term(info.html_url)}")
            if info.expected_sha256:
                print(f"Expected SHA256: {_clean_term(info.expected_sha256)}")
            if args.update:
                ok_upd, msg_upd = perform_update(info, log_fn=print)
                sys.exit(0 if ok_upd else 1)
            else:
                print("Run 'python3 cli.py --update' or './install' to apply the verified release.")
        sys.exit(0 if not info.error else 1)
    elif args.setup_all:
        ok = cmd_setup()
        sys.exit(0 if ok else 1)
    elif args.status:
        cmd_status()
        sys.exit(0)
    elif args.card_info:
        cmd_card_info()
        sys.exit(0)
    elif args.export_certs is not None:
        ok = cmd_export_certs(args.export_certs)
        sys.exit(0 if ok else 1)
    elif args.pin_status:
        rc = cmd_pin_status()
        sys.exit(rc)
    elif args.change_pin:
        ok = cmd_change_pin()
        sys.exit(0 if ok else 1)
    elif args.lock_on_removal:
        ok = cmd_lock_on_removal(True)
        sys.exit(0 if ok else 1)
    elif args.no_lock_on_removal:
        ok = cmd_lock_on_removal(False)
        sys.exit(0 if ok else 1)
    elif args.agent:
        cmd_agent()
        sys.exit(0)
    elif args.install_agent:
        ok = cmd_install_agent()
        sys.exit(0 if ok else 1)
    elif args.browsers:
        from core.browsers import configure_all_browsers
        print("Configuring browsers...")
        res = configure_all_browsers(log_fn=print)
        sys.exit(0 if not res.get("errors") else 1)
    elif args.certs:
        from core.certificates import is_system_trust_installed
        from core.platform_detector import detect_platform
        from core.system_fix import run_privileged_helper
        plat = detect_platform()
        ok, _ = run_privileged_helper(["--certs", "--family", plat.family], log_fn=print)
        sys.exit(0 if (ok and is_system_trust_installed(plat)) else 1)
    elif args.reader_fix:
        from core.system_fix import run_privileged_helper
        ok, _ = run_privileged_helper(["--reader-fix"], log_fn=print)
        sys.exit(0 if ok else 1)
    elif args.scdaemon_fix:
        from core.system_fix import fix_scdaemon_conflict
        ok, msg = fix_scdaemon_conflict(log_fn=print)
        print(f"[{'+' if ok else '-'}] {msg}")
        sys.exit(0 if ok else 1)
    else:
        # Default when run without args in terminal: show status or launch GUI if DISPLAY is available
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            try:
                from ui.app import run_gui
                run_gui()
                sys.exit(0)
            except Exception as e:
                print(f"Could not initialize GUI ({e}). Falling back to CLI status:\n")
                cmd_status()
                sys.exit(0)
        else:
            cmd_status()
            sys.exit(0)


if __name__ == "__main__":
    main()
