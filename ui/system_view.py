"""System Components and Browser Manager View for Sentinel v2."""

import os
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core import __version__
from core.platform_detector import detect_platform, PlatformInfo
from core.smartcard import SmartCardStatus
from core.certificates import is_system_trust_installed
from core.updater import check_for_updates, perform_update, UpdateInfo
from core.browsers import (
    check_browsers_status,
    configure_all_browsers,
    configure_chrome_nssdb,
    find_opensc_module,
)


class SystemView(Gtk.Box):
    def __init__(self, main_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_window = main_window
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.set_vexpand(True)
        self.scrolled.set_hexpand(True)

        self.clamp = Adw.Clamp()
        self.clamp.set_maximum_size(1000)
        self.clamp.set_tightening_threshold(800)
        self.clamp.set_hexpand(True)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.clamp.set_child(self.content_box)
        self.scrolled.set_child(self.clamp)
        self.append(self.scrolled)

        self.setup_ui()

    def setup_ui(self):
        # 1. System Services Group
        self.svc_group = Adw.PreferencesGroup()
        self.svc_group.set_title("Middleware and System Services")

        # pcscd row
        self.pcscd_row = Adw.ActionRow(title="Smart Card Daemon (pcscd)")
        self.pcscd_row.set_subtitle("Required for USB smart card reader communication")
        self.pcscd_badge = Gtk.Label(label="Checking")
        self.pcscd_badge.add_css_class("badge-info")
        self.pcscd_row.add_suffix(self.pcscd_badge)

        self.pcscd_btn = Gtk.Button(label="Start")
        self.pcscd_btn.add_css_class("flat")
        self.pcscd_btn.connect("clicked", self.on_start_pcscd)
        self.pcscd_row.add_suffix(self.pcscd_btn)
        self.svc_group.add(self.pcscd_row)

        # OpenSC row
        self.opensc_row = Adw.ActionRow(title="OpenSC Middleware")
        self.opensc_row.set_subtitle("Provides PKCS#11 module for CAC / PIV tokens")
        self.opensc_badge = Gtk.Label(label="Checking")
        self.opensc_badge.add_css_class("badge-info")
        self.opensc_row.add_suffix(self.opensc_badge)
        self.svc_group.add(self.opensc_row)

        # Reader hang fix row
        self.reader_fix_row = Adw.ActionRow(title="Broadcom 58200 Reader Hang Fix")
        self.reader_fix_row.set_subtitle("Restricts OpenSC drivers to bypass 26s APDU freeze")
        self.reader_fix_badge = Gtk.Label(label="Checking")
        self.reader_fix_badge.add_css_class("badge-info")
        self.reader_fix_row.add_suffix(self.reader_fix_badge)

        self.reader_fix_btn = Gtk.Button(label="Optimize")
        self.reader_fix_btn.add_css_class("flat")
        self.reader_fix_btn.connect("clicked", self.on_fix_reader)
        self.reader_fix_row.add_suffix(self.reader_fix_btn)
        self.svc_group.add(self.reader_fix_row)

        self.content_box.append(self.svc_group)

        # 2. Certificates Group
        self.cert_group = Adw.PreferencesGroup()
        self.cert_group.set_title("DoD Certificate Authority Store")
        self.cert_group.set_description("Installs DoD Root CAs into system trust and intermediate CAs into browser NSS stores:")

        self.sys_cert_row = Adw.ActionRow(title="System CA Trust Store")
        self.sys_cert_row.set_subtitle("DoD Root CA 3, 4, 5, 6 (System Trust) + DoD ID/Email CAs (Browser NSS)")
        self.sys_cert_badge = Gtk.Label(label="Checking")
        self.sys_cert_badge.add_css_class("badge-info")
        self.sys_cert_row.add_suffix(self.sys_cert_badge)

        self.sys_cert_btn = Gtk.Button(label="Install CAs")
        self.sys_cert_btn.add_css_class("flat")
        self.sys_cert_btn.connect("clicked", self.on_install_certs)
        self.sys_cert_row.add_suffix(self.sys_cert_btn)
        self.cert_group.add(self.sys_cert_row)

        self.content_box.append(self.cert_group)

        # 3. Browsers Group
        self.browser_group = Adw.PreferencesGroup()
        self.browser_group.set_title("Browser Integration (The Fix)")
        self.browser_group.set_description(
            "Loads PKCS#11 module and enables 'Ask Every Time' certificate prompting so .mil sites request your CAC:"
        )

        # Firefox row
        self.ff_row = Adw.ActionRow(title="Mozilla Firefox")
        self.ff_row.set_subtitle("Enterprise Policies, pkcs11.txt, user.js prompt setting")
        self.ff_badge = Gtk.Label(label="Checking")
        self.ff_badge.add_css_class("badge-info")
        self.ff_row.add_suffix(self.ff_badge)

        self.ff_btn = Gtk.Button(label="Configure")
        self.ff_btn.add_css_class("flat")
        self.ff_btn.connect("clicked", self.on_configure_firefox)
        self.ff_row.add_suffix(self.ff_btn)
        self.browser_group.add(self.ff_row)

        # Chrome row
        self.chrome_row = Adw.ActionRow(title="Google Chrome / Chromium / Edge")
        self.chrome_row.set_subtitle("~/.pki/nssdb security device registration and root CA import")
        self.chrome_badge = Gtk.Label(label="Checking")
        self.chrome_badge.add_css_class("badge-info")
        self.chrome_row.add_suffix(self.chrome_badge)

        self.chrome_btn = Gtk.Button(label="Configure")
        self.chrome_btn.add_css_class("flat")
        self.chrome_btn.connect("clicked", self.on_configure_chrome)
        self.chrome_row.add_suffix(self.chrome_btn)
        self.browser_group.add(self.chrome_row)

        self.content_box.append(self.browser_group)

        # 4. Workstation Session Security
        self.logon_group = Adw.PreferencesGroup()
        self.logon_group.set_title("Workstation Session Security")
        self.logon_group.set_description(
            "Automatically lock your desktop session when your smart card is removed from the reader."
        )

        self.lock_removal_row = Adw.ActionRow(title="Lock Screen on Smart Card Removal")
        self.lock_removal_row.set_subtitle("Automatically lock desktop session when CAC is removed")
        self.lock_removal_switch = Gtk.Switch()
        self.lock_removal_switch.set_valign(Gtk.Align.CENTER)
        self.lock_removal_switch.connect("state-set", self.on_lock_removal_switch_toggled)
        self.lock_removal_row.add_suffix(self.lock_removal_switch)
        self.logon_group.add(self.lock_removal_row)

        self.content_box.append(self.logon_group)

        # 5. Application Version & Updates
        self.update_group = Adw.PreferencesGroup()
        self.update_group.set_title("Application Version & Updates")
        self.update_group.set_description(
            "Check for verified Sentinel releases from GitHub (pinned tags and SHA-256 checksum verification)."
        )

        self.update_row = Adw.ActionRow(title=f"Sentinel v{__version__}")
        self.update_row.set_subtitle("Release channel: GitHub Releases (SHA-256 verified)")
        self.update_badge = Gtk.Label(label=f"v{__version__}")
        self.update_badge.add_css_class("badge-info")
        self.update_row.add_suffix(self.update_badge)

        self.check_update_btn = Gtk.Button(label="Check for Updates")
        self.check_update_btn.add_css_class("flat")
        self.check_update_btn.connect("clicked", self.on_check_updates)
        self.update_row.add_suffix(self.check_update_btn)
        self.update_group.add(self.update_row)

        self.content_box.append(self.update_group)
        self._latest_update_info: UpdateInfo | None = None

    def update_status(self, plat: PlatformInfo, card_stat: SmartCardStatus):
        b_stat = check_browsers_status()
        certs_installed = is_system_trust_installed(plat)

        # 1. pcscd status
        if card_stat.service_active:
            self.pcscd_badge.set_label("Running")
            self.pcscd_badge.remove_css_class("badge-warning")
            self.pcscd_badge.add_css_class("badge-success")
            self.pcscd_btn.set_visible(False)
        else:
            self.pcscd_badge.set_label("Stopped")
            self.pcscd_badge.remove_css_class("badge-success")
            self.pcscd_badge.add_css_class("badge-warning")
            self.pcscd_btn.set_visible(True)

        # 2. OpenSC module
        mod = find_opensc_module()
        if mod:
            self.opensc_row.set_subtitle(f"Module found: {mod}")
            self.opensc_badge.set_label("Installed")
            self.opensc_badge.remove_css_class("badge-danger")
            self.opensc_badge.add_css_class("badge-success")
        else:
            self.opensc_row.set_subtitle("opensc-pkcs11.so not found on system")
            self.opensc_badge.set_label("Missing")
            self.opensc_badge.remove_css_class("badge-success")
            self.opensc_badge.add_css_class("badge-danger")

        # 3. Reader hang fix
        from core.system_fix import is_opensc_config_optimized
        hang_fixed = False
        for c in ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]:
            if os.path.isfile(c):
                try:
                    with open(c, "r", encoding="utf-8", errors="replace") as f:
                        if is_opensc_config_optimized(f.read()):
                            hang_fixed = True
                            break
                except OSError:
                    pass
        if hang_fixed:
            self.reader_fix_badge.set_label("Optimized")
            self.reader_fix_badge.remove_css_class("badge-warning")
            self.reader_fix_badge.add_css_class("badge-success")
            self.reader_fix_btn.set_visible(False)
        else:
            self.reader_fix_badge.set_label("Unoptimized")
            self.reader_fix_badge.remove_css_class("badge-success")
            self.reader_fix_badge.add_css_class("badge-warning")
            self.reader_fix_btn.set_visible(True)

        # 4. System CA Trust
        from core.ca_manifest import check_bundled_ca_expirations, get_certs_dir
        ca_exp_stat = check_bundled_ca_expirations(get_certs_dir())
        if certs_installed:
            if ca_exp_stat["expired"]:
                self.sys_cert_badge.set_label("Installed (CAs Expired)")
                self.sys_cert_badge.remove_css_class("badge-success")
                self.sys_cert_badge.add_css_class("badge-warning")
            elif ca_exp_stat["expiring_soon"]:
                self.sys_cert_badge.set_label("Installed (Expiring Soon)")
                self.sys_cert_badge.remove_css_class("badge-warning")
                self.sys_cert_badge.add_css_class("badge-success")
            else:
                self.sys_cert_badge.set_label("Installed (DoD Roots)")
                self.sys_cert_badge.remove_css_class("badge-warning")
                self.sys_cert_badge.add_css_class("badge-success")
            self.sys_cert_btn.set_label("Reinstall")
        else:
            self.sys_cert_badge.set_label("Missing")
            self.sys_cert_badge.remove_css_class("badge-success")
            self.sys_cert_badge.add_css_class("badge-warning")
            self.sys_cert_btn.set_label("Install CAs")

        # 5. Firefox status
        if b_stat.firefox_prompt_configured and b_stat.firefox_module_loaded:
            self.ff_badge.set_label("Configured")
            self.ff_badge.remove_css_class("badge-warning")
            self.ff_badge.add_css_class("badge-success")
            self.ff_row.set_subtitle(
                f"Prompt: 'Ask Every Time' active | {b_stat.firefox_profiles_count} profile(s) ready"
            )
        else:
            self.ff_badge.set_label("Setup Needed")
            self.ff_badge.remove_css_class("badge-success")
            self.ff_badge.add_css_class("badge-warning")
            self.ff_row.set_subtitle("Security module not loaded or prompt not set to 'Ask Every Time'")

        # 6. Chrome status
        if b_stat.chrome_module_loaded:
            self.chrome_badge.set_label("Configured")
            self.chrome_badge.remove_css_class("badge-warning")
            self.chrome_badge.add_css_class("badge-success")
            self.chrome_row.set_subtitle("~/.pki/nssdb module loaded and DoD certificates trusted")
        else:
            self.chrome_badge.set_label("Setup Needed")
            self.chrome_badge.remove_css_class("badge-success")
            self.chrome_badge.add_css_class("badge-warning")
            self.chrome_row.set_subtitle("Smart card module not registered in ~/.pki/nssdb")

        # 7. Workstation Session Lock on Removal
        from core.system_fix import check_smartcard_logon_status
        l_stat = check_smartcard_logon_status()
        self.lock_removal_switch.set_active(l_stat["lock_removal_enabled"])

    def on_start_pcscd(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_start_pcscd, daemon=True).start()

    def _run_start_pcscd(self):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--service"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "pcscd service started", msg)

    def on_fix_reader(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_fix_reader, daemon=True).start()

    def _run_fix_reader(self):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--reader-fix"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "Reader hang fix applied", msg)

    def on_install_certs(self, btn):
        btn.set_sensitive(False)
        plat = detect_platform()
        threading.Thread(target=self._run_install_certs, args=(plat.family,), daemon=True).start()

    def _run_install_certs(self, family: str):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--certs", "--family", family], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "DoD certificates installed into system trust", msg)

    def on_configure_firefox(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_configure_firefox, daemon=True).start()

    def _run_configure_firefox(self):
        res = configure_all_browsers(log_fn=self.main_window.append_log)
        ok = res.get("firefox_ok", False)
        GLib.idle_add(self._after_action, ok, "Firefox configured with 'Ask Every Time' and DoD CAC", "")

    def on_configure_chrome(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_configure_chrome, daemon=True).start()

    def _run_configure_chrome(self):
        mod = find_opensc_module() or "/usr/lib64/opensc-pkcs11.so"
        ok, msg = configure_chrome_nssdb(mod, log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "Chrome / Edge NSS DB configured", msg)

    def _after_action(self, ok: bool, title: str, msg: str):
        self.main_window.show_toast(title if ok else f"Action failed: {msg}")
        self.main_window.refresh_all_status(force=True)

    def on_lock_removal_switch_toggled(self, switch, state):
        from core.system_fix import set_lock_on_removal
        set_lock_on_removal(state, log_fn=self.main_window.append_log)
        action_name = "enabled" if state else "disabled"
        self.main_window.show_toast(f"Screen lock on smart card removal {action_name}.")
        return False

    def on_check_updates(self, btn):
        if self._latest_update_info and self._latest_update_info.update_available:
            self._prompt_confirm_update(self._latest_update_info)
            return

        btn.set_sensitive(False)
        btn.set_label("Checking...")
        threading.Thread(target=self._run_check_updates, daemon=True).start()

    def _run_check_updates(self):
        info = check_for_updates()
        GLib.idle_add(self._after_check_updates, info)

    def _after_check_updates(self, info: UpdateInfo):
        self._latest_update_info = info
        self.check_update_btn.set_sensitive(True)
        self.update_row.set_subtitle(info.status_message)

        self.update_badge.remove_css_class("badge-info")
        self.update_badge.remove_css_class("badge-success")
        self.update_badge.remove_css_class("badge-warning")

        if info.update_available:
            self.update_badge.set_label(f"Update: {info.tag_name}")
            self.update_badge.add_css_class("badge-warning")
            self.check_update_btn.set_label("Install Update" if info.expected_sha256 else "View Release")
            self.check_update_btn.remove_css_class("flat")
            self.check_update_btn.add_css_class("suggested-action")
            self.main_window.show_toast(info.status_message)
            self._prompt_confirm_update(info)
        elif info.error:
            self.update_badge.set_label(f"v{__version__}")
            self.update_badge.add_css_class("badge-info")
            self.check_update_btn.set_label("Check for Updates")
            self.main_window.show_toast(info.status_message)
        else:
            self.update_badge.set_label("Up to Date")
            self.update_badge.add_css_class("badge-success")
            self.check_update_btn.set_label("Check for Updates")
            self.main_window.show_toast(f"Sentinel v{__version__} is up to date.")

    def _prompt_confirm_update(self, info: UpdateInfo):
        sha_note = info.expected_sha256 if info.expected_sha256 else "See release page SHA256SUMS"
        dialog = Adw.MessageDialog.new(
            self.main_window,
            f"Update Available ({info.tag_name})",
            f"A newer release ({info.tag_name}) is available on GitHub.\n\n"
            f"Installed version: v{info.current_version}\n"
            f"Latest release: {info.tag_name}\n"
            f"SHA-256: {sha_note}\n\n"
            f"Updates are verified against the release SHA-256 digest before transactional staging.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("open", "Open Release Page")
        if info.expected_sha256 and info.download_url:
            dialog.add_response("update", f"Update to {info.tag_name}")
            dialog.set_response_appearance("update", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("update")
        else:
            dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("open")
        dialog.set_close_response("cancel")

        def _on_response(dlg, response_id):
            if response_id == "open":
                self.main_window.diagnostics_view.open_url(info.html_url)
            elif response_id == "update":
                self.check_update_btn.set_sensitive(False)
                self.check_update_btn.set_label("Updating...")
                threading.Thread(target=self._run_perform_update, args=(info,), daemon=True).start()

        dialog.connect("response", _on_response)
        dialog.present()

    def _run_perform_update(self, info: UpdateInfo):
        ok, msg = perform_update(info, log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_perform_update, ok, msg, info)

    def _after_perform_update(self, ok: bool, msg: str, info: UpdateInfo):
        self.check_update_btn.set_sensitive(True)
        self.update_row.set_subtitle(msg)
        self.main_window.show_toast(msg)
        if ok:
            self._latest_update_info = None
            self.update_badge.remove_css_class("badge-warning")
            self.update_badge.add_css_class("badge-success")
            self.update_badge.set_label(f"Updated ({info.tag_name})")
            self.check_update_btn.set_label("Restart Required")
        else:
            self.check_update_btn.set_label("Retry Update")
