"""Graphical Installer Wizard for Sentinel v2 (ActivClient for Linux).
Provides a modern Windows-like setup wizard experience with Libadwaita / GTK4.
"""

from __future__ import annotations

import os
import subprocess
import sys
import platform as sys_platform
import threading
from typing import List

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core.platform_detector import detect_platform, PlatformInfo, find_opensc_module
from core.smartcard import scan_smartcard
from core.browsers import configure_all_browsers
from core.system_fix import (
    run_privileged_helper,
    check_missing_packages,
    install_desktop_integration,
)

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel.png")
if not os.path.isfile(ICON_PATH):
    ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel_cac_manager.png")
CSS_PATH = os.path.join(SCRIPT_DIR, "ui", "style.css")


class InstallerWindow(Adw.Window):
    def __init__(self, app: Adw.Application):
        super().__init__(application=app)
        self.set_title("Sentinel Setup")
        self.set_default_size(780, 620)
        self.set_modal(True)

        self.platform: PlatformInfo = detect_platform()
        self.log_lines: List[str] = []

        # Load style sheet
        self._load_styles()

        # Ensure installer styling aligns with the dark cybersecurity theme
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.PREFER_DARK)

        # Build UI layout
        self._build_ui()

    def _load_styles(self):
        if os.path.isfile(CSS_PATH):
            provider = Gtk.CssProvider()
            try:
                provider.load_from_path(CSS_PATH)
                Gtk.StyleContext.add_provider_for_display(
                    self.get_display(),
                    provider,
                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
                )
            except Exception as e:
                print(f"Error loading CSS: {e}")

    def _build_ui(self):
        # Root container
        root_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(root_box)

        # HeaderBar
        self.header_bar = Adw.HeaderBar()
        self.header_bar.set_show_end_title_buttons(True)
        self.header_bar.set_show_start_title_buttons(False)

        title_widget = Adw.WindowTitle(
            title="Sentinel",
            subtitle="Setup Wizard",
        )
        self.header_bar.set_title_widget(title_widget)
        root_box.append(self.header_bar)

        # Main ViewStack
        self.stack = Adw.ViewStack()
        self.stack.set_vexpand(True)
        self.stack.set_hexpand(True)
        root_box.append(self.stack)

        # Build Wizard Pages
        self._build_welcome_page()
        self._build_options_page()
        self._build_installing_page()
        self._build_finish_page()
        self._build_error_page()

        # Start at Welcome page
        self.stack.set_visible_child_name("welcome")

    # --------------------------------------------------------------------------
    # Page 1: Welcome Screen
    # --------------------------------------------------------------------------
    def _build_welcome_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        page.set_margin_top(28)
        page.set_margin_bottom(24)
        page.set_margin_start(36)
        page.set_margin_end(36)

        # Hero Banner
        hero_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        hero_box.add_css_class("hero-card")

        if os.path.isfile(ICON_PATH):
            try:
                icon_img = Gtk.Image.new_from_file(ICON_PATH)
                icon_img.set_pixel_size(84)
                hero_box.append(icon_img)
            except Exception:
                pass

        hero_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        hero_text.set_hexpand(True)

        w_title = Gtk.Label(label="Welcome to Sentinel CAC Setup")
        w_title.add_css_class("hero-title")
        w_title.set_xalign(0)
        hero_text.append(w_title)

        w_sub = Gtk.Label(
            label="Automated Department of Defense (DoD) Common Access Card Middleware and Browser Configuration"
        )
        w_sub.add_css_class("hero-subtitle")
        w_sub.set_xalign(0)
        w_sub.set_wrap(True)
        hero_text.append(w_sub)

        hero_box.append(hero_text)
        page.append(hero_box)

        # System Inspection Info Group
        info_group = Adw.PreferencesGroup()
        info_group.set_title("Target System Environment")
        info_group.set_description("Sentinel inspected your operating system and configuration:")

        # OS Row
        os_row = Adw.ActionRow(
            title="Operating System",
            subtitle=f"{self.platform.name} ({sys_platform.machine()})",
        )
        os_badge = Gtk.Label(label=f"Family: {self.platform.family.upper()}")
        os_badge.add_css_class("badge-info")
        os_row.add_suffix(os_badge)
        info_group.add(os_row)

        # Package Manager Row
        pkg_row = Adw.ActionRow(
            title="Package Manager",
            subtitle=f"Detected system package manager: {self.platform.package_manager}",
        )
        info_group.add(pkg_row)

        # Hardware Reader Row
        card_stat = scan_smartcard()
        r_name = card_stat.reader_name or "No physical reader detected (can be connected later)"
        reader_row = Adw.ActionRow(
            title="Smart Card Hardware",
            subtitle=GLib.markup_escape_text(r_name),
        )
        if hasattr(reader_row, "set_use_markup"):
            reader_row.set_use_markup(False)
        if card_stat.reader_name:
            r_badge = Gtk.Label(label="Reader Found")
            r_badge.add_css_class("badge-success")
            reader_row.add_suffix(r_badge)
        info_group.add(reader_row)

        page.append(info_group)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        page.append(spacer)

        # Navigation Bar
        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        nav_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _: self.close())
        nav_box.append(cancel_btn)

        next_btn = Gtk.Button(label="Next")
        next_btn.add_css_class("suggested-action")
        next_btn.connect("clicked", lambda _: self.stack.set_visible_child_name("options"))
        nav_box.append(next_btn)

        page.append(nav_box)
        self.stack.add_named(page, "welcome")

    # --------------------------------------------------------------------------
    # Page 2: Component Options Screen
    # --------------------------------------------------------------------------
    def _build_options_page(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)

        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_margin_top(20)
        page.set_margin_bottom(24)
        page.set_margin_start(36)
        page.set_margin_end(36)
        scrolled.set_child(page)

        # Title
        opts_group = Adw.PreferencesGroup()
        opts_group.set_title("Select Setup Components")
        opts_group.set_description(
            "Select the components and configuration tasks you want Sentinel to automate:"
        )

        # Component 1: System Packages & Middleware
        missing = check_missing_packages(self.platform)
        sub1 = "Installs pcsc-lite, opensc, nss-tools, and driver fixes."
        if missing:
            sub1 += f" (Missing: {', '.join(missing)})"
        self.switch_middleware = Adw.SwitchRow(
            title="Smart Card Middleware and Daemon",
            subtitle=sub1,
        )
        self.switch_middleware.set_active(True)
        opts_group.add(self.switch_middleware)

        # Component 2: DoD PKI Certificates
        self.switch_certs = Adw.SwitchRow(
            title="DoD PKI Trust Bundle (Root CAs)",
            subtitle="Installs verified DoD Root CAs into system trust and configures enterprise chain for browsers.",
        )
        self.switch_certs.set_active(True)
        opts_group.add(self.switch_certs)

        # Component 3: Browsers
        self.switch_browsers = Adw.SwitchRow(
            title="Web Browser Configuration",
            subtitle="Configures Mozilla Firefox ('Ask Every Time' prompt) and Chrome/Edge NSS DB.",
        )
        self.switch_browsers.set_active(True)
        opts_group.add(self.switch_browsers)

        # Component 4: Desktop Launcher & CLI
        self.switch_desktop = Adw.SwitchRow(
            title="Application Menu Shortcut and CLI Tools",
            subtitle="Installs Sentinel into your application menu and sets up ~/.local/bin/sentinel.",
        )
        self.switch_desktop.set_active(True)
        opts_group.add(self.switch_desktop)

        page.append(opts_group)

        # Security Authorization Note
        note_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        note_box.add_css_class("banner-warning")
        note_icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        note_box.append(note_icon)
        note_lbl = Gtk.Label(
            label="System-level changes will prompt for administrative authorization (Polkit) once during installation."
        )
        note_lbl.set_wrap(True)
        note_lbl.set_xalign(0)
        note_lbl.set_hexpand(True)
        note_box.append(note_lbl)
        page.append(note_box)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        page.append(spacer)

        # Navigation Bar
        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        nav_box.set_halign(Gtk.Align.END)

        back_btn = Gtk.Button(label="←  Back")
        back_btn.connect("clicked", lambda _: self.stack.set_visible_child_name("welcome"))
        nav_box.append(back_btn)

        install_btn = Gtk.Button(label="Install Now")
        install_btn.add_css_class("master-setup-btn")
        install_btn.connect("clicked", self._start_installation)
        nav_box.append(install_btn)

        page.append(nav_box)
        self.stack.add_named(scrolled, "options")

    # --------------------------------------------------------------------------
    # Page 3: Live Installation Progress
    # --------------------------------------------------------------------------
    def _build_installing_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_margin_top(24)
        page.set_margin_bottom(24)
        page.set_margin_start(36)
        page.set_margin_end(36)

        # Progress Header
        prog_header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.prog_title = Gtk.Label(label="Configuring Sentinel...")
        self.prog_title.add_css_class("hero-title")
        self.prog_title.set_xalign(0)
        prog_header.append(self.prog_title)

        self.prog_status_lbl = Gtk.Label(label="Preparing installation tasks...")
        self.prog_status_lbl.add_css_class("hero-subtitle")
        self.prog_status_lbl.set_xalign(0)
        prog_header.append(self.prog_status_lbl)

        page.append(prog_header)

        # Progress Bar
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_show_text(False)
        page.append(self.progress_bar)

        # Step List Box
        steps_group = Adw.PreferencesGroup()
        steps_group.set_title("Installation Steps")

        self.step_rows = []
        step_definitions = [
            ("packages", "Install and verify system packages (pcsc-lite, opensc, nss-tools)"),
            ("middleware", "Enable pcscd daemon and apply OpenSC Broadcom reader fix"),
            ("certs", "Install DoD Root and Intermediate CAs into system store"),
            ("browsers", "Configure Firefox policies, 'Ask Every Time', and Chrome NSS DB"),
            ("desktop", "Install application menu shortcut and CLI commands"),
        ]

        for s_id, s_text in step_definitions:
            row = Adw.ActionRow(title=s_text)
            status_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
            status_icon.set_opacity(0.3)
            row.add_suffix(status_icon)
            steps_group.add(row)
            self.step_rows.append({"id": s_id, "row": row, "icon": status_icon})

        page.append(steps_group)

        # Expandable Log Console
        expander = Adw.ExpanderRow()
        expander.set_title("Installation Log Console")
        expander.set_subtitle("Real-time command and daemon output")

        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_min_content_height(140)
        log_scroll.set_vexpand(True)

        self.log_buffer = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buffer)
        self.log_view.set_editable(False)
        self.log_view.set_monospace(True)
        self.log_view.add_css_class("log-view")
        log_scroll.set_child(self.log_view)

        expander.add_row(log_scroll)
        page.append(expander)

        self.stack.add_named(page, "installing")

    # --------------------------------------------------------------------------
    # Page 4: Completion Screen
    # --------------------------------------------------------------------------
    def _build_finish_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        page.set_margin_top(28)
        page.set_margin_bottom(24)
        page.set_margin_start(36)
        page.set_margin_end(36)

        # Hero Success Card
        finish_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        finish_card.add_css_class("banner-ready")

        success_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
        success_icon.set_pixel_size(64)
        finish_card.append(success_icon)

        finish_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        finish_text.set_hexpand(True)

        f_title = Gtk.Label(label="Installation Complete!")
        f_title.add_css_class("hero-title")
        f_title.set_xalign(0)
        finish_text.append(f_title)

        f_sub = Gtk.Label(
            label="Sentinel and DoD smart card authentication are now fully configured and active."
        )
        f_sub.add_css_class("hero-subtitle")
        f_sub.set_xalign(0)
        f_sub.set_wrap(True)
        finish_text.append(f_sub)

        finish_card.append(finish_text)
        page.append(finish_card)

        # Results Group
        results_group = Adw.PreferencesGroup()
        results_group.set_title("Configuration Summary")

        r1 = Adw.ActionRow(
            title="DoD Certificate Authorities",
            subtitle="Verified DoD Root CAs installed into system certificate trust store.",
        )
        b1 = Gtk.Label(label="Active")
        b1.add_css_class("badge-success")
        r1.add_suffix(b1)
        results_group.add(r1)

        r2 = Adw.ActionRow(
            title="Web Browsers (Firefox and Chrome)",
            subtitle="Security devices registered. Firefox will prompt 'Ask Every Time' for certificate selection.",
        )
        b2 = Gtk.Label(label="Integrated")
        b2.add_css_class("badge-success")
        r2.add_suffix(b2)
        results_group.add(r2)

        r3 = Adw.ActionRow(
            title="Smart Card Daemon and Hardware",
            subtitle="pcscd service active. Broadcom reader hang fix applied.",
        )
        b3 = Gtk.Label(label="Optimized")
        b3.add_css_class("badge-success")
        r3.add_suffix(b3)
        results_group.add(r3)

        r4 = Adw.ActionRow(
            title="Application Shortcuts",
            subtitle="Sentinel is available in your desktop application menu and command line.",
        )
        b4 = Gtk.Label(label="Installed")
        b4.add_css_class("badge-success")
        r4.add_suffix(b4)
        results_group.add(r4)

        page.append(results_group)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        page.append(spacer)

        # Checkbox & Finish Button
        bottom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)

        self.launch_check = Gtk.CheckButton(label="Launch Sentinel now")
        self.launch_check.add_css_class("launch-checkbox")
        self.launch_check.set_active(True)
        self.launch_check.set_hexpand(True)
        bottom_box.append(self.launch_check)

        finish_btn = Gtk.Button(label="Finish")
        finish_btn.add_css_class("suggested-action")
        finish_btn.connect("clicked", self._on_finish_clicked)
        bottom_box.append(finish_btn)

        page.append(bottom_box)
        self.stack.add_named(page, "finish")

    # --------------------------------------------------------------------------
    # Page 5: Error Screen
    # --------------------------------------------------------------------------
    def _build_error_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        page.set_margin_top(28)
        page.set_margin_bottom(24)
        page.set_margin_start(36)
        page.set_margin_end(36)

        err_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        err_card.add_css_class("banner-warning")

        err_icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
        err_icon.set_pixel_size(64)
        err_card.append(err_icon)

        err_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        err_text.set_hexpand(True)

        e_title = Gtk.Label(label="Installation Incomplete")
        e_title.add_css_class("hero-title")
        e_title.set_xalign(0)
        err_text.append(e_title)

        self.err_sub = Gtk.Label(label="An error occurred during system setup.")
        self.err_sub.add_css_class("hero-subtitle")
        self.err_sub.set_xalign(0)
        self.err_sub.set_wrap(True)
        err_text.append(self.err_sub)

        err_card.append(err_text)
        page.append(err_card)

        # Error Details Box
        err_group = Adw.PreferencesGroup()
        err_group.set_title("Diagnostic Information")

        self.err_detail_lbl = Gtk.Label(label="")
        self.err_detail_lbl.set_wrap(True)
        self.err_detail_lbl.set_xalign(0)
        self.err_detail_lbl.set_margin_start(12)
        self.err_detail_lbl.set_margin_top(8)
        self.err_detail_lbl.set_margin_bottom(8)
        err_group.add(self.err_detail_lbl)
        page.append(err_group)

        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        page.append(spacer)

        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        nav_box.set_halign(Gtk.Align.END)

        retry_btn = Gtk.Button(label="← Try Again")
        retry_btn.connect("clicked", lambda _: self.stack.set_visible_child_name("options"))
        nav_box.append(retry_btn)

        close_btn = Gtk.Button(label="Close")
        close_btn.connect("clicked", lambda _: self.close())
        nav_box.append(close_btn)

        page.append(nav_box)
        self.stack.add_named(page, "error")

    # --------------------------------------------------------------------------
    # Installation Logic (Runs in Background Thread)
    # --------------------------------------------------------------------------
    def _start_installation(self, _btn):
        self.stack.set_visible_child_name("installing")
        self.progress_bar.set_fraction(0.05)
        self.prog_status_lbl.set_label("Initializing setup routine...")

        opts = {
            "middleware": self.switch_middleware.get_active(),
            "certs": self.switch_certs.get_active(),
            "browsers": self.switch_browsers.get_active(),
            "desktop": self.switch_desktop.get_active(),
        }

        # Run in thread
        threading.Thread(target=self._run_installer_worker, args=(opts,), daemon=True).start()

    def _append_log(self, text: str):
        GLib.idle_add(self._ui_append_log, text)

    def _ui_append_log(self, text: str):
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")
        # Scroll to bottom
        adj = self.log_view.get_vadjustment()
        if adj:
            adj.set_value(adj.get_upper())

    def _set_step_status(self, step_id: str, status: str):
        GLib.idle_add(self._ui_set_step_status, step_id, status)

    def _ui_set_step_status(self, step_id: str, status: str):
        for item in self.step_rows:
            if item["id"] == step_id:
                icon: Gtk.Image = item["icon"]
                icon.set_opacity(1.0)
                if status == "running":
                    icon.set_from_icon_name("process-working-symbolic")
                elif status == "success":
                    icon.set_from_icon_name("emblem-ok-symbolic")
                elif status == "error":
                    icon.set_from_icon_name("dialog-error-symbolic")
                elif status == "skip":
                    icon.set_from_icon_name("action-unavailable-symbolic")
                    icon.set_opacity(0.5)

    def _set_progress(self, frac: float, msg: str):
        GLib.idle_add(self._ui_set_progress, frac, msg)

    def _ui_set_progress(self, frac: float, msg: str):
        self.progress_bar.set_fraction(frac)
        self.prog_status_lbl.set_label(msg)

    def _run_installer_worker(self, opts: dict):
        self._append_log("=================================================================")
        self._append_log(f"   Sentinel v2 Setup Wizard on {self.platform.name}")
        self._append_log("=================================================================")

        do_middleware = opts["middleware"]
        do_certs = opts["certs"]
        do_browsers = opts["browsers"]
        do_desktop = opts["desktop"]

        # Step 1: Packages & Middleware
        if do_middleware:
            self._set_step_status("packages", "running")
            self._set_progress(0.15, "Verifying and installing system middleware packages...")
            self._append_log("[1/5] Checking required packages...")
            missing = check_missing_packages(self.platform)
            if missing:
                self._append_log(f"[1/5] Installing missing packages: {', '.join(missing)}")
                ok, msg = run_privileged_helper(
                    ["--packages", "--family", self.platform.family],
                    log_fn=self._append_log,
                    timeout=180,
                )
                if not ok:
                    self._set_step_status("packages", "error")
                    self._show_failure("Failed to install system packages", msg)
                    return
            else:
                self._append_log("[1/5] All required packages are already installed.")
            self._set_step_status("packages", "success")

            # Step 2: Service & Broadcom Reader Optimization
            self._set_step_status("middleware", "running")
            self._set_progress(0.35, "Configuring pcscd service and reader optimization...")
            self._append_log("[2/5] Configuring pcscd service & OpenSC compatibility...")
            mod_path = find_opensc_module() or (
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
                if self.platform.is_debian_derivative
                else "/usr/lib64/opensc-pkcs11.so"
            )
            ok, msg = run_privileged_helper(
                ["--service", "--reader-fix", "--family", self.platform.family, "--module", mod_path],
                log_fn=self._append_log,
                timeout=60,
            )
            if not ok:
                self._set_step_status("middleware", "error")
                self._show_failure("Failed to configure system services", msg)
                return
            self._set_step_status("middleware", "success")
        else:
            self._set_step_status("packages", "skip")
            self._set_step_status("middleware", "skip")

        # Step 3: DoD PKI Certificates
        if do_certs:
            self._set_step_status("certs", "running")
            self._set_progress(0.55, "Installing DoD Root and Intermediate CAs...")
            self._append_log("[3/5] Installing DoD Certificate Authorities into system store...")
            ok, msg = run_privileged_helper(
                ["--certs", "--family", self.platform.family],
                log_fn=self._append_log,
                timeout=60,
            )
            if not ok:
                self._set_step_status("certs", "error")
                self._show_failure("Failed to install DoD certificates", msg)
                return
            self._set_step_status("certs", "success")
        else:
            self._set_step_status("certs", "skip")

        # Step 4: Browser Integration
        if do_browsers:
            self._set_step_status("browsers", "running")
            self._set_progress(0.75, "Configuring Mozilla Firefox and Chrome/Edge NSS...")
            self._append_log("[4/5] Configuring browser security devices and policies...")
            # Enterprise policies (privileged)
            mod_path = find_opensc_module() or (
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
                if self.platform.is_debian_derivative
                else "/usr/lib64/opensc-pkcs11.so"
            )
            ok_pol, _ = run_privileged_helper(
                ["--policies", "--family", self.platform.family, "--module", mod_path],
                log_fn=self._append_log,
                timeout=30,
            )
            # User profile configurations
            b_res = configure_all_browsers(log_fn=self._append_log)
            self._append_log(f"[4/5] Browser configuration finished: {b_res}")
            if ok_pol and b_res:
                self._set_step_status("browsers", "success")
            elif ok_pol or b_res:
                self._set_step_status("browsers", "warning")
            else:
                self._set_step_status("browsers", "error")
        else:
            self._set_step_status("browsers", "skip")

        # Step 5: Desktop Launcher & CLI
        if do_desktop:
            self._set_step_status("desktop", "running")
            self._set_progress(0.90, "Creating application menu shortcut and CLI commands...")
            self._append_log("[5/5] Installing desktop integration and command launchers...")
            ok, msg = install_desktop_integration(SCRIPT_DIR, log_fn=self._append_log)
            if not ok:
                self._append_log(f"[WARNING] Desktop launcher notice: {msg}")
            self._set_step_status("desktop", "success")
        else:
            self._set_step_status("desktop", "skip")

        # Complete!
        self._set_progress(1.0, "Installation complete!")
        self._append_log("=================================================================")
        self._append_log("   Installation successfully completed!")
        self._append_log("=================================================================")

        GLib.idle_add(self._show_success)

    def _show_success(self):
        self.stack.set_visible_child_name("finish")

    def _show_failure(self, title: str, details: str):
        def _apply():
            self.err_sub.set_label(title)
            self.err_detail_lbl.set_label(details)
            self.stack.set_visible_child_name("error")
        GLib.idle_add(_apply)

    def _on_finish_clicked(self, _btn):
        launch_now = self.launch_check.get_active()
        self.close()
        if launch_now:
            # Spawn sentinel main app in background
            app_script = os.path.join(SCRIPT_DIR, "sentinel.py")
            if not os.path.isfile(app_script):
                app_script = os.path.join(SCRIPT_DIR, "sentinel_cac_manager.py")
            subprocess.Popen([sys.executable, app_script, "--gui"])


class InstallerApplication(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="com.codefxr.sentinel.installer",
            flags=0,
        )

    def do_activate(self):
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.PREFER_DARK)
        win = self.props.active_window
        if not win:
            win = InstallerWindow(self)
        win.present()


def run_installer_gui():
    app = InstallerApplication()
    return app.run([sys.argv[0]])
