"""Dashboard View (ActivClient Experience) for Sentinel v2."""

import os
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, Adw, GdkPixbuf, GLib

from core.smartcard import SmartCardStatus

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel.png")
if not os.path.isfile(ICON_PATH):
    ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel_cac_manager.png")
if not os.path.isfile(ICON_PATH):
    ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel_icon_v2.png")


class DashboardView(Gtk.Box):
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

        self.container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.clamp.set_child(self.container)
        self.scrolled.set_child(self.clamp)
        self.append(self.scrolled)

        self.setup_ui()

    def setup_ui(self):
        # 1. Hero Card
        hero_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        hero_box.add_css_class("hero-card")

        # Icon
        if os.path.isfile(ICON_PATH):
            try:
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(ICON_PATH, 80, 80, True)
                app_icon = Gtk.Image.new_from_pixbuf(pixbuf)
                app_icon.set_pixel_size(80)
                hero_box.append(app_icon)
            except Exception:
                pass

        # Text column
        hero_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        hero_text.set_hexpand(True)

        title = Gtk.Label(label="Sentinel")
        title.add_css_class("hero-title")
        title.set_xalign(0)
        hero_text.append(title)

        subtitle = Gtk.Label(
            label="Automated DoD Common Access Card Middleware and Browser Integration"
        )
        subtitle.add_css_class("hero-subtitle")
        subtitle.set_xalign(0)
        hero_text.append(subtitle)

        # Status Banner
        self.status_banner = Gtk.Label(label="Checking system configuration...")
        self.status_banner.add_css_class("banner-warning")
        self.status_banner.set_xalign(0)
        hero_text.append(self.status_banner)

        hero_box.append(hero_text)
        self.container.append(hero_box)

        # 2. Master One-Click Setup Card
        setup_group = Adw.PreferencesGroup()
        setup_group.set_title("Automated Configuration")
        setup_group.set_description(
            "Configures Firefox &amp; Chrome, installs all DoD Root and Issuing CAs, sets 'Ask Every Time' certificate prompt, and starts middleware."
        )

        setup_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        setup_box.set_margin_top(8)
        setup_box.set_margin_bottom(8)

        # Action button row
        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.master_btn = Gtk.Button(label="Automate Full CAC Setup")
        self.master_btn.add_css_class("master-setup-btn")
        self.master_btn.connect("clicked", self.on_master_setup_clicked)
        btn_row.append(self.master_btn)

        self.spinner = Gtk.Spinner()
        btn_row.append(self.spinner)

        setup_box.append(btn_row)

        # Progress bar & label
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_hexpand(True)
        self.progress_bar.set_visible(False)
        setup_box.append(self.progress_bar)

        self.step_label = Gtk.Label(label="")
        self.step_label.set_xalign(0)
        self.step_label.add_css_class("dim-label")
        self.step_label.set_visible(False)
        setup_box.append(self.step_label)

        setup_row = Adw.ActionRow()
        setup_row.set_child(setup_box)
        setup_group.add(setup_row)
        self.container.append(setup_group)

        # 3. Hardware & Smart Card Status
        self.hw_group = Adw.PreferencesGroup()
        self.hw_group.set_title("Hardware and Smart Card Reader")

        self.reader_row = Adw.ActionRow(title="Smart Card Reader")
        self.reader_row.set_subtitle("Scanning for readers...")
        self.reader_badge = Gtk.Label(label="Scanning")
        self.reader_badge.add_css_class("badge-info")
        self.reader_row.add_suffix(self.reader_badge)
        self.hw_group.add(self.reader_row)

        self.card_row = Adw.ActionRow(title="Common Access Card Status")
        self.card_row.set_subtitle("Checking card presence...")
        self.card_badge = Gtk.Label(label="Checking")
        self.card_badge.add_css_class("badge-warning")
        self.card_row.add_suffix(self.card_badge)
        self.hw_group.add(self.card_row)

        self.container.append(self.hw_group)

        # 4. Cardholder Identity Group (ActivClient details)
        self.id_group = Adw.PreferencesGroup()
        self.id_group.set_title("Cardholder Identity (ActivClient)")

        self.holder_row = Adw.ActionRow(title="Cardholder Name")
        self.holder_row.set_subtitle("Insert CAC to read identity")
        self.id_group.add(self.holder_row)

        self.edipi_row = Adw.ActionRow(title="DoD ID Number (EDIPI)")
        self.edipi_row.set_subtitle("-")
        self.id_group.add(self.edipi_row)

        self.cert_status_row = Adw.ActionRow(title="PIV Certificate Status")
        self.cert_status_row.set_subtitle("-")
        self.id_group.add(self.cert_status_row)

        self.pin_status_row = Adw.ActionRow(title="PIV PIN Status")
        self.pin_status_row.set_subtitle("-")
        self.pin_badge = Gtk.Label(label="-")
        self.pin_badge.add_css_class("badge-info")
        self.pin_status_row.add_suffix(self.pin_badge)
        self.id_group.add(self.pin_status_row)

        self.logon_status_row = Adw.ActionRow(title="Session Lock on Removal")
        self.logon_status_row.set_subtitle("-")
        self.logon_badge = Gtk.Label(label="-")
        self.logon_badge.add_css_class("badge-info")
        self.logon_status_row.add_suffix(self.logon_badge)
        self.id_group.add(self.logon_status_row)

        self.container.append(self.id_group)

    def update_status(self, card_stat: SmartCardStatus, system_ready: bool):
        # Update Banner
        if system_ready and card_stat.card_present:
            self.status_banner.set_label("System Ready: DoD CAC Ready for Browser Authentication")
            self.status_banner.remove_css_class("banner-warning")
            self.status_banner.add_css_class("banner-ready")
        elif not system_ready:
            self.status_banner.set_label("Setup Required: Click 'Automate Full CAC Setup' Below")
            self.status_banner.remove_css_class("banner-ready")
            self.status_banner.add_css_class("banner-warning")
        else:
            self.status_banner.set_label("System Configured: Insert CAC into Reader to Authenticate")
            self.status_banner.remove_css_class("banner-ready")
            self.status_banner.add_css_class("banner-warning")

        # Update Reader
        if card_stat.reader_name:
            r_name = GLib.markup_escape_text(card_stat.reader_name)
            self.reader_row.set_subtitle(r_name)
            self.reader_badge.set_label("Connected")
            self.reader_badge.remove_css_class("badge-warning")
            self.reader_badge.remove_css_class("badge-danger")
            self.reader_badge.add_css_class("badge-success")
        else:
            self.reader_row.set_subtitle("No smart card reader detected. Plug in reader via USB.")
            self.reader_badge.set_label("No Reader")
            self.reader_badge.remove_css_class("badge-success")
            self.reader_badge.add_css_class("badge-danger")

        # Update Card Presence
        if card_stat.card_present:
            c_name = GLib.markup_escape_text(card_stat.card_name or "Common Access Card")
            t_serial = GLib.markup_escape_text(card_stat.token_serial or "Active")
            self.card_row.set_subtitle(f"{c_name} (Serial: {t_serial})")
            self.card_badge.set_label("Inserted")
            self.card_badge.remove_css_class("badge-warning")
            self.card_badge.remove_css_class("badge-danger")
            self.card_badge.add_css_class("badge-success")
        else:
            self.card_row.set_subtitle("Card slot empty. Please insert your DoD CAC.")
            self.card_badge.set_label("No Card")
            self.card_badge.remove_css_class("badge-success")
            self.card_badge.add_css_class("badge-warning")

        # Update Cardholder Details
        prim_cert = card_stat.primary_certificate
        if card_stat.card_present and prim_cert:
            h_name = GLib.markup_escape_text(prim_cert.holder_name or "DoD Cardholder")
            e_id = GLib.markup_escape_text(prim_cert.edipi or "Verified on Card")
            s_text = GLib.markup_escape_text(prim_cert.status_text or "Active")
            i_cn = GLib.markup_escape_text(prim_cert.issuer_cn or "DoD CA")
            self.holder_row.set_subtitle(h_name)
            self.edipi_row.set_subtitle(e_id)
            self.cert_status_row.set_subtitle(f"{s_text} (Issuer: {i_cn})")
        else:
            self.holder_row.set_subtitle("Insert CAC into reader to read identity")
            self.edipi_row.set_subtitle("-")
            self.cert_status_row.set_subtitle("-")

        # Update PIN Status
        if card_stat.card_present:
            self.pin_badge.remove_css_class("badge-info")
            self.pin_badge.remove_css_class("badge-success")
            self.pin_badge.remove_css_class("badge-warning")
            self.pin_badge.remove_css_class("badge-danger")
            if card_stat.pin_locked:
                self.pin_status_row.set_subtitle("PIN is LOCKED (Contact ID Card Facility)")
                self.pin_badge.set_label("LOCKED")
                self.pin_badge.add_css_class("badge-danger")
            elif card_stat.pin_retries_remaining is not None:
                self.pin_status_row.set_subtitle(f"{card_stat.pin_retries_remaining} verification attempts remaining")
                self.pin_badge.set_label(f"{card_stat.pin_retries_remaining} Retries")
                if card_stat.pin_retries_remaining >= 3:
                    self.pin_badge.add_css_class("badge-success")
                elif card_stat.pin_retries_remaining > 1:
                    self.pin_badge.add_css_class("badge-warning")
                else:
                    self.pin_badge.add_css_class("badge-danger")
            else:
                msg = card_stat.pin_status_msg or "Status unverified"
                self.pin_status_row.set_subtitle(GLib.markup_escape_text(msg))
                self.pin_badge.set_label("Unchecked")
                self.pin_badge.add_css_class("badge-info")
        else:
            self.pin_status_row.set_subtitle("-")
            self.pin_badge.set_label("-")
            self.pin_badge.remove_css_class("badge-success")
            self.pin_badge.remove_css_class("badge-warning")
            self.pin_badge.remove_css_class("badge-danger")
            self.pin_badge.add_css_class("badge-info")

        # Update Session Lock on Removal Status
        from core.system_fix import check_smartcard_logon_status
        l_stat = check_smartcard_logon_status()
        self.logon_badge.remove_css_class("badge-info")
        self.logon_badge.remove_css_class("badge-success")
        self.logon_badge.remove_css_class("badge-warning")

        if l_stat["lock_removal_enabled"]:
            self.logon_status_row.set_subtitle("Active (Workstation screen locks when CAC is removed)")
            self.logon_badge.set_label("Active")
            self.logon_badge.add_css_class("badge-success")
        else:
            self.logon_status_row.set_subtitle("Inactive (Configure in System & Browsers tab)")
            self.logon_badge.set_label("Inactive")
            self.logon_badge.add_css_class("badge-info")

    def on_master_setup_clicked(self, button):
        self.master_btn.set_sensitive(False)
        self.spinner.start()
        self.progress_bar.set_visible(True)
        self.progress_bar.set_fraction(0.05)
        self.step_label.set_visible(True)
        self.step_label.set_label("Starting automated setup...")

        def _worker():
            from core.system_fix import run_full_setup

            def _progress_cb(frac, msg):
                GLib.idle_add(self._update_progress, frac, msg)

            def _log_cb(msg):
                GLib.idle_add(self.main_window.append_log, msg)

            res = run_full_setup(progress_callback=_progress_cb, log_callback=_log_cb)
            GLib.idle_add(self._on_setup_finished, res)

        threading.Thread(target=_worker, daemon=True).start()

    def _update_progress(self, frac: float, msg: str):
        self.progress_bar.set_fraction(frac)
        self.step_label.set_label(msg)

    def _on_setup_finished(self, result):
        self.spinner.stop()
        self.master_btn.set_sensitive(True)
        self.progress_bar.set_fraction(1.0)

        if result.get("success"):
            self.step_label.set_label("Configuration Complete! Browsers and CAC ready.")
            self.main_window.show_toast("DoD CAC Full Setup successfully completed!")
        else:
            self.step_label.set_label(f"Setup Error: {result.get('message', 'Failed')}")
            self.main_window.show_toast(f"Setup Warning: {result.get('message', 'Check logs')}")

        self.main_window.refresh_all_status(force=True)
