"""Diagnostics, Web Portal Testing, and Activity Log View for Sentinel v2."""

import subprocess
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Gtk, Adw, Gdk


PORTALS = [
    ("Defense Manpower Data Center (DMDC)", "https://www.dmdc.osd.mil/milconnect/"),
    ("MyPay (DFAS)", "https://mypay.dfas.mil"),
    ("Army Human Resources Command", "https://www.hrc.army.mil"),
    ("Air Force Portal", "https://www.my.af.mil"),
    ("Navy Quick Links", "https://my.navy.mil"),
    ("Client Certificate TLS Test (BadSSL)", "https://client.badssl.com"),
]


class DiagnosticsView(Gtk.Box):
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
        # 0. Hardware & CCID Conflicts Group
        conflict_group = Adw.PreferencesGroup()
        conflict_group.set_title("Smart Card Hardware & CCID Diagnostics")
        conflict_group.set_description("Inspect low-level reader access and daemon locks:")

        self.scdaemon_row = Adw.ActionRow(title="GnuPG scdaemon Lock")
        self.scdaemon_badge = Gtk.Label(label="Checking...")
        self.scdaemon_badge.add_css_class("badge-info")
        self.scdaemon_btn = Gtk.Button(label="Resolve Conflict")
        self.scdaemon_btn.add_css_class("suggested-action")
        self.scdaemon_btn.set_visible(False)
        self.scdaemon_btn.connect("clicked", self.on_fix_scdaemon)
        self.scdaemon_row.add_suffix(self.scdaemon_btn)
        self.scdaemon_row.add_suffix(self.scdaemon_badge)
        conflict_group.add(self.scdaemon_row)
        self.container.append(conflict_group)
        self.refresh_scdaemon_status()

        # 1. Portal Testing Group
        portal_group = Adw.PreferencesGroup()
        portal_group.set_title("DoD Portal Testing")
        portal_group.set_description(
            "Click any portal to launch your default browser and test CAC PIN and certificate authentication:"
        )

        for name, url in PORTALS:
            row = Adw.ActionRow(title=name, subtitle=url)
            if hasattr(row, "set_use_markup"):
                row.set_use_markup(False)
            btn = Gtk.Button(label="Open")
            btn.add_css_class("flat")
            btn.connect("clicked", lambda b, u=url: self.open_url(u))
            row.add_suffix(btn)
            portal_group.add(row)

        self.container.append(portal_group)

        # 2. Activity Log Group
        log_group = Adw.PreferencesGroup()
        log_group.set_title("Activity and Diagnostic Console")
        log_group.set_description("Real-time diagnostic output from middleware, certificates, and browser configurations:")

        # Log action bar
        bar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bar_box.set_margin_bottom(8)

        copy_btn = Gtk.Button(label="Copy Log")
        copy_btn.connect("clicked", self.on_copy_log)
        bar_box.append(copy_btn)

        clear_btn = Gtk.Button(label="Clear")
        clear_btn.connect("clicked", self.on_clear_log)
        bar_box.append(clear_btn)

        log_row = Adw.ActionRow()
        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        log_box.set_vexpand(True)
        log_box.append(bar_box)

        # Scrolled Text View
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(220)
        scrolled.set_vexpand(True)

        self.text_view = Gtk.TextView()
        self.text_view.set_editable(False)
        self.text_view.set_monospace(True)
        self.text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.text_view.add_css_class("log-view")
        self.buffer = self.text_view.get_buffer()

        scrolled.set_child(self.text_view)
        log_box.append(scrolled)

        log_row.set_child(log_box)
        log_group.add(log_row)
        self.container.append(log_group)

    def open_url(self, url: str):
        try:
            subprocess.Popen(["xdg-open", url])
            self.main_window.append_log(f"Launched browser to test portal: {url}")
        except Exception as e:
            self.main_window.append_log(f"Failed to open URL {url}: {e}")

    def append_log(self, text: str):
        iter_end = self.buffer.get_end_iter()
        self.buffer.insert(iter_end, f"{text}\n")
        # Scroll to bottom
        mark = self.buffer.create_mark(None, self.buffer.get_end_iter(), False)
        self.text_view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

    def on_copy_log(self, button):
        start = self.buffer.get_start_iter()
        end = self.buffer.get_end_iter()
        content = self.buffer.get_text(start, end, True)
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(content)
        self.main_window.show_toast("Diagnostic log copied to clipboard!")

    def on_clear_log(self, button):
        self.buffer.set_text("")
