"""Smart Card Certificates View (ActivClient Certificate Explorer) for Sentinel v2."""

import base64
import logging
import os
import re
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core.smartcard import CardCertificate, SmartCardStatus, scan_smartcard, verify_cert_ocsp

logger = logging.getLogger("sentinel.cards_view")


class CardsView(Gtk.Box):
    def __init__(self, main_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_window = main_window
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        # Scrolled Window
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

        # Empty state widget
        self.empty_status = Adw.StatusPage()
        self.empty_status.set_icon_name("dialog-password-symbolic")
        self.empty_status.set_title("No Smart Card Detected")
        self.empty_status.set_description(
            "Please plug in your smart card reader and insert your DoD Common Access Card (CAC) to inspect on-card certificates."
        )

        self.setup_ui()

    def setup_ui(self):
        self.content_box.append(self.empty_status)

    def update_status(self, card_stat: SmartCardStatus):
        new_fingerprint = (
            card_stat.card_present,
            card_stat.reader_name,
            card_stat.atr,
            card_stat.token_serial,
            len(card_stat.certificates),
            card_stat.pin_retries_remaining,
            card_stat.pin_locked,
        )
        if getattr(self, "_current_fingerprint", None) == new_fingerprint:
            # Card and status have not changed; avoid tearing down open expanders or active widgets
            return
        self._current_fingerprint = new_fingerprint

        # Clear previous widgets
        while True:
            child = self.content_box.get_first_child()
            if not child:
                break
            self.content_box.remove(child)

        if not card_stat.card_present or not card_stat.certificates:
            self.content_box.append(self.empty_status)
            return

        # Header info
        header_group = Adw.PreferencesGroup()
        label_text = GLib.markup_escape_text(card_stat.token_label or "DoD CAC")
        header_group.set_title(f"Inserted Card: {label_text}")
        r_text = GLib.markup_escape_text(card_stat.reader_name or "PCSC")
        s_text = GLib.markup_escape_text(card_stat.token_serial or "Active")
        a_text = GLib.markup_escape_text(card_stat.atr or "N/A")
        header_group.set_description(
            f"Reader: {r_text} | Serial: {s_text} | ATR: {a_text}"
        )
        self.content_box.append(header_group)

        # PIN & Verification Group
        pin_group = Adw.PreferencesGroup()
        pin_group.set_title("PIV Card Security & PIN")
        pin_group.set_description("NIST SP 800-73-4 Cardholder Verification status:")

        pin_row = Adw.ActionRow(title="PIV PIN Status")
        if card_stat.pin_locked:
            pin_row.set_subtitle("PIN is LOCKED. Contact servicing RAPIDS/DEERS ID card facility.")
            pin_badge = Gtk.Label(label="LOCKED")
            pin_badge.add_css_class("badge-danger")
        elif card_stat.pin_retries_remaining is not None:
            if card_stat.pin_retries_remaining == 1:
                pin_row.set_subtitle(
                    "1 verification attempt remaining. Automated PIN change is disabled to prevent card lockout."
                )
            else:
                pin_row.set_subtitle(
                    f"{card_stat.pin_retries_remaining} verification attempts remaining before card lockout."
                )
            pin_badge = Gtk.Label(label=f"{card_stat.pin_retries_remaining} Retries")
            if card_stat.pin_retries_remaining >= 3:
                pin_badge.add_css_class("badge-success")
            elif card_stat.pin_retries_remaining > 1:
                pin_badge.add_css_class("badge-warning")
            else:
                pin_badge.add_css_class("badge-danger")
        else:
            msg = card_stat.pin_status_msg or "Status unverified"
            pin_row.set_subtitle(GLib.markup_escape_text(msg))
            pin_badge = Gtk.Label(label="Unchecked")
            pin_badge.add_css_class("badge-info")

        pin_row.add_suffix(pin_badge)

        btn_change_pin = Gtk.Button(label="Change PIN...")
        btn_change_pin.set_valign(Gtk.Align.CENTER)
        btn_change_pin.add_css_class("suggested-action")
        if card_stat.pin_locked or card_stat.pin_retries_remaining == 1:
            btn_change_pin.set_sensitive(False)
        btn_change_pin.connect("clicked", lambda _: self._show_change_pin_dialog(card_stat))
        pin_row.add_suffix(btn_change_pin)

        pin_group.add(pin_row)
        self.content_box.append(pin_group)

        # List Certificates
        certs_group = Adw.PreferencesGroup()
        certs_group.set_title("On-Card Digital Certificates")
        certs_group.set_description("Certificates loaded directly from the PKCS#15 secure smart card token:")

        for cert in card_stat.certificates:
            row = Adw.ExpanderRow()
            label_esc = GLib.markup_escape_text(cert.label or "Certificate")
            issuer_esc = GLib.markup_escape_text(cert.issuer_cn or "Unknown")
            status_esc = GLib.markup_escape_text(cert.status_text or "")
            row.set_title(label_esc)
            row.set_subtitle(f"Issuer: {issuer_esc} • {status_esc}")

            # Badge suffix
            badge = Gtk.Label(label=cert.status_text)
            if cert.is_valid:
                badge.add_css_class("badge-success")
            else:
                badge.add_css_class("badge-danger")
            row.add_suffix(badge)

            # Details inside expander
            holder = GLib.markup_escape_text(cert.holder_name or cert.cn or "Unknown")
            sub_name = Adw.ActionRow(title="Cardholder Name", subtitle=holder)
            row.add_row(sub_name)

            if cert.edipi:
                sub_edipi = Adw.ActionRow(title="DoD ID Number (EDIPI)", subtitle=GLib.markup_escape_text(cert.edipi))
                row.add_row(sub_edipi)

            if getattr(cert, "upn", None):
                sub_upn = Adw.ActionRow(title="User Principal Name (UPN)", subtitle=GLib.markup_escape_text(cert.upn))
                row.add_row(sub_upn)

            if getattr(cert, "aia_url", None):
                sub_aia = Adw.ActionRow(title="CA Issuers (AIA)", subtitle=GLib.markup_escape_text(cert.aia_url))
                row.add_row(sub_aia)

            sub_iss = Adw.ActionRow(title="Issuing Certificate Authority", subtitle=GLib.markup_escape_text(cert.issuer or "Unknown"))
            row.add_row(sub_iss)

            sub_val = Adw.ActionRow(
                title="Validity Period",
                subtitle=f"{cert.valid_from.strftime('%Y-%m-%d') if cert.valid_from else 'Unknown'} to {cert.valid_to_str}",
            )
            row.add_row(sub_val)

            sub_serial = Adw.ActionRow(title="Certificate Serial Number", subtitle=GLib.markup_escape_text(cert.serial or "N/A"))
            row.add_row(sub_serial)

            sub_usage = Adw.ActionRow(title="Key Usage and Purpose", subtitle=GLib.markup_escape_text(cert.usage or "General Purpose"))
            row.add_row(sub_usage)

            # Revocation status row with on-demand OCSP verification
            sub_revoc = Adw.ActionRow(
                title="Revocation Status",
                subtitle="Date Valid (Revocation Unchecked)",
            )
            btn_ocsp = Gtk.Button(label="Check OCSP")
            btn_ocsp.add_css_class("flat")
            btn_ocsp.set_valign(Gtk.Align.CENTER)

            def make_ocsp_handler(target_cert, action_row, button):
                def on_click(_btn):
                    button.set_sensitive(False)
                    button.set_label("Checking...")

                    def worker():
                        res, msg = verify_cert_ocsp(target_cert)

                        def update_ui():
                            action_row.set_subtitle(GLib.markup_escape_text(msg))
                            if res is True:
                                button.set_label("Good")
                                button.add_css_class("suggested-action")
                            elif res is False:
                                button.set_label("Revoked")
                                button.add_css_class("destructive-action")
                            else:
                                button.set_label("Retry OCSP")
                                button.set_sensitive(True)
                            return False

                        GLib.idle_add(update_ui)

                    threading.Thread(target=worker, daemon=True).start()

                return on_click

            btn_ocsp.connect("clicked", make_ocsp_handler(cert, sub_revoc, btn_ocsp))
            sub_revoc.add_suffix(btn_ocsp)
            row.add_row(sub_revoc)

            # Export Certificate Row
            sub_export = Adw.ActionRow(
                title="Certificate Export",
                subtitle="Save certificate in PEM or DER format for external tools or signing",
            )
            btn_export = Gtk.Button(label="Export...")
            btn_export.add_css_class("flat")
            btn_export.set_valign(Gtk.Align.CENTER)

            def make_export_handler(target_cert):
                def on_export_click(_btn):
                    self._export_certificate(target_cert)
                return on_export_click

            btn_export.connect("clicked", make_export_handler(cert))
            sub_export.add_suffix(btn_export)
            row.add_row(sub_export)

            certs_group.add(row)

        self.content_box.append(certs_group)

    def _export_certificate(self, cert: CardCertificate):
        if not cert.raw_der:
            self.main_window.show_toast("Certificate raw data unavailable for export.")
            return

        clean_holder = re.sub(r"[^a-zA-Z0-9_-]", "_", cert.holder_name or "CAC").strip("_")
        clean_label = re.sub(r"[^a-zA-Z0-9_-]", "_", cert.label or "Certificate").strip("_")
        suggested_name = f"{clean_holder}_{clean_label}.pem"

        b64 = base64.b64encode(cert.raw_der).decode("ascii")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        pem_content = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

        def _write_cert(path: str):
            try:
                flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags, 0o644)
                with open(fd, "wb") as f:
                    if path.lower().endswith((".der", ".cer")):
                        f.write(cert.raw_der)
                    else:
                        f.write(pem_content.encode("utf-8"))
                self.main_window.show_toast(f"Exported {os.path.basename(path)}")
                self.main_window.append_log(f"Exported certificate {cert.label} to {path}")
            except Exception as e:
                self.main_window.show_toast(f"Export failed: {e}")

        if hasattr(Gtk, "FileDialog"):
            dialog = Gtk.FileDialog()
            dialog.set_title("Export Certificate")
            dialog.set_initial_name(suggested_name)

            def on_save_finish(_dlg, result):
                try:
                    gfile = dialog.save_finish(result)
                    if gfile and gfile.get_path():
                        _write_cert(gfile.get_path())
                except Exception as e:
                    logger.debug(f"File dialog save cancelled or failed: {e}")

            dialog.save(self.main_window, None, on_save_finish)
        else:
            chooser = Gtk.FileChooserNative.new(
                "Export Certificate",
                self.main_window,
                Gtk.FileChooserAction.SAVE,
                "_Save",
                "_Cancel",
            )
            chooser.set_current_name(suggested_name)

            def on_native_response(dialog, response_id):
                if response_id == Gtk.ResponseType.ACCEPT:
                    path = chooser.get_file().get_path()
                    if path:
                        _write_cert(path)
                chooser.destroy()

            chooser.connect("response", on_native_response)
            chooser.show()

    def _show_change_pin_dialog(self, card_stat: SmartCardStatus):
        fresh_stat = scan_smartcard(force_refresh=True)
        if fresh_stat.card_present:
            card_stat = fresh_stat
        if card_stat.pin_locked or card_stat.pin_retries_remaining == 1:
            self.main_window.show_toast(
                "PIN change blocked: card is locked or has only 1 retry remaining."
            )
            self.main_window.refresh_all_status(force=True)
            return

        dialog = Adw.Window(title="Change PIV Card PIN", modal=True, transient_for=self.main_window)
        dialog.set_default_size(440, 440)

        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        main_box.append(header)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(400)
        clamp.set_margin_start(16)
        clamp.set_margin_end(16)
        clamp.set_margin_bottom(24)

        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        info_label = Gtk.Label(
            label="PIV PINs must consist of 6 to 8 numeric digits. Please ensure the current PIN is entered accurately.",
            wrap=True,
            xalign=0,
        )
        info_label.add_css_class("dim-label")
        form_box.append(info_label)

        low_retry_check = None
        if card_stat.pin_retries_remaining == 2:
            warn_label = Gtk.Label(
                label="Warning: Only 2 PIN verification retries remain on this token. An incorrect current PIN will drop the counter to 1 retry.",
                wrap=True,
                xalign=0,
            )
            warn_label.add_css_class("error-label")
            form_box.append(warn_label)
            low_retry_check = Gtk.CheckButton(
                label="I confirm I want to proceed with only 2 retries remaining"
            )
            form_box.append(low_retry_check)

        group = Adw.PreferencesGroup()
        current_pin_row = Adw.PasswordEntryRow(title="Current PIN")
        new_pin_row = Adw.PasswordEntryRow(title="New PIN (6-8 digits)")
        confirm_pin_row = Adw.PasswordEntryRow(title="Confirm New PIN")

        group.add(current_pin_row)
        group.add(new_pin_row)
        group.add(confirm_pin_row)
        form_box.append(group)

        status_label = Gtk.Label(label="", wrap=True, xalign=0)
        status_label.set_visible(False)
        form_box.append(status_label)

        spinner = Gtk.Spinner()
        spinner.set_visible(False)
        spinner.set_halign(Gtk.Align.CENTER)
        form_box.append(spinner)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.END)
        btn_box.set_margin_top(8)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _: dialog.close())

        submit_btn = Gtk.Button(label="Update PIN")
        submit_btn.add_css_class("suggested-action")

        def on_submit(_btn):
            if low_retry_check is not None and not low_retry_check.get_active():
                status_label.set_text("Please confirm the 2-retry warning checkbox before proceeding.")
                status_label.add_css_class("error-label")
                status_label.set_visible(True)
                return

            curr_pin = current_pin_row.get_text().strip()
            new_pin = new_pin_row.get_text().strip()
            confirm_pin = confirm_pin_row.get_text().strip()

            if not curr_pin:
                status_label.set_text("Please enter your current PIN.")
                status_label.add_css_class("error-label")
                status_label.set_visible(True)
                return

            if not (6 <= len(new_pin) <= 8 and new_pin.isdigit()):
                status_label.set_text("New PIN must be 6 to 8 numeric digits.")
                status_label.add_css_class("error-label")
                status_label.set_visible(True)
                return

            if new_pin != confirm_pin:
                status_label.set_text("New PIN and confirmation PIN do not match.")
                status_label.add_css_class("error-label")
                status_label.set_visible(True)
                return

            if curr_pin == new_pin:
                status_label.set_text("New PIN must be different from current PIN.")
                status_label.add_css_class("error-label")
                status_label.set_visible(True)
                return

            status_label.set_visible(False)
            submit_btn.set_sensitive(False)
            cancel_btn.set_sensitive(False)
            current_pin_row.set_sensitive(False)
            new_pin_row.set_sensitive(False)
            confirm_pin_row.set_sensitive(False)
            spinner.set_visible(True)
            spinner.start()

            current_pin_row.set_text("")
            new_pin_row.set_text("")
            confirm_pin_row.set_text("")

            def worker():
                from core.smartcard import change_card_pin
                ok, retries, msg = change_card_pin(curr_pin, new_pin, card_stat.reader_name)

                def on_done():
                    spinner.stop()
                    spinner.set_visible(False)
                    if ok:
                        dialog.close()
                        self.main_window.show_toast("PIV PIN updated successfully.")
                        self.main_window.refresh_all_status(force=True)
                    else:
                        submit_btn.set_sensitive(True)
                        cancel_btn.set_sensitive(True)
                        current_pin_row.set_sensitive(True)
                        new_pin_row.set_sensitive(True)
                        confirm_pin_row.set_sensitive(True)
                        status_label.set_text(f"PIN change failed: {msg}")
                        status_label.add_css_class("error-label")
                        status_label.set_visible(True)
                        self.main_window.refresh_all_status(force=True)
                    return False

                GLib.idle_add(on_done)

            threading.Thread(target=worker, daemon=True).start()

        submit_btn.connect("clicked", on_submit)
        btn_box.append(cancel_btn)
        btn_box.append(submit_btn)
        form_box.append(btn_box)

        clamp.set_child(form_box)
        main_box.append(clamp)
        dialog.set_content(main_box)
        dialog.present()
