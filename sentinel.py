import asyncio
import distro
import platform
import os
import shutil
import logging
import re
from logging.handlers import SysLogHandler

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center
from textual.widgets import Button, Static, Label, Log, TabbedContent, TabPane, Input
from textual.reactive import reactive

# Import Refactored Utils and Widgets
from sentinel_utils import get_terminal_name, StatusLED
from sentinel_backend import SentinelBackend

# 1. Path to artwork
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ASCII Art Backup
LOGO_ASCII = r"""
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) /
  /___/\__/_//_/\__/_/_//_/\__/_/"""

# --- MAIN APP ---

class SentinelApp(App):
    # CSS Optimized for TUI
    CSS = """
    Screen { background: #000000; color: #e0e0e0; }

    #sidebar {
        width: 38;
        dock: left;
        background: #000000;
        border-right: solid #222;
        padding: 0;
    }

    #logo-container {
        width: 100%;
        height: auto;
        margin: 0;
        padding: 0;
        content-align: center middle;
    }

    #logo { width: 100%; height: auto; margin: 0; padding: 0; }

    .sidebar-title {
        color: #00d4ff;
        text-style: bold;
        margin-top: 1;
        border-bottom: solid #222;
        padding: 0 1;
    }

    StatusLED { height: 1; margin-top: 1; padding: 0 1; }

    .identity-label {
        color: #ffcc00;
        margin-top: 1;
        padding: 0 1;
        text-style: italic;
        height: auto;
    }

    #main-panel { padding: 1; background: #000000; }

    .panel-title {
        color: #e0e0e0;
        text-style: bold;
        margin-bottom: 0;
    }

    TabbedContent { height: 1fr; margin-top: 0; }

    Log {
        background: #000000;
        border: solid #222;
        color: #00ff99;
        height: 1fr;
    }

    /* COMPACT INPUTS & BUTTONS */
    Input {
        height: 1;
        margin: 0 0 1 0;
        background: #222;
        border: none;
        padding: 0 1;
    }
    
    .action-btn {
        width: 100%;
        margin-top: 1;
        background: #00d4ff;
        color: black;
        text-style: bold;
        border: none;
    }
    .action-btn:hover { background: #00ff00; }
    
    .btn-row { height: auto; margin-top: 1; }
    
    .half-btn { width: 1fr; margin-right: 1; }
    .half-btn:last-of-type { margin-right: 0; }
    
    /* Specific Compact Layouts */
    .compact-row { height: auto; margin-bottom: 1; }
    .compact-input { width: 1fr; margin-right: 1; }
    .compact-input:last-of-type { margin-right: 0; }
    """

    def __init__(self):
        super().__init__()
        self.scan_process = None
        self.scan_task = None
        self.setup_logging()
        self.backend = SentinelBackend(self.logger)

    def setup_logging(self):
        self.logger = logging.getLogger("sentinel")
        self.logger.setLevel(logging.INFO)
        
        # File Handler
        fh = logging.FileHandler("sentinel.log")
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(fh)
        
        # Syslog Handler
        try:
            sh = SysLogHandler(address='/dev/log')
            sh.setFormatter(logging.Formatter('sentinel: %(message)s'))
            self.logger.addHandler(sh)
        except Exception:
            pass # Syslog might not be available

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Container(id="sidebar"):
                with Vertical(id="logo-container"):
                    with Center(): yield Static(LOGO_ASCII, id="logo")

                yield Label("SYSTEM COMPLIANCE", classes="sidebar-title")
                yield StatusLED("PCSC Daemon Service", id="led-service")
                yield StatusLED("Middleware (OpenSC)", id="led-opensc")
                yield StatusLED("CAC Token Hardware", id="led-card")
                yield StatusLED("Certificates (DoD)", id="led-certs")
                yield StatusLED("Browser Integration", id="led-browsers")
                yield StatusLED("STIG Compliance", id="led-stig")

                yield Label("IDENTITY MAPPING", classes="sidebar-title")
                yield StatusLED("Identity Validation", id="led-identity")
                yield Label("User: [None]", id="label-user", classes="identity-label")

            with Container(id="main-panel"):
                yield Label("Console", classes="panel-title")
                with TabbedContent():
                    with TabPane("Config"):
                        yield Log(id="console")
                        with Horizontal(classes="btn-row"):
                            yield Button("RUN CHECKS", id="config-btn", classes="action-btn half-btn")
                            yield Button("INSTALL CERTS", id="install-certs-btn", classes="action-btn half-btn")
                        yield Button("CONFIG BROWSERS", id="browser-btn", classes="action-btn")
                    
                    with TabPane("Scan"):
                        yield Log(id="scan-log")
                        yield Button("RUN", id="scan-btn", classes="action-btn")
                    
                    with TabPane("Cert Validation"):
                        yield Log(id="cert-log")
                        # Compact Layout: PIN Input next to Validate Button
                        with Horizontal(classes="compact-row"):
                            yield Input(placeholder="Enter CAC PIN", password=True, id="pin-input", classes="compact-input")
                            yield Button("VALIDATE", id="cert-btn", classes="action-btn compact-input")
                    
                    with TabPane("SSH"):
                        yield Log(id="ssh-log")
                        with Horizontal(classes="btn-row"):
                            yield Button("EXPORT PUBKEY", id="ssh-export-btn", classes="action-btn half-btn")
                            yield Button("SETUP SSH AGENT", id="ssh-agent-btn", classes="action-btn half-btn")
                            
                    with TabPane("PDF Sign"):
                        yield Log(id="pdf-log")
                        yield Input(placeholder="Path to PDF File", id="pdf-path-input")
                        with Horizontal(classes="compact-row"):
                            yield Input(placeholder="CAC PIN", password=True, id="pdf-pin-input", classes="compact-input")
                            yield Button("SIGN PDF", id="pdf-sign-btn", classes="action-btn compact-input")
                        
                    with TabPane("PIN Mgmt"):
                        yield Log(id="pin-log")
                        yield Button("CHECK STATUS", id="pin-status-btn", classes="action-btn")
                        
                        yield Label("Change PIN", classes="panel-title")
                        with Horizontal(classes="compact-row"):
                            yield Input(placeholder="Current PIN", password=True, id="pin-current", classes="compact-input")
                            yield Input(placeholder="New PIN", password=True, id="pin-new", classes="compact-input")
                        yield Button("CHANGE PIN", id="pin-change-btn", classes="action-btn")
                        
                        yield Label("Unblock PIN (Requires PUK)", classes="panel-title")
                        with Horizontal(classes="compact-row"):
                            yield Input(placeholder="PUK Code", password=True, id="pin-puk", classes="compact-input")
                            yield Input(placeholder="New PIN", password=True, id="pin-unblock-new", classes="compact-input")
                        yield Button("UNBLOCK PIN", id="pin-unblock-btn", classes="action-btn")

                    with TabPane("STIG"):
                        yield Log(id="stig-log")
                        with Horizontal(classes="btn-row"):
                            yield Button("RUN STIG SCAN", id="stig-run-btn", classes="action-btn half-btn")
                            yield Button("SCAP REPORT", id="scap-btn", classes="action-btn half-btn")

    async def on_mount(self):
        log = self.query_one("#console")
        log.write_line("Sentinel Identity Manager v1.0.0")
        log.write_line("-" * 30)
        log.write_line(f"OS:       {distro.name(pretty=True)}")
        log.write_line(f"Kernel:   {platform.release()}")
        log.write_line(f"Terminal: {get_terminal_name()}")
        log.write_line("-" * 30)
        log.write_line("System Ready.")
        self.log_event(f"Sentinel started on {distro.name(pretty=True)} ({platform.release()})")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "config-btn":
            await self.backend.check_services(self.query_one("#console").write_line, self.update_led_status)
        elif event.button.id == "scan-btn":
            await self.toggle_pcsc_scan()
        elif event.button.id == "cert-btn":
            pin = self.query_one("#pin-input").value
            await self.backend.validate_cert(
                self.query_one("#cert-log").write_line,
                self.update_led_status,
                lambda t: self.query_one("#label-user").update(t),
                pin=pin
            )
        elif event.button.id == "install-certs-btn":
            await self.backend.install_certs(self.query_one("#console").write_line, self.update_led_status)
        elif event.button.id == "browser-btn":
            await self.backend.configure_browsers(self.query_one("#console").write_line, self.update_led_status)
            
        # SSH Features
        elif event.button.id == "ssh-export-btn":
            await self.backend.export_ssh_key(self.query_one("#ssh-log").write_line)
        elif event.button.id == "ssh-agent-btn":
            await self.backend.setup_ssh_agent(self.query_one("#ssh-log").write_line)
            
        # PDF Features
        elif event.button.id == "pdf-sign-btn":
            path = self.query_one("#pdf-path-input").value
            pin = self.query_one("#pdf-pin-input").value
            await self.backend.sign_pdf(self.query_one("#pdf-log").write_line, path, pin)
            
        # PIN Mgmt Features
        elif event.button.id == "pin-status-btn":
            await self.backend.check_pin_status(self.query_one("#pin-log").write_line)
        elif event.button.id == "pin-change-btn":
            current = self.query_one("#pin-current").value
            new = self.query_one("#pin-new").value
            await self.backend.change_pin(self.query_one("#pin-log").write_line, current, new)
        elif event.button.id == "pin-unblock-btn":
            puk = self.query_one("#pin-puk").value
            new = self.query_one("#pin-unblock-new").value
            await self.backend.unblock_pin(self.query_one("#pin-log").write_line, puk, new)
            
        elif event.button.id == "scap-btn":
            await self.backend.generate_scap_report(self.query_one("#console").write_line)
        elif event.button.id == "stig-run-btn":
            await self.backend.run_stig_scan(self.query_one("#stig-log").write_line, self.update_led_status)

    def update_led_status(self, led_id, status):
        self.query_one(f"#{led_id}").status = status

    async def toggle_pcsc_scan(self):
        """Starts or stops the constant background pcsc_scan."""
        scan_log = self.query_one("#scan-log")
        btn = self.query_one("#scan-btn")

        # If a process is already running, stop it
        if self.scan_process is not None:
            self.scan_process.terminate()
            if self.scan_task:
                self.scan_task.cancel()
            self.scan_process = None
            self.scan_task = None
            btn.label = "RUN"
            btn.variant = "default"
            scan_log.write_line("\n[Monitoring Stopped]")
            return

        # Start a new constant scan process
        cmd_path = shutil.which("pcsc_scan")
        if not cmd_path:
            scan_log.write_line("Error: 'pcsc_scan' binary not found.")
            return

        btn.label = "STOP"
        scan_log.write_line("\n[Starting Constant Monitoring...]")

        try:
            self.scan_process = await asyncio.create_subprocess_shell(
                cmd_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            # Fire and forget a task to read the output stream
            self.scan_task = asyncio.create_task(self.read_scan_stream(self.scan_process, scan_log))
        except Exception as e:
            scan_log.write_line(f"Process Error: {e}")
            btn.label = "RUN"

    async def read_scan_stream(self, proc, log_widget):
        """Reads output line-by-line and filters out the spinner 'gibberish'."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[[[0-?]*[ -/]*[@-~])')
        try:
            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                
                # Decode and strip ANSI codes
                raw_line = line_bytes.decode(errors='replace')
                line = ansi_escape.sub('', raw_line).strip()

                # FILTER: Ignore lines that are just spinner characters or empty
                if not line or line in ["\\", "|", "/", "-", ""]:
                    continue

                # STRICT FILTER: Only allow known good lines
                valid_prefixes = ["Reader", "Event", "Card", "ATR", "Scanning", "Using"]
                is_date = re.match(r'^[A-Z][a-z]{2} [A-Z][a-z]{2} \d+', line) 
                is_known_prefix = any(line.startswith(p) for p in valid_prefixes)
                is_device_line = re.match(r'^\d+: .*', line)

                if not (is_date or is_known_prefix or is_device_line):
                    continue

                log_widget.write_line(line)

                # Real-time Hardware LED Updates
                if "Card inserted" in line:
                    self.query_one("#led-card").status = "success"
                    self.log_event("Hardware: Card inserted")
                elif "Card removed" in line:
                    self.query_one("#led-card").status = "idle"
                    self.log_event("Hardware: Card removed")
        except asyncio.CancelledError:
            pass 

    def log_event(self, message, level="info"):
        """Logs to both the internal SIEM logger and the UI console if needed."""
        if level == "info":
            self.logger.info(message)
        elif level == "error":
            self.logger.error(message)
        elif level == "warning":
            self.logger.warning(message)

if __name__ == "__main__":
    SentinelApp().run()