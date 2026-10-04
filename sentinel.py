"""Sentinel — Textual user interface.

The UI owns widgets, styling and event dispatch. It never runs a subprocess:
every operation is delegated to `SentinelBackend`, which reports progress as
`Event` values. That split is what lets the whole backend be tested headlessly,
including the privileged paths, with no card, no root and no TTY.

The same backend has a headless interface -- `sentinel setup`, `sentinel doctor`
and `sentinel-cli` -- which does everything this does without a terminal. See
the README.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform as platform_mod
import re
import shutil
from logging.handlers import RotatingFileHandler

import distro
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Center, Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Log, Static, TabbedContent, TabPane

import sentinel_setup
from sentinel_backend import Event, SentinelBackend
from sentinel_platform import browsers_running
from sentinel_platform import TRUST_ANCHOR_NAME
from sentinel_utils import StatusLED, get_terminal_name

VERSION = "2.2.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Hoisted out of the per-line loop: recompiling this for every line of
# pcsc_scan output was measurable on a busy reader.
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Control characters and newlines, stripped from anything untrusted before it
# reaches the console. A certificate subject or reader name containing a
# newline must not be able to forge an extra log line.
CONTROL_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F\r\n\t]")

LOGO_ASCII = r"""
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) /
  /___/\__/_//_/\__/_/_//_/\__/_/"""


class CardPromptScreen(ModalScreen[bool]):
    """A modal that asks the user to insert their CAC.

    Dismisses on either key or button, and reports which, so the caller can tell
    "acknowledged, I will insert it" from "closed without reading it". Kept to
    one short question because it interrupts a running operation: anything
    longer belongs in the console, which is still being written to underneath.
    """

    BINDINGS = [
        Binding("escape", "dismiss(False)", "Close"),
        Binding("enter", "dismiss(True)", "I inserted it"),
    ]

    DEFAULT_CSS = """
    CardPromptScreen {
        align: center middle;
        background: #000000 70%;
    }
    #card-prompt-box {
        width: 64;
        height: auto;
        padding: 1 2;
        background: #111111;
        border: thick #ffcc00;
    }
    #card-prompt-title {
        color: #ffcc00;
        text-style: bold;
        width: 100%;
        margin-bottom: 1;
    }
    #card-prompt-detail {
        color: #e0e0e0;
        width: 100%;
        height: auto;
        margin-bottom: 1;
    }
    #card-prompt-btn {
        width: 100%;
        background: #ffcc00;
        color: black;
        text-style: bold;
        border: none;
    }
    """

    def __init__(self, detail: str):
        super().__init__()
        self.detail = detail or "No card was detected in the reader."

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(id="card-prompt-box"):
                yield Label("INSERT YOUR CAC", id="card-prompt-title")
                yield Static(
                    f"{self.detail}\n\n"
                    "Put your Common Access Card in the reader, then run "
                    "CONFIG BROWSERS again. Everything else is already set up.",
                    id="card-prompt-detail",
                )
                yield Button("I INSERTED IT  [enter]", id="card-prompt-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "card-prompt-btn":
            self.dismiss(True)


class SentinelApp(App):
    CSS_PATH = "sentinel.tcss"

    BINDINGS = [
        ("enter", "run('setup')", "Set up everything"),
        ("d", "run('diagnose')", "Why no card?"),
        ("c", "run('check')", "Checks"),
        ("i", "run('install-certs')", "Install certs"),
        ("b", "run('configure-browsers')", "Browsers"),
        ("f", "run('fix-opensc')", "Fix reader hang"),
        ("s", "toggle_scan", "Scan"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.scan_process = None
        self.scan_task = None
        self._busy = False
        self.logger = setup_logging()
        self.backend = SentinelBackend(self.logger)

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Container(id="sidebar"):
                with Vertical(id="logo-container"):
                    with Center():
                        yield Static(LOGO_ASCII, id="logo")
                yield Label("SYSTEM COMPLIANCE", classes="sidebar-title")
                yield StatusLED("PCSC Daemon Service", id="led-service")
                yield StatusLED("Middleware (OpenSC)", id="led-opensc")
                yield StatusLED("CAC Token Hardware", id="led-card")
                yield StatusLED("Certificates (DoD)", id="led-certs")
                yield StatusLED("Browser Integration", id="led-browsers")

            with Container(id="main-panel"):
                yield Label("Console", classes="panel-title")
                with TabbedContent():
                    with TabPane("Setup"):
                        yield Log(id="console")
                        yield Button(
                            "SET UP EVERYTHING  [enter]", id="setup-btn",
                            classes="action-btn primary-btn",
                        )
                        yield Static(id="verdict")
                        yield Button(
                            "WHY IS MY CARD NOT SEEN?  [d]", id="diagnose-btn",
                            classes="action-btn",
                        )
                        with Horizontal(classes="btn-row"):
                            yield Button(
                                "RUN CHECKS [c]", id="config-btn",
                                classes="action-btn half-btn",
                            )
                            yield Button(
                                "INSTALL CERTS [i]", id="install-certs-btn",
                                classes="action-btn half-btn",
                            )
                        yield Button(
                            "CONFIG BROWSERS [b]", id="browser-btn", classes="action-btn",
                        )
                        yield Button(
                            "FIX 26s READER HANG [f]", id="opensc-btn", classes="action-btn",
                        )
                    with TabPane("Scan"):
                        yield Log(id="scan-log")
                        yield Button("RUN [s]", id="scan-btn", classes="action-btn")
                yield Label(
                    "enter set up  d why no card  c checks  i certs  "
                    "b browsers  f reader  s scan  q quit",
                    classes="tab-hint",
                )

    async def on_mount(self) -> None:
        self.write("Sentinel Identity Manager v" + VERSION)
        self.write("-" * 30)
        self.write(f"OS:       {distro.name(pretty=True)}")
        self.write(f"Kernel:   {platform_mod.release()}")
        self.write(f"Terminal: {get_terminal_name()}")
        self.write("-" * 30)
        self.write(f"Ready. Trust bundle: {TRUST_ANCHOR_NAME}")
        self.logger.info(f"Sentinel {VERSION} started on {distro.name(pretty=True)}")

    # --- output -------------------------------------------------------------

    def write(self, text: str) -> None:
        """Write one line to the console.

        Textual's `Log.write_line` takes the line and nothing else: it does not
        parse Rich markup and it strips control characters itself. What this
        method does add is newline sanitisation, so a certificate subject or a
        reader name containing a newline cannot forge an extra log line.

        Failures are reported rather than swallowed. A silently-failing console
        is exactly the class of defect this project spent v2.0.0 removing.
        """
        text = CONTROL_RE.sub(" ", str(text))
        try:
            self.query_one("#console", Log).write_line(text)
        except Exception as exc:
            self.logger.error(f"console write failed: {exc}")

    def write_scan(self, line: str) -> None:
        try:
            self.query_one("#scan-log", Log).write_line(CONTROL_RE.sub(" ", line))
        except Exception as exc:
            self.logger.error(f"scan log write failed: {exc}")

    def emit(self, event: Event) -> None:
        if event.kind == "log":
            self.write(event.payload)
        elif event.kind == "led":
            self.set_led(event.payload, event.status)
        elif event.kind == "card-prompt":
            self.prompt_for_card(event.payload)

    def prompt_for_card(self, detail: str) -> None:
        """Ask the user to insert their CAC, in a window they cannot miss.

        This is the one condition where the tool genuinely cannot proceed on the
        user's behalf: a card that is not in the reader cannot be shown working.
        A line in the console is easy to scroll past while the LED sits red, and
        the natural conclusion is that the tool is broken. So it gets a modal,
        which is also the only reliable way to interrupt a running operation in
        Textual without cancelling it.

        The popup carries the reason as well as the request, because "no reader"
        and "no card" need different fixes and the user should not have to work
        out which one applies.
        """
        try:
            self.push_screen(CardPromptScreen(detail), self._on_card_prompt_closed)
        except Exception as exc:  # a popup must never take the app down
            self.logger.error(f"could not show the card prompt: {exc}")
            self.write("Insert your CAC into the reader, then run CONFIG BROWSERS again.")

    def _on_card_prompt_closed(self, retry: bool | None) -> None:
        if retry:
            self.write("Insert your CAC, then press b to run CONFIG BROWSERS again.")

    def set_led(self, led_id: str, status: str) -> None:
        try:
            self.query_one(f"#{led_id}", StatusLED).status = status
        except Exception:
            pass

    # --- dispatch -----------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "setup-btn": "setup",
            "diagnose-btn": "diagnose",
            "config-btn": "check",
            "install-certs-btn": "install-certs",
            "browser-btn": "configure-browsers",
            "opensc-btn": "fix-opensc",
        }
        if event.button.id in actions:
            await self.action_run(actions[event.button.id])

    async def action_run(self, action: str) -> None:
        if self._busy:
            self.write("Busy with another operation; wait for it to finish.")
            return
        handlers = {
            "check": self.backend.check_services,
            "install-certs": self.backend.install_certs,
            "configure-browsers": self.backend.configure_browsers,
            "fix-opensc": self.backend.fix_opensc_conf,
            "diagnose": self.backend.diagnose_reader,
        }
        if action == "setup":
            await self.run_setup()
            return
        handler = handlers.get(action)
        if handler is None:
            return
        self._busy = True
        try:
            await handler(self.emit, dry_run=False)
        except Exception as exc:
            # A crash in one operation must not take the whole app down.
            self.write(f"UNEXPECTED ERROR: {exc}")
            self.logger.exception(f"{action} failed")
        finally:
            self._busy = False

    async def run_setup(self) -> None:
        """Every step in order, then a verdict in plain language on screen.

        This is the path a non-technical user should take, and it is why the
        Enter key is bound to it before anything else. Four separate buttons
        means four chances to skip the one that matters and conclude the tool
        is broken.
        """
        if self._busy:
            self.write("Busy with another operation; wait for it to finish.")
            return
        self._busy = True
        self.show_verdict("Setting up... this takes a moment.", working=True)
        try:
            results: dict = {}
            for step in sentinel_setup.SETUP_STEPS:
                self.write(f"\n>>> {step}")
                handler = {
                    "diagnose": self.backend.diagnose_reader,
                    "fix-opensc": self.backend.fix_opensc_conf,
                    "check": self.backend.check_services,
                    "install-certs": self.backend.install_certs,
                    "configure-browsers": self.backend.configure_browsers,
                }[step]
                results[step] = await handler(self.emit, dry_run=False)
            verdict = sentinel_setup.summarise(
                results, browsers_running=bool(browsers_running())
            )
            self.show_verdict(verdict)
        except Exception as exc:
            self.write(f"UNEXPECTED ERROR: {exc}")
            self.logger.exception("setup failed")
            self.show_verdict(f"Something went wrong: {exc}", working=False)
        finally:
            self._busy = False

    def show_verdict(self, verdict, working: bool = False) -> None:
        """Put the answer where the user is looking, not buried in the log."""
        try:
            widget = self.query_one("#verdict", Static)
        except Exception:
            return
        if working:
            widget.update(f"[#ffcc00]{verdict}[/]")
            return
        head = "READY" if verdict.works else "NOT READY"
        colour = "#00ff00" if verdict.works else "#ff5555"
        body = [f"[{colour}]{head}[/]", verdict.headline, ""]
        for step in verdict.next_steps:
            body.append(f"  {step}")
        if verdict.problems:
            body.append("")
            body.append("[#ffcc00]To fix:[/]")
            for problem in verdict.problems:
                body.append(f"  - {problem.splitlines()[0]}")
        widget.update("\n".join(body))
        widget.display = True

    # --- card scanning ------------------------------------------------------

    async def action_toggle_scan(self) -> None:
        await self.toggle_pcsc_scan()

    async def toggle_pcsc_scan(self) -> None:
        """Start or stop the live pcsc_scan monitor."""
        log_widget = self.query_one("#scan-log", Log)
        button = self.query_one("#scan-btn", Button)

        if self.scan_process is not None:
            self.stop_scan(log_widget, button)
            return

        cmd_path = shutil.which("pcsc_scan")
        if not cmd_path:
            log_widget.write_line("Error: 'pcsc_scan' is not installed.")
            return

        button.label = "STOP [s]"
        log_widget.write_line("[Monitoring card events...]")

        try:
            # exec with an argument list, not a shell. The path comes from
            # shutil.which and still does not belong in a shell string.
            self.scan_process = await asyncio.create_subprocess_exec(
                cmd_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self.scan_task = asyncio.create_task(self.read_scan_stream(self.scan_process))
        except OSError as exc:
            log_widget.write_line(f"Could not start pcsc_scan: {exc}")
            self.scan_process = None
            button.label = "RUN [s]"

    def stop_scan(self, log_widget, button) -> None:
        proc, self.scan_process = self.scan_process, None
        if self.scan_task:
            self.scan_task.cancel()
            self.scan_task = None
        if proc is not None:
            try:
                proc.terminate()
            except ProcessLookupError:
                # Already exited on its own; terminating is not an error.
                pass
        button.label = "RUN [s]"
        log_widget.write_line("[Monitoring stopped]")

    async def read_scan_stream(self, proc) -> None:
        """Pass pcsc_scan output through, and drive the card LED from it.

        The previous version filtered against a hardcoded list of string
        prefixes guessed at another program's output format, which discarded
        nearly everything real pcsc_scan emits. The only rule applied here is
        that a line is a line; duplicate consecutive lines are collapsed so a
        chatty reader does not flood the widget.
        """
        last = None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = ANSI_RE.sub("", raw.decode(errors="replace")).rstrip()
                if not line or line == last:
                    continue
                last = line
                self.write_scan(line)

                # Card transitions, matched loosely because the wording varies
                # across pcsc-lite versions.
                lowered = line.lower()
                if "card inserted" in lowered or "card detected" in lowered:
                    self.set_led("led-card", "success")
                    self.logger.info("Hardware: card inserted")
                elif "card removed" in lowered or "card removed" in lowered:
                    self.set_led("led-card", "idle")
                    self.logger.info("Hardware: card removed")
        except asyncio.CancelledError:
            pass
        except (OSError, ValueError):
            pass
        finally:
            self.scan_process = None
            self.scan_task = None

    async def on_unmount(self) -> None:
        if self.scan_process is not None:
            self.stop_scan(self.query_one("#scan-log", Log), self.query_one("#scan-btn", Button))


def setup_logging() -> logging.Logger:
    """Rotating file log with owner-only permissions.

    Three properties the previous handler lacked: the path is resolved against
    the install directory rather than the current working directory, the file is
    created 0600 rather than world-readable under the default umask, and it
    rotates instead of growing without bound.

    Syslog is intentionally not used. A second, unbounded, rarely-inspected
    sink that receives every message is a poor trade for this application, and
    nothing in the log needs to be shipped off-box.
    """
    logger = logging.getLogger("sentinel")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_path = os.path.join(SCRIPT_DIR, "sentinel.log")
    try:
        handler = RotatingFileHandler(
            log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8",
        )
        # Create it 0600 regardless of umask, and tighten an existing file too.
        os.chmod(log_path, 0o600)
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)
    except OSError:
        # A read-only install directory must not stop the app from starting.
        pass

    return logger


if __name__ == "__main__":
    SentinelApp().run()
