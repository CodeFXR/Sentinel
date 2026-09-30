"""Small UI helpers and terminal detection.

Deliberately thin. The service probe that used to live here as a
single-implementation "strategy" factory is now `sentinel_platform.service_is_active`,
because a factory with one implementation and one platform was indirection with
no payoff, and its bare `except:` was swallowing KeyboardInterrupt.
"""

from __future__ import annotations

import os

from textual.reactive import reactive
from textual.widgets import Static


def get_terminal_name() -> str:
    """Identify the terminal environment, for the status banner."""
    if os.environ.get("GHOSTTY_BIN_NAME") or os.environ.get("GHOSTTY_RESOURCES_DIR"):
        return "Ghostty"
    term = os.environ.get("TERM_PROGRAM") or os.environ.get("TERM")
    return term.capitalize() if term else "Linux Console"


class StatusLED(Static):
    """A one-line status indicator.

    Four states, and the distinction between them is the point: `idle` means
    "not checked or nothing to report", which must not look like success. The
    previous version had three and used `loading` for "no card inserted", so the
    spinner ran forever and the dashboard implied a fault where none existed.

    The spinner timer starts when the LED enters `loading` and stops when it
    leaves, instead of running a 10 Hz callback on every LED for the lifetime of
    the app.
    """

    status = reactive("idle")
    frame_index = reactive(0)

    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    ICONS = {
        "idle": "○",
        "success": "●",
        "error": "⊗",
        "loading": "",  # spinner frame is used instead
    }
    COLORS = {
        "idle": "#555555",
        "loading": "#ffcc00",
        "success": "#00ff00",
        "error": "#ff3333",
    }

    def __init__(self, label: str, id: str):
        super().__init__(id=id)
        self.label = label
        self._timer = None

    def on_mount(self) -> None:
        self._sync_timer()

    def watch_status(self, _old: str, _new: str) -> None:
        self._sync_timer()

    def _sync_timer(self) -> None:
        """Run the spinner only while this LED is actually loading."""
        if not self.is_mounted:
            return
        if self.status == "loading":
            if self._timer is None:
                self._timer = self.set_interval(0.1, self._advance)
        elif self._timer is not None:
            self._timer.stop()
            self._timer = None
            self.frame_index = 0

    def _advance(self) -> None:
        self.frame_index = (self.frame_index + 1) % len(self.FRAMES)

    def render(self) -> str:
        icon = self.FRAMES[self.frame_index] if self.status == "loading" else self.ICONS.get(
            self.status, "○"
        )
        return f"[{self.COLORS.get(self.status, '#555555')}]{icon}[/] {self.label}"
