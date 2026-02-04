import os
import shutil
import subprocess
from textual.widgets import Static
from textual.reactive import reactive

# --- UTILS ---
def get_terminal_name():
    """Identifies the terminal environment."""
    if os.environ.get("GHOSTTY_BIN_NAME") or os.environ.get("GHOSTTY_RESOURCES_DIR"):
        return "Ghostty"
    term = os.environ.get("TERM_PROGRAM") or os.environ.get("TERM")
    return term.capitalize() if term else "Linux Console"

# --- STRATEGY PATTERN (OS Detection) ---
class LinuxStrategy:
    def check_installed(self, pkg): return shutil.which(pkg) is not None
    def is_service_running(self, service="pcscd"):
        try:
            result = subprocess.run(['systemctl', 'is-active', service],
                                    capture_output=True, text=True)
            return result.stdout.strip() == "active"
        except: return False

def get_strategy():
    return LinuxStrategy()

# --- WIDGETS ---

class StatusLED(Static):
    status = reactive("idle")
    frame_index = reactive(0)
    
    # Spinner frames
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def on_mount(self):
        self.set_interval(0.1, self.update_frame)

    def update_frame(self):
        if self.status == "loading":
            self.frame_index = (self.frame_index + 1) % len(self.FRAMES)

    def render(self) -> str:
        icons = {"idle": "○", "success": "●", "error": "⊗"}
        colors = {"idle": "#333", "loading": "#ffcc00", "success": "#00ff00", "error": "#ff3333"}
        
        if self.status == "loading":
            icon = self.FRAMES[self.frame_index]
        else:
            icon = icons.get(self.status, "○")
            
        color = colors.get(self.status, "#333")
        return f"[{color}]{icon}[/] {self.label}"

    def __init__(self, label: str, id: str):
        super().__init__(id=id)
        self.label = label
