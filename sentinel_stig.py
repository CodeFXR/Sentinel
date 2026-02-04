import asyncio
import shutil
import os
import subprocess
import re

class StigChecker:
    """
    Embedded STIG Compliance logic for Linux Smart Card & Identity Management.
    Uses generic SC-LINUX-XXX naming for broad applicability.
    """

    def __init__(self):
        self.rules = [
            {
                "id": "SC-LINUX-001",
                "title": "Smart Card Daemon (pcscd) must be active",
                "severity": "HIGH",
                "check_func": self.check_pcscd_active
            },
            {
                "id": "SC-LINUX-002",
                "title": "Smart Card Middleware (OpenSC) must be installed",
                "severity": "HIGH",
                "check_func": self.check_opensc_installed
            },
            {
                "id": "SC-LINUX-003",
                "title": "SSH Daemon must be configured to use PAM",
                "severity": "MEDIUM",
                "check_func": self.check_ssh_pam
            },
            {
                "id": "SC-LINUX-004",
                "title": "GNOME Smart Card removal action must lock the screen",
                "severity": "MEDIUM",
                "check_func": self.check_gnome_removal_action
            },
            {
                "id": "SC-LINUX-005",
                "title": "System must utilize sssd for authentication",
                "severity": "MEDIUM",
                "check_func": self.check_sssd_active
            },
             {
                "id": "SC-LINUX-006",
                "title": "Firefox must have a PKCS#11 Security Device configured",
                "severity": "LOW",
                "check_func": self.check_firefox_pkcs11
            },
            {
                "id": "SC-LINUX-007",
                "title": "Authselect profile must enable smartcard support",
                "severity": "HIGH",
                "check_func": self.check_authselect
            },
            {
                "id": "SC-LINUX-008",
                "title": "DoD Root CA certificates must be installed in system trust",
                "severity": "HIGH",
                "check_func": self.check_root_ca_trust
            },
            {
                "id": "SC-LINUX-009",
                "title": "OpenSSL PKCS#11 module must be installed",
                "severity": "MEDIUM",
                "check_func": self.check_openssl_pkcs11
            },
            {
                "id": "SC-LINUX-010",
                "title": "PCSC Lite package must be installed",
                "severity": "MEDIUM",
                "check_func": self.check_pcsclite_pkg
            }
        ]

    def load_rules(self):
        """Returns the list of rule definitions."""
        return self.rules

    # --- CHECK FUNCTIONS ---

    async def check_pcscd_active(self):
        """Check if pcscd service is active."""
        try:
            cmd = "systemctl is-active pcscd"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            status = stdout.decode().strip()
            if status == "active":
                return True, "Service is active."
            return False, f"Service state: {status}"
        except Exception as e:
            return False, f"Error checking service: {e}"

    async def check_opensc_installed(self):
        """Check if opensc is installed via rpm/dpkg or path."""
        if shutil.which("opensc-tool"):
             return True, "opensc-tool binary found in PATH."
        return False, "opensc-tool not found."

    async def check_ssh_pam(self):
        """Check /etc/ssh/sshd_config for 'UsePAM yes'."""
        config_path = "/etc/ssh/sshd_config"
        if not os.path.exists(config_path):
             return False, "sshd_config not found."
        
        try:
            with open(config_path, "r") as f:
                content = f.read()
            if re.search(r"^\s*UsePAM\s+yes", content, re.MULTILINE):
                return True, "'UsePAM yes' found in config."
            return False, "'UsePAM yes' not found or commented out."
        except PermissionError:
             return False, "Permission denied reading sshd_config (Need Root?)"
        except Exception as e:
             return False, f"Error reading config: {e}"

    async def check_gnome_removal_action(self):
        """Check GNOME settings for smart card removal action."""
        if not shutil.which("gsettings"):
            return False, "gsettings tool not found (Not GNOME?)."
            
        try:
            cmd = "gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip().replace("'", "")
            
            if output == "lock-screen":
                return True, "Removal action is set to 'lock-screen'."
            elif output == "none":
                 return False, "Removal action is set to 'none'."
            return False, f"Current setting: {output}"
        except Exception as e:
             return False, f"Error checking gsettings: {e}"

    async def check_sssd_active(self):
        """Check if sssd service is active."""
        try:
            cmd = "systemctl is-active sssd"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            status = stdout.decode().strip()
            if status == "active":
                return True, "SSSD Service is active."
            return False, f"SSSD Service state: {status}"
        except Exception as e:
            return False, f"Error checking service: {e}"

    async def check_firefox_pkcs11(self):
        """Check if NSS DB has the module (basic check)."""
        db_path = os.path.expanduser("~/.pki/nssdb")
        if os.path.exists(db_path):
             return True, "NSS Database found."
        return False, "NSS Database (~/.pki/nssdb) missing."

    async def check_authselect(self):
        """Check if authselect is configured with smartcard support."""
        if not shutil.which("authselect"):
            return False, "authselect tool not found."
        
        try:
            cmd = "authselect current"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip()
            
            if "with-smartcard" in output:
                return True, "'with-smartcard' feature enabled."
            return False, "'with-smartcard' feature NOT detected."
        except Exception as e:
            return False, f"Error checking authselect: {e}"

    async def check_root_ca_trust(self):
        """Check if DoD Root CAs are present in the trust anchors."""
        anchor_path = "/etc/pki/ca-trust/source/anchors/"
        if not os.path.exists(anchor_path):
             return False, "Anchors directory not found."
             
        found = False
        try:
            for f in os.listdir(anchor_path):
                if "DoD" in f or "dod" in f:
                    found = True
                    break
        except Exception:
            pass

        if found:
            return True, "DoD Certificates found in /etc/pki/ca-trust/source/anchors/."
        return False, "No DoD-named certificates found in anchors directory."

    async def check_openssl_pkcs11(self):
        """Check for openssl-pkcs11 (engine) presence."""
        # RHEL 9 often uses the pkcs11-provider or engine.
        # Simple check: look for library or rpm
        libs = ["/usr/lib64/engines-3/pkcs11.so", "/usr/lib64/libpkcs11.so"]
        if any(os.path.exists(l) for l in libs):
            return True, "OpenSSL PKCS#11 module found."
        
        # Fallback: check RPM
        if shutil.which("rpm"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    "rpm -q openssl-pkcs11", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if "openssl-pkcs11" in stdout.decode():
                    return True, "Package 'openssl-pkcs11' installed."
            except:
                pass
                
        return False, "OpenSSL PKCS#11 module not found."

    async def check_pcsclite_pkg(self):
        """Check for pcsc-lite package."""
        if shutil.which("rpm"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    "rpm -q pcsc-lite", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if "pcsc-lite" in stdout.decode():
                    return True, "Package 'pcsc-lite' installed."
            except:
                pass
        
        # Fallback: check for library
        if os.path.exists("/usr/lib64/libpcsclite.so.1"):
             return True, "libpcsclite.so.1 found."
             
        return False, "pcsc-lite package not found."
