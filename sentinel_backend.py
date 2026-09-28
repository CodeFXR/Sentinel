import asyncio
import os
import shutil

from sentinel_utils import get_strategy


class SentinelBackend:
    def __init__(self, logger):
        self.logger = logger
        self.strategy = get_strategy()
        self.SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    async def check_services(self, log_writer, update_led):
        log_writer("\n--- PROBING CORE SERVICES ---")
        self.logger.info("Starting system compliance check")
        
        # Reset LEDs
        update_led("led-service", "loading")
        update_led("led-opensc", "loading")
        # led-certs, led-browsers, led-stig are NOT reset (per user request)
        
        # 1. Check PCSC Service
        await asyncio.sleep(0.5)
        if self.strategy.is_service_running():
            log_writer("OK: pcscd is active.")
            update_led("led-service", "success")
            self.logger.info("PCSC Service: Active")
        else:
            log_writer("WARN: pcscd is inactive. Attempting auto-start...")
            self.logger.warning("PCSC Service: Inactive (attempting auto-start)")
            try:
                start_proc = await asyncio.create_subprocess_shell(
                    "pkexec systemctl start pcscd",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await start_proc.communicate()
            except Exception as e:
                log_writer(f"Auto-start failed: {e}")
            
            if self.strategy.is_service_running():
                log_writer("SUCCESS: pcscd started.")
                update_led("led-service", "success")
                self.logger.info("PCSC Service: Started successfully")
            else:
                log_writer("ERROR: pcscd failed to start.")
                log_writer("Manual Fix: sudo systemctl enable --now pcscd")
                update_led("led-service", "error")
                self.logger.error("PCSC Service: Failed to start")

        # 2. Check Dependencies
        missing = []
        for pkg in ["pcsc_scan", "pkcs11-tool", "opensc-tool"]:
            if not self.strategy.check_installed(pkg):
                missing.append(pkg)
        
        if missing:
             log_writer(f"WARNING: Missing tools: {', '.join(missing)}")
             log_writer("Install via: dnf install pcsc-tools opensc")
             self.logger.warning(f"Dependencies: Missing {', '.join(missing)}")
        else:
             log_writer("OK: Required tools installed.")
             self.logger.info("Dependencies: OK")

        # 3. Check Hardware/Middleware
        update_led("led-opensc", "loading")
        p11_path = shutil.which("pkcs11-tool")
        if p11_path:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"{p11_path} -L",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode().strip()
                if "Slot" in output:
                    log_writer("OK: PKCS#11 Slots detected.")
                    update_led("led-opensc", "success")
                    self.logger.info("Middleware: PKCS#11 Slots detected")
                    if "piv_II" in output or "CAC" in output or "PIV" in output:
                         log_writer("Card Type: PIV/CAC-compatible token found.")
                         self.logger.info("Middleware: PIV/CAC token detected")
                else:
                    log_writer("WARNING: No PKCS#11 slots found (Card missing?)")
                    update_led("led-opensc", "loading")
                    self.logger.warning("Middleware: No slots found")
            except Exception as e:
                log_writer(f"Middleware Error: {e}")
                update_led("led-opensc", "error")
                self.logger.error(f"Middleware Error: {e}")

    async def install_certs(self, log_writer, update_led):
        log_writer("\n--- INSTALLING DOD CERTIFICATES ---")
        self.logger.info("Starting DoD Certificate Installation")
        
        update_led("led-certs", "loading")

        # Source file (Mega Chain: Roots + Intermediates from ALL bundles)
        chain_file = os.path.join(self.SCRIPT_DIR, "DoD_Mega_Chain.pem")
        if not os.path.exists(chain_file):
            log_writer(f"ERROR: Source file not found: {chain_file}")
            log_writer("Run create_mega_chain.py to generate it.")
            update_led("led-certs", "error")
            return

        target_dir = "/etc/pki/ca-trust/source/anchors/"
        target_file = os.path.join(target_dir, "DoD_Full_Chain.pem")
        
        log_writer(f"Source: {os.path.basename(chain_file)}")
        log_writer(f"Target: {target_dir}")
        log_writer("Requesting privileges via pkexec...")

        try:
            cmd = f'pkexec sh -c "cp \'{chain_file}\' \'{target_file}\' && update-ca-trust"'
            
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                log_writer("SUCCESS: Certificates installed and trust store updated.")
                self.logger.info("DoD Certificates installed successfully.")
                update_led("led-certs", "success")
            else:
                err_msg = stderr.decode().strip() or "Unknown error"
                log_writer(f"FAILURE: {err_msg}")
                self.logger.error(f"Certificate installation failed: {err_msg}")
                update_led("led-certs", "error")
                
        except Exception as e:
            log_writer(f"Execution Error: {str(e)}")
            self.logger.error(f"Installation execution error: {e}")
            update_led("led-certs", "error")

    async def configure_browsers(self, log_writer, update_led):
        log_writer("\n--- CONFIGURING BROWSERS (NSS DB) ---")
        self.logger.info("Starting Browser Configuration")
        
        update_led("led-browsers", "loading")

        modutil = shutil.which("modutil")
        lib_path = "/usr/lib64/opensc-pkcs11.so"
        
        if not modutil:
            log_writer("ERROR: 'modutil' not found (install nss-tools).")
            update_led("led-browsers", "error")
            return
        if not os.path.exists(lib_path):
             log_writer(f"ERROR: Library not found at {lib_path}")
             update_led("led-browsers", "error")
             return

        nss_paths = [os.path.expanduser("~/.pki/nssdb")]
        
        firefox_base = os.path.expanduser("~/.mozilla/firefox")
        if os.path.exists(firefox_base):
            for item in os.listdir(firefox_base):
                if item.endswith(".default") or item.endswith(".default-release") or "default" in item:
                    full_path = os.path.join(firefox_base, item)
                    if os.path.isdir(full_path):
                        nss_paths.append(full_path)

        flatpak_bases = [
            os.path.expanduser("~/.var/app/org.mozilla.firefox/.mozilla/firefox"),
            os.path.expanduser("~/.var/app/org.mozilla.Firefox/.mozilla/firefox")
        ]
        for fp_base in flatpak_bases:
            if os.path.exists(fp_base):
                for item in os.listdir(fp_base):
                    if "default" in item:
                        full_path = os.path.join(fp_base, item)
                        if os.path.isdir(full_path):
                            nss_paths.append(full_path)

        log_writer(f"Found {len(nss_paths)} NSS databases to update.")

        success_count = 0
        for db_path in nss_paths:
            if not os.path.exists(db_path):
                continue
            
            log_writer(f"Updating: {db_path}...")
            self.logger.info(f"Browser Config: Checking {db_path}...")
            await asyncio.sleep(0.05) 

            try:
                check_cmd = [modutil, "-dbdir", f"sql:{db_path}", "-list", "DoD CAC"]
                check_proc = await asyncio.create_subprocess_exec(
                    *check_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(check_proc.communicate(), timeout=5.0)

                if check_proc.returncode == 0:
                    log_writer("  -> 'DoD CAC' module already exists. Skipping.")
                    success_count += 1
                else:
                    add_cmd = [modutil, "-force", "-dbdir", f"sql:{db_path}", "-add", "DoD CAC", "-libfile", lib_path]
                    proc = await asyncio.create_subprocess_exec(
                        *add_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                        
                        if proc.returncode == 0:
                            log_writer("  -> SUCCESS: Module added.")
                            success_count += 1
                        else:
                            log_writer(f"  -> FAILED: {stderr.decode().strip()}")
                    except asyncio.TimeoutError:
                        log_writer("  -> ERROR: Operation timed out.")
                        if proc.returncode is None:
                            try:
                                proc.kill()
                            except ProcessLookupError:
                                pass
                        
            except Exception as e:
                log_writer(f"  -> ERROR: {e}")

        log_writer("Browser configuration complete. Restart browsers to apply.")
        update_led("led-browsers", "success")
