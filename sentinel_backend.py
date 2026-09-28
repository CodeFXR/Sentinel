import asyncio
import os
import shutil

from sentinel_platform import detect, nss_databases
from sentinel_utils import get_strategy


class SentinelBackend:
    def __init__(self, logger):
        self.logger = logger
        self.strategy = get_strategy()
        self.platform = detect()
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
             log_writer(f"Detected platform: {self.platform.name}")
             log_writer(f"Fix with: sudo {self.platform.install_hint()}")
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

        platform = self.platform
        target_dir = platform.trust_anchor_dir
        refresh_cmd = platform.trust_refresh_cmd
        if target_dir is None or not refresh_cmd:
            log_writer(f"ERROR: {platform.name} is not a supported trust-store layout.")
            log_writer("Sentinel will not guess a certificate directory.")
            log_writer("Install the DoD roots manually, then see SENTINEL_DOCS.md.")
            self.logger.error(f"Unsupported trust store layout: {platform.family}")
            update_led("led-certs", "error")
            return

        chain_file = os.path.join(self.SCRIPT_DIR, "DoD_Mega_Chain.pem")
        if not os.path.exists(chain_file):
            log_writer(f"ERROR: Source file not found: {chain_file}")
            log_writer("Run tools/create_mega_chain.py to generate it.")
            update_led("led-certs", "error")
            return

        target_file = os.path.join(target_dir, platform.trust_anchor_name)

        log_writer(f"Platform:  {platform.name}")
        log_writer(f"Source:    {os.path.basename(chain_file)}")
        log_writer(f"Target:    {target_file}")
        log_writer("Requesting privileges via pkexec...")

        # Two exec calls, no shell. polkit caches the authorization so this
        # normally prompts once, not twice.
        steps = (
            ("pkexec", "install", "-m", "0644", chain_file, target_file),
            ("pkexec", *refresh_cmd),
        )

        for command in steps:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await proc.communicate()
            except Exception as e:
                log_writer(f"Execution Error: {e}")
                self.logger.error(f"Certificate installation error: {e}")
                update_led("led-certs", "error")
                return

            if proc.returncode != 0:
                err_msg = stderr.decode().strip() or "Unknown error"
                log_writer(f"FAILURE: {' '.join(command)} -> {err_msg}")
                self.logger.error(f"Certificate installation failed: {err_msg}")
                update_led("led-certs", "error")
                return

        log_writer("SUCCESS: Certificates installed and trust store updated.")
        self.logger.info("DoD Certificates installed successfully.")
        update_led("led-certs", "success")

    async def configure_browsers(self, log_writer, update_led):
        log_writer("\n--- CONFIGURING BROWSERS (NSS DB) ---")
        self.logger.info("Starting Browser Configuration")
        
        update_led("led-browsers", "loading")

        modutil = shutil.which("modutil")
        lib_path = self.platform.pkcs11_module

        if not modutil:
            log_writer("ERROR: 'modutil' not found.")
            log_writer(f"Fix with: sudo {self.platform.install_hint()}")
            update_led("led-browsers", "error")
            return
        if not lib_path:
            log_writer("ERROR: opensc-pkcs11.so not found on this system.")
            log_writer(f"Fix with: sudo {self.platform.install_hint()}")
            update_led("led-browsers", "error")
            return

        nss_paths = nss_databases()
        log_writer(f"Module:  {lib_path}")
        log_writer(f"Found {len(nss_paths)} NSS database(s) to update.")

        if not nss_paths:
            log_writer("No NSS databases found. Launch a browser once, then retry.")
            update_led("led-browsers", "error")
            return

        success_count = 0
        for db_path in nss_paths:
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

        if success_count:
            log_writer(f"Configured {success_count}/{len(nss_paths)} database(s).")
            log_writer("Close and restart browsers to apply.")
            update_led("led-browsers", "success")
        else:
            log_writer("FAILED: no database was configured.")
            self.logger.error("Browser configuration: no database succeeded")
            update_led("led-browsers", "error")
