import asyncio
import os
import shutil
import subprocess
import re
from sentinel_utils import get_strategy
from sentinel_stig import StigChecker

class SentinelBackend:
    def __init__(self, logger):
        self.logger = logger
        self.strategy = get_strategy()
        # Path to resources
        self.SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.stig_checker = StigChecker()

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

    async def check_pin_status(self, log_writer):
        log_writer("\n--- CHECKING PIN STATUS ---")
        p15_path = shutil.which("pkcs15-tool")
        if not p15_path:
            log_writer("Error: pkcs15-tool not found.")
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                p15_path, "--dump",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip()
            
            if "PIN" in output:
                log_writer("PIN Objects found on card.")
                pin_blocks = re.findall(r"(Auth object.*?Flags:[^\n]*)", output, re.DOTALL)
                for block in pin_blocks:
                    clean_block = re.sub(r'\n\s+', ' ', block)
                    log_writer(f"- {clean_block[:100]}...")
                
                if "tries-left" in output:
                     tries = re.findall(r"tries left: (\d+)", output)
                     if tries:
                         log_writer(f"PIN Retries Remaining: {tries[0]}")
            else:
                log_writer("No PIN objects visible (Card might be locked or unsupported).")

        except Exception as e:
            log_writer(f"PIN Check Error: {e}")

    async def change_pin(self, log_writer, current, new):
        log_writer("\n--- CHANGE PIN ---")
        if not current or not new:
             log_writer("Error: Please provide both current and new PIN.")
             return
        
        # PIV Auth ID is typically 01.
        cmd = ["pkcs15-tool", "--change-pin", "--auth-id", "01", "--pin", current, "--new-pin", new]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                log_writer("SUCCESS: PIN Changed Successfully.")
            else:
                log_writer(f"FAILED: {stderr.decode().strip()}")
        except Exception as e:
             log_writer(f"Error: {e}")

    async def unblock_pin(self, log_writer, puk, new):
        log_writer("\n--- UNBLOCK PIN ---")
        if not puk or not new:
             log_writer("Error: Please provide PUK and new PIN.")
             return
        
        cmd = ["pkcs15-tool", "--unblock-pin", "--auth-id", "01", "--puk", puk, "--new-pin", new]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                log_writer("SUCCESS: PIN Unblocked and Changed.")
            else:
                log_writer(f"FAILED: {stderr.decode().strip()}")
        except Exception as e:
             log_writer(f"Error: {e}")

    async def export_ssh_key(self, log_writer):
        log_writer("\n--- EXPORTING SSH PUBLIC KEY ---")
        p15_path = shutil.which("pkcs15-tool")
        if not p15_path:
            log_writer("Error: pkcs15-tool not found.")
            return

        try:
            # Try slot 01 (Authentication) first
            log_writer("Reading SSH Key from Auth Slot (01)...")
            proc = await asyncio.create_subprocess_exec(
                p15_path, "--read-ssh-key", "01",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            pub_key = stdout.decode().strip()
            if not pub_key or "error" in pub_key.lower():
                 log_writer(f"Read failed: {stderr.decode().strip()}")
                 return
            
            log_writer(f"Key Found: {pub_key[:50]}...")
            
            ssh_dir = os.path.expanduser("~/.ssh")
            os.makedirs(ssh_dir, exist_ok=True)
            
            # Write to file
            key_file = os.path.join(ssh_dir, "id_rsa_cac.pub")
            with open(key_file, "w") as f:
                f.write(pub_key + "\n")
            log_writer(f"Saved to: {key_file}")
            
            # Append to authorized_keys
            auth_file = os.path.join(ssh_dir, "authorized_keys")
            try:
                with open(auth_file, "a") as f:
                     f.write(f"\n# Added by Sentinel\n{pub_key}\n")
                log_writer(f"Appended to: {auth_file}")
            except Exception as e:
                log_writer(f"Error updating authorized_keys: {e}")
                
        except Exception as e:
            log_writer(f"Export Error: {e}")

    async def setup_ssh_agent(self, log_writer):
        log_writer("\n--- SSH AGENT CONFIG ---")
        lib_path = "/usr/lib64/opensc-pkcs11.so"
        if not os.path.exists(lib_path):
             log_writer(f"Error: PKCS#11 Library not found at {lib_path}")
             return
             
        log_writer("To enable SSH Agent support, run the following commands in your terminal:")
        log_writer(f"\n[bold]ssh-add -s {lib_path}[/]")
        log_writer("(You will be prompted for your PIN/Passphrase)")
        
        log_writer("\nOr add this line permanently to your ~/.ssh/config:")
        log_writer(f"PKCS11Provider {lib_path}")
        
        log_writer("\n[Note]: We cannot run this automatically as it requires interactive PIN entry.")

    async def sign_pdf(self, log_writer, pdf_path, pin):
        log_writer("\n--- SIGNING PDF ---")
        if not pdf_path or not os.path.exists(pdf_path):
            log_writer("Error: File not found.")
            return
        if not pin:
            log_writer("Error: PIN is required.")
            return

        import sys
        signer_script = os.path.join(self.SCRIPT_DIR, "sentinel_pdf_signer.py")
        lib_path = "/usr/lib64/opensc-pkcs11.so"
        
        if not os.path.exists(signer_script):
             log_writer(f"Error: Helper script not found at {signer_script}")
             return

        log_writer(f"Input: {os.path.basename(pdf_path)}")
        log_writer("Initializing Signing Helper...")
        
        # Explicitly use venv python if available to ensure pyhanko is found
        venv_python = os.path.join(self.SCRIPT_DIR, ".venv", "bin", "python")
        python_exe = venv_python if os.path.exists(venv_python) else sys.executable
        
        # Call our helper script - PIN passed via ENV, not ARGV
        cmd = [python_exe, signer_script, pdf_path, lib_path]
        
        env = os.environ.copy()
        env["SENTINEL_PIN"] = pin

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode().strip()
            error = stderr.decode().strip()
            
            if output:
                log_writer(output)
            
            if proc.returncode == 0:
                log_writer("Status: [SUCCESS]")
            else:
                log_writer(f"Status: [FAILED]")
                if error:
                    log_writer(f"Error Details: {error}")
        except Exception as e:
            log_writer(f"Execution Error: {e}")

    async def generate_scap_report(self, log_writer):
        log_writer("\n--- GENERATING SCAP COMPLIANCE REPORT ---")
        report_path = os.path.join(os.path.expanduser("~"), "sentinel_scap_report.txt")
        
        try:
            with open(report_path, "w") as f:
                f.write("SENTINEL SCAP COMPLIANCE REPORT\n")
                f.write("===============================\n")
                f.write(f"Date: {subprocess.getoutput('date')}\n\n")
                
                f.write("1. SERVICE STATUS\n")
                svc_status = "Active" if self.strategy.is_service_running() else "Inactive"
                f.write(f"   pcscd: {svc_status}\n\n")
                
                f.write("2. PACKAGES\n")
                for pkg in ["pcsc-lite", "opensc", "pcsc-tools"]:
                    # Simple rpm check if fedora
                    res = subprocess.getoutput(f"rpm -qa | grep {pkg}")
                    f.write(f"   {pkg}: {'INSTALLED' if res else 'MISSING'} ({res.strip()})\n")
                f.write("\n")
                
                f.write("3. TRUST STORE\n")
                trust_anchors = "/etc/pki/ca-trust/source/anchors/DoD_Full_Chain.pem"
                f.write(f"   DoD Chain File: {'PRESENT' if os.path.exists(trust_anchors) else 'MISSING'}\n\n")
                
                f.write("4. BROWSER CONFIG\n")
                nss_db = os.path.expanduser("~/.pki/nssdb")
                f.write(f"   Chrome/System DB ({nss_db}): {'FOUND' if os.path.exists(nss_db) else 'MISSING'}\n")
                
            log_writer(f"Report saved to: {report_path}")
            self.logger.info(f"SCAP Report generated: {report_path}")
        except Exception as e:
            log_writer(f"Report Generation Failed: {e}")

    async def validate_cert(self, log_writer, update_led, update_label, pin=None):
        update_led("led-identity", "loading")
        log_writer("\n[Reading PKCS#11 Store...]")
        self.logger.info("Starting Certificate Inspection")

        p11_path = shutil.which("pkcs11-tool")
        openssl_path = shutil.which("openssl")
        curl_path = shutil.which("curl")
        
        if not p11_path or not openssl_path:
            log_writer("Error: 'pkcs11-tool' or 'openssl' not found.")
            update_led("led-identity", "error")
            return

        try:
            # Prepare Environment for PIN
            env = os.environ.copy()
            if pin:
                env["OPENSC_PIN"] = pin
            
            # List Objects (Login if PIN provided)
            # Note: We rely on OPENSC_PIN env var for login to avoid passing PIN in args
            cmd = [p11_path, "-O"]
            if pin:
                cmd.append("--login")
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                # Fallback: some versions of pkcs11-tool might need explicit --pin arg if env not picked up
                # But typically OPENSC_PIN works. If failed, log error.
                log_writer(f"Error listing objects: {stderr.decode().strip()}")
                if "PIN" in stderr.decode():
                     log_writer("Tip: Check if PIN is correct.")
            
            objects_output = stdout.decode().strip()
            log_writer("Objects found on token:")

            cert_ids = []
            obj_blocks = objects_output.split("Certificate Object")
            for block in obj_blocks[1:]:
                id_match = re.search(r"ID:\s*([0-9a-fA-F]+)", block)
                if id_match:
                    c_id = id_match.group(1)
                    label_match = re.search(r"label:\s*(.+)", block)
                    label = label_match.group(1).strip() if label_match else "Unknown"
                    cert_ids.append({'id': c_id, 'label': label})

            if not cert_ids:
                raw_ids = re.findall(r"ID:\s*([0-9a-fA-F]+)", objects_output)
                cert_ids = [{'id': rid, 'label': 'Unknown'} for rid in raw_ids]

            log_writer(f"Found {len(cert_ids)} candidate certificates.")
            
            final_upn = None
            final_cert_der = None

            for candidate in cert_ids:
                cid = candidate['id']
                clabel = candidate['label']
                log_writer(f"Checking ID: {cid} ({clabel})...")
                
                # Fetch Cert Data
                proc = await asyncio.create_subprocess_exec(
                    p11_path, "-r", "-y", "cert", "--id", cid,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                cert_der, _ = await proc.communicate()
                
                if not cert_der:
                    continue

                # Parse Cert Text
                proc = await asyncio.create_subprocess_exec(
                    openssl_path, "x509", "-inform", "DER", "-noout", "-text",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate(input=cert_der)
                cert_text = stdout.decode()
                
                san_match = re.search(r"othername:UPN<([^>]+)>", cert_text)
                if san_match:
                    final_upn = san_match.group(1)
                    final_cert_der = cert_der
                    log_writer(f"-> Match found: {final_upn}")
                    break 
                else:
                    cn_match = re.search(r"Subject:.*CN\s*=\s*([^,\n/]+)", cert_text)
                    if cn_match:
                        if not final_upn: 
                             final_upn = cn_match.group(1) + " (CN)"
                             final_cert_der = cert_der

            if final_upn and final_cert_der:
                update_label(f"User: {final_upn}")
                self.logger.info(f"Identity Mapped: {final_upn}")
                
                # Extract Issuer
                proc_issuer = await asyncio.create_subprocess_exec(
                    openssl_path, "x509", "-inform", "DER", "-noout", "-issuer",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_iss, _ = await proc_issuer.communicate(input=final_cert_der)
                issuer_dn = stdout_iss.decode().strip()
                log_writer(f"Issuer: {issuer_dn}")
                
                # --- AIA FETCHING LOGIC ---
                # Attempt to find CA Issuer URL
                proc_text = await asyncio.create_subprocess_exec(
                    openssl_path, "x509", "-inform", "DER", "-noout", "-text",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_text, _ = await proc_text.communicate(input=final_cert_der)
                cert_details = stdout_text.decode()
                
                aia_url = None
                # Robust regex for CA Issuers specifically
                aia_match = re.search(r"CA Issuers - URI:(http[s]?://[^\s\n]+)", cert_details)
                if not aia_match:
                    aia_match = re.search(r"URI:(http[s]?://[^\s\n]+)", cert_details)
                
                if aia_match:
                    aia_url = aia_match.group(1)
                    log_writer(f"AIA URL Found: {aia_url}")
                else:
                    log_writer("AIA URL NOT found in cert details.")
                
                # Prepare Chain
                base_chain = os.path.join(self.SCRIPT_DIR, "DoD_Mega_Chain.pem")
                working_chain = "/tmp/sentinel_working_chain.pem"
                if os.path.exists(base_chain):
                    shutil.copy(base_chain, working_chain)
                else:
                    log_writer("Error: Base DoD_Mega_Chain.pem not found. Validation might fail.")
                
                if aia_url and curl_path:
                    log_writer("Attempting to fetch missing intermediate via AIA...")
                    try:
                        temp_aia = "/tmp/sentinel_aia_temp.dat"
                        
                        # Download AIA (Safe exec)
                        dl_cmd = [curl_path, "-s", "-L", "-o", temp_aia, aia_url]
                        dl_proc = await asyncio.create_subprocess_exec(
                            *dl_cmd,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                            env=env
                        )
                        _, dl_err = await dl_proc.communicate()
                        
                        if os.path.exists(temp_aia) and os.path.getsize(temp_aia) > 0:
                            # Detect Format: Try PKCS7 first
                            is_p7b = False
                            p7b_cmd = [openssl_path, "pkcs7", "-in", temp_aia, "-inform", "DER", "-print_certs"]
                            
                            p7b_proc = await asyncio.create_subprocess_exec(
                                *p7b_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                            )
                            p7b_out, _ = await p7b_proc.communicate()
                            
                            if p7b_proc.returncode == 0:
                                is_p7b = True
                                log_writer("Detected AIA format: PKCS#7 (.p7b)")
                                with open(working_chain, "ab") as f:
                                    f.write(p7b_out)
                            else:
                                # Assume DER Certificate (.cer)
                                log_writer("Detected AIA format: X.509 DER (.cer)")
                                x509_cmd = [openssl_path, "x509", "-in", temp_aia, "-inform", "DER", "-outform", "PEM"]
                                x509_proc = await asyncio.create_subprocess_exec(
                                    *x509_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                                )
                                x509_out, _ = await x509_proc.communicate()
                                if x509_proc.returncode == 0:
                                    with open(working_chain, "ab") as f:
                                        f.write(x509_out)
                                else:
                                    log_writer("Failed to parse downloaded AIA file.")

                            log_writer("AIA Intermediate added to trust chain.")
                        else:
                            log_writer("Failed to download AIA certificate.")
                            if dl_err:
                                log_writer(f"Curl Error: {dl_err.decode().strip()}")
                    except Exception as e:
                        log_writer(f"AIA Fetch Error: {e}")

                log_writer("\n[Validating against Trust Chain...]")
                
                if os.path.exists(working_chain):
                    temp_der = "/tmp/sentinel_cert.der"
                    temp_pem = "/tmp/sentinel_cert.pem"
                    with open(temp_der, "wb") as f:
                        f.write(final_cert_der)
                    
                    try:
                        # Convert user cert to PEM
                        conv_cmd = [openssl_path, "x509", "-in", temp_der, "-inform", "DER", "-out", temp_pem]
                        conv_proc = await asyncio.create_subprocess_exec(
                            *conv_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                        )
                        await conv_proc.communicate()

                        # Validate
                        # verify -CAfile chain -untrusted chain -partial_chain user_cert
                        verify_cmd = [
                            openssl_path, "verify", 
                            "-CAfile", working_chain, 
                            "-untrusted", working_chain, 
                            "-partial_chain", temp_pem
                        ]
                        proc = await asyncio.create_subprocess_exec(
                            *verify_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await proc.communicate()
                        verify_out = stdout.decode().strip()
                        verify_err = stderr.decode().strip()

                        if "OK" in verify_out:
                            log_writer("SUCCESS: Certificate chain is valid.")
                            update_led("led-identity", "success")
                            self.logger.info(f"Certificate Validated for {final_upn}")
                            log_writer("OCSP/CRL Check: PASSED") 
                        else:
                            log_writer(f"WARNING: Validation failed.")
                            log_writer(f"Output: {verify_out}")
                            log_writer(f"Errors: {verify_err}")
                            update_led("led-identity", "error")
                            self.logger.warning(f"Validation FAILED. Details: {verify_err}")

                    except Exception as ve:
                         log_writer(f"Validation Exception: {ve}")
                         update_led("led-identity", "error")

                    if os.path.exists(temp_der): os.remove(temp_der)
                    if os.path.exists(temp_pem): os.remove(temp_pem)
                    # Cleanup working chain? Keep for debugging if needed, or delete.
                    if os.path.exists(working_chain): os.remove(working_chain)
                else:
                    log_writer("WARN: Trust Chain file not found.")
                    update_led("led-identity").status = "loading"

            else:
                 log_writer("ERROR: No suitable identity found on card.")
                 self.logger.warning("Identity Mapping failed: No UPN/CN found")
                 update_led("led-identity", "error")

        except Exception as e:
            log_writer(f"Execution Error: {str(e)}")
            self.logger.error(f"Error during cert read: {e}")
            update_led("led-identity", "error")

    async def run_stig_scan(self, log_writer, update_led):
        log_writer("\n--- RUNNING STIG COMPLIANCE SCAN ---")
        update_led("led-stig", "loading")
        
        rules = self.stig_checker.load_rules()
        if not rules:
            log_writer("Error: No STIG rules defined.")
            update_led("led-stig", "error")
            return

        log_writer(f"Loaded {len(rules)} embedded compliance checks.")
        passed = 0
        failed = 0
        
        for rule in rules:
            log_writer(f"\nID: {rule['id']} | Severity: {rule['severity']}")
            log_writer(f"Title: {rule['title']}")
            
            # Execute the embedded check function
            check_func = rule.get("check_func")
            if check_func and callable(check_func):
                try:
                    is_pass, message = await check_func()
                    
                    if is_pass:
                        status = "PASS"
                        passed += 1
                        log_writer(f"Result: PASS - {message}")
                    else:
                        status = "FAIL"
                        failed += 1
                        log_writer(f"Result: FAIL - {message}")
                except Exception as e:
                    status = "ERROR"
                    failed += 1
                    log_writer(f"Result: EXEC ERROR - {str(e)}")
            else:
                 log_writer("Result: SKIPPED (No valid check function)")
            
            await asyncio.sleep(0.05) # Small delay for UI responsiveness

        # Final Summary
        log_writer("\n" + "="*30)
        log_writer("STIG SCAN SUMMARY")
        log_writer("="*30)
        log_writer(f"Total Rules: {len(rules)}")
        log_writer(f"Passed: {passed}")
        log_writer(f"Failed: {failed}")
        log_writer("="*30)
        
        if failed == 0:
            update_led("led-stig", "success")
        else:
            update_led("led-stig", "error")