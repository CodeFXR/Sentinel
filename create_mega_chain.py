import os
import subprocess

def create_chain():
    outfile = "DoD_Mega_Chain.pem"
    with open(outfile, "w") as f_out:
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".p7b"):
                    path = os.path.join(root, file)
                    print(f"Processing {path}...")
                    
                    # Try PEM
                    cmd = ["openssl", "pkcs7", "-in", path, "-print_certs"]
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    if res.returncode == 0:
                        f_out.write(res.stdout)
                        continue
                    
                    # Try DER
                    cmd = ["openssl", "pkcs7", "-in", path, "-inform", "DER", "-print_certs"]
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    if res.returncode == 0:
                        f_out.write(res.stdout)
                    else:
                        print(f"Failed to process {path}")

if __name__ == "__main__":
    create_chain()
