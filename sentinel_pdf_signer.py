import sys
import os
import logging
from pyhanko.sign import fields
from pyhanko.sign.signers.functions import sign_pdf
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext

def sign_pdf_with_cac(pdf_path, output_path, pin, pkcs11_lib, key_label=None):
    """
    Signs a PDF using a PKCS#11 token (CAC/PIV) via pyHanko library.
    """
    if not os.path.exists(pdf_path):
        print(f"Error: Input file not found: {pdf_path}")
        return False

    print(f"Signing: {pdf_path} -> {output_path}")

    try:
        with open(pdf_path, 'rb') as inf:
            # Check for XFA (Adobe XML Forms Architecture)
            # This requires a partial read or using a reader.
            from pyhanko.pdf_utils.reader import PdfFileReader
            r = PdfFileReader(inf)
            try:
                # XFA is usually in the AcroForm dictionary
                root = r.root
                acro_form = root.get('/AcroForm')
                if acro_form and '/XFA' in acro_form:
                    print("Error: This PDF is an Adobe XFA Form (Dynamic).")
                    print("       These proprietary forms cannot be signed by open-source tools.")
                    print("       Please flatten the PDF (print to PDF) or use a standard AcroForm.")
                    return False
            except Exception:
                pass # Continue if check fails, might be standard PDF
            
            # Reset stream for writer
            inf.seek(0)
            
            # Setup PKCS#11 session
            print("Initializing PKCS#11 session...")
            
            session = open_pkcs11_session(
                lib_location=pkcs11_lib,
                user_pin=pin
            )
            
            # We must specify a label or ID. For CAC PIV Auth, standard key ID is often '01' or '02'
            # or usage of key_label="PIV AUTH key"
            # Let's try key_id for PIV Authentication (9A) which is usually ID 1 in OpenSC
            signer = PKCS11Signer(
                pkcs11_session=session,
                key_id=b'\x01', # Try standard PIV Auth Key ID
            )

            w = IncrementalPdfFileWriter(inf)
            
            # Create signature field
            fields.append_signature_field(
                w, sig_field_spec=fields.SigFieldSpec(
                    sig_field_name='Signature1'
                )
            )
            
            meta = PdfSignatureMetadata(
                field_name='Signature1'
            )
            
            with open(output_path, 'wb') as outf:
                sign_pdf(
                    w, meta, signer=signer, output=outf,
                )
        
        print("Success: PDF Signed Successfully.")
        return True

    except Exception as e:
        print(f"Signing Failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python sentinel_pdf_signer.py <input_pdf> <pkcs11_lib_path>")
        print("       (PIN must be set in SENTINEL_PIN env var)")
        sys.exit(1)
        
    in_pdf = sys.argv[1]
    lib_path = sys.argv[2]
    user_pin = os.environ.get("SENTINEL_PIN")
    
    if not user_pin:
        print("Error: SENTINEL_PIN environment variable not set.")
        sys.exit(1)

    out_pdf = in_pdf.replace(".pdf", "_signed.pdf")
    
    success = sign_pdf_with_cac(in_pdf, out_pdf, user_pin, lib_path)
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
