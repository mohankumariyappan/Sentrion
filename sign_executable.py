import os
import sys
import subprocess
import shutil

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_EXE = os.path.join(ROOT_DIR, "dist", "SentrionCompanion.exe")

print("========================================================")
print("  SENTRION BINARY CODE-SIGNING & TRUST PIPELINE        ")
print("========================================================")

if not os.path.exists(TARGET_EXE):
    print(f"[!] Target binary not found: {TARGET_EXE}")
    print("[!] Run 'python build_exe.py' first to build the executable.")
    sys.exit(1)

# Check for Microsoft SignTool in PATH or Windows SDK paths
signtool_path = shutil.which("signtool.exe")
if not signtool_path:
    # Common Windows SDK paths
    possible_paths = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
    ]
    for p in possible_paths:
        if os.path.exists(p):
            signtool_path = p
            break

if signtool_path:
    print(f"[*] Found SignTool at: {signtool_path}")
    cert_path = os.path.join(ROOT_DIR, "SentrionReleaseCert.pfx")
    
    if os.path.exists(cert_path):
        print(f"[*] Signing binary with PFX certificate: {cert_path}")
        sign_cmd = [
            signtool_path, "sign",
            "/f", cert_path,
            "/p", "SentrionSecure2026",
            "/tr", "http://timestamp.digicert.com",
            "/td", "SHA256",
            "/fd", "SHA256",
            TARGET_EXE
        ]
        ret = subprocess.call(sign_cmd)
        if ret == 0:
            print("[+] SUCCESS: Binary signed with Authenticode certificate!")
        else:
            print(f"[!] SignTool returned non-zero code: {ret}")
    else:
        print("[!] PFX Certificate (SentrionReleaseCert.pfx) not found.")
        print("[!] To sign with Authenticode, place a valid PFX certificate at root.")
else:
    print("[!] Windows SignTool.exe not found in PATH or standard Windows SDK paths.")
    print("[*] Generates Powershell Self-Signed Authenticode Certificate for Institutional Audit:")
    
    ps_cert_script = """
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Sentrion Exam Integrity System, O=Sentrion Security" -CertStoreLocation Cert:\\CurrentUser\\My
    Set-AuthenticodeSignature -FilePath "%s" -Certificate $cert
    """ % TARGET_EXE.replace("\\", "\\\\")

    try:
        res = subprocess.call(["powershell", "-NoProfile", "-Command", ps_cert_script])
        if res == 0:
            print("[+] SUCCESS: Binary signed with local development Authenticode Certificate!")
        else:
            print(f"[!] PowerShell signing returned exit code: {res}")
    except Exception as e:
        print(f"[!] PowerShell self-signing failed: {e}")

print("========================================================\n")
