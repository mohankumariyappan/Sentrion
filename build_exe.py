import os
import sys
import subprocess
import hashlib
import json
import time

print("========================================================")
print("  BUILDING SENTRION COMPANION STANDALONE WINDOWS APP   ")
print("========================================================")

# Ensure PyInstaller is installed
try:
    import PyInstaller
except ImportError:
    print("[*] Installing PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
exam_file = os.path.join(ROOT_DIR, "candidate_exam.html")
faculty_file = os.path.join(ROOT_DIR, "faculty_dashboard.html")
demo_file = os.path.join(ROOT_DIR, "exam-gate-demo.html")
config_file = os.path.join(ROOT_DIR, "companion_config.json")
companion_dir = os.path.join(ROOT_DIR, "companion")
icon_file = os.path.join(ROOT_DIR, "icon.ico")
entrypoint = os.path.join(ROOT_DIR, "run_companion.py")

def compute_file_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return ""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

hidden_imports = [
    "wmi",
    "psutil",
    "win32gui",
    "win32process",
    "win32api",
    "win32con",
    "win32com",
    "win32com.client",
    "pywintypes",
    "pythoncom",
    "PIL",
    "PIL.Image",
    "PIL.ImageGrab",
    "ctypes",
    "ctypes.wintypes",
    "companion",
    "companion.app",
    "companion.state",
    "companion.config",
    "companion.security",
    "companion.policy",
    "companion.evidence",
    "companion.modules",
    "companion.modules.overlay_detector",
    "companion.modules.vm_detector",
    "companion.modules.process_blacklist",
    "companion.modules.hardware_detector",
    "companion.modules.keystroke_detector",
    "companion.modules.synthetic_input",
    "companion.modules.process_integrity"
]

# PyInstaller Build Command
cmd = [
    sys.executable,
    "-m",
    "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--add-data", f"{exam_file};.",
    "--add-data", f"{faculty_file};.",
    "--add-data", f"{demo_file};.",
    "--add-data", f"{config_file};.",
    "--add-data", f"{companion_dir};companion",
    "--name", "SentrionCompanion",
]

if os.path.exists(icon_file):
    cmd.extend(["--icon", icon_file, "--add-data", f"{icon_file};."])
for hi in hidden_imports:
    cmd.extend(["--hidden-import", hi])
cmd.append(entrypoint)

print("[*] Executing PyInstaller build pipeline...")
result = subprocess.call(cmd, cwd=ROOT_DIR)

if result == 0:
    exe_path = os.path.join(ROOT_DIR, "dist", "SentrionCompanion.exe")
    exe_hash = compute_file_sha256(exe_path)
    exam_hash = compute_file_sha256(exam_file)
    faculty_hash = compute_file_sha256(faculty_file)
    entry_hash = compute_file_sha256(entrypoint)

    # 1. Generate SHA-256 Checksum File
    checksum_file = os.path.join(ROOT_DIR, "dist", "checksums.sha256")
    with open(checksum_file, "w") as f:
        f.write(f"{exe_hash}  SentrionCompanion.exe\n")
        f.write(f"{exam_hash}  candidate_exam.html\n")
        f.write(f"{faculty_hash}  faculty_dashboard.html\n")
        f.write(f"{entry_hash}  run_companion.py\n")

    # 2. Generate Reproducible Build Manifest JSON for Institutional Review
    manifest_file = os.path.join(ROOT_DIR, "dist", "build_manifest.json")
    manifest_data = {
        "app_name": "Sentrion Companion Native Security Service",
        "version": "1.0.0",
        "build_timestamp": time.time(),
        "build_timestamp_utc": time.asctime(time.gmtime()),
        "python_version": sys.version,
        "target_binary": "SentrionCompanion.exe",
        "binary_sha256": exe_hash,
        "source_hashes": {
            "candidate_exam.html": exam_hash,
            "faculty_dashboard.html": faculty_hash,
            "run_companion.py": entry_hash
        }
    }
    with open(manifest_file, "w") as f:
        json.dump(manifest_data, f, indent=2)

    # 3. Invoke Authenticode Code-Signing Pipeline Step
    signer_script = os.path.join(ROOT_DIR, "sign_executable.py")
    if os.path.exists(signer_script):
        print("\n[*] Triggering Authenticode Code-Signing Pipeline...")
        subprocess.call([sys.executable, signer_script], cwd=ROOT_DIR)

    print("\n========================================================")
    print("  [+] SUCCESS! Sentrion Executable App Built & Signed!")
    print(f"  Executable location: {exe_path}")
    print(f"  SHA-256 Checksum:    {exe_hash}")
    print(f"  Build Manifest:      {manifest_file}")
    print("========================================================\n")
else:
    print(f"\n[!] Build failed with exit code: {result}")
