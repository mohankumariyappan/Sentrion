# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\run_companion.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\candidate_exam.html', '.'), ('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\faculty_dashboard.html', '.'), ('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\exam-gate-demo.html', '.'), ('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\companion_config.json', '.'), ('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\companion', 'companion'), ('C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\icon.ico', '.')],
    hiddenimports=['wmi', 'psutil', 'win32gui', 'win32process', 'win32api', 'win32con', 'win32com', 'win32com.client', 'pywintypes', 'pythoncom', 'PIL', 'PIL.Image', 'PIL.ImageGrab', 'ctypes', 'ctypes.wintypes', 'companion', 'companion.app', 'companion.state', 'companion.config', 'companion.security', 'companion.policy', 'companion.evidence', 'companion.modules', 'companion.modules.overlay_detector', 'companion.modules.vm_detector', 'companion.modules.process_blacklist', 'companion.modules.hardware_detector', 'companion.modules.keystroke_detector', 'companion.modules.synthetic_input', 'companion.modules.process_integrity'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SentrionCompanion',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\Users\\Mohankumar I\\Documents\\New folder (2)\\icon.ico'],
)
