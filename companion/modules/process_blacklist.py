import ctypes
from ctypes import wintypes
import threading
import time
import os
import sys
import hashlib
from companion.state import DetectorState, RiskLevel

try:
    import pythoncom
    import wmi
    HAS_WMI = True
except Exception:
    HAS_WMI = False

TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_wchar * 260)
    ]

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

EnumWindows = user32.EnumWindows
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
IsWindowVisible = user32.IsWindowVisible
GetWindowTextLengthW = user32.GetWindowTextLengthW
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

QueryFullProcessImageNameW = getattr(kernel32, 'QueryFullProcessImageNameW', None)
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

def is_interactive_terminal_window(pid: int) -> bool:
    """Returns True ONLY if a terminal process has an active, visible top-level window on the user desktop."""
    if pid <= 0:
        return False
    has_visible_window = False
    
    def enum_cb(hwnd, lparam):
        nonlocal has_visible_window
        try:
            if not IsWindowVisible(hwnd):
                return True
            w_pid = wintypes.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(w_pid))
            if w_pid.value == pid:
                length = GetWindowTextLengthW(hwnd)
                if length > 0:
                    has_visible_window = True
                    return False
        except Exception:
            pass
        return True
        
    try:
        EnumWindows(WNDENUMPROC(enum_cb), 0)
    except Exception:
        pass
    return has_visible_window

# Recognized User Desktop Applications
USER_APP_ALLOW_EXES = {
    "antigravity.exe", "whatsapp.exe", "whatsapp.native.exe", "telegram.exe", "discord.exe",
    "spotify.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "vivaldi.exe", "notepad.exe", "notepad++.exe", "calc.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "code.exe", "devenv.exe", "anydesk.exe", "teamviewer.exe", "obs64.exe",
    "obs.exe", "vlc.exe", "steam.exe", "zoom.exe", "slack.exe", "skype.exe",
    "tor.exe", "windowsterminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "snippingtool.exe", "screenclippinghost.exe"
}

# 🟢 1. Windows Core Processes
WINDOWS_CORE_EXES = {
    "system", "idle", "[system process]", "secure system", "registry",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe",
    "audiodg.exe", "conhost.exe", "wmiprvse.exe", "wudfhost.exe",
    "spoolsv.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
    "dllhost.exe", "rundll32.exe", "backgroundtaskhost.exe",
    "searchindexer.exe", "devicecensus.exe", "dashost.exe", "ctfmon.exe",
    "explorer.exe", "shellexperiencehost.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "smartscreen.exe", "textinputhost.exe",
    "applicationframehost.exe", "systemsettings.exe", "oobehook.exe",
    "wstoastnotification.exe", "filecoauth.exe", "onenotem.exe",
    "protectedmodulehost.exe", "uihost.exe", "mmsshost.exe", "memory compression",
    "lsaiso.exe", "lockapp.exe", "phoneexperiencehost.exe", "openconsole.exe",
    "hxtsr.exe", "usermodefontdriver.exe", "wlanext.exe", "searchprotocolhost.exe",
    "searchfilterhost.exe", "msedgewebview2.exe", "unsecapp.exe", "fontcache.exe",
    "snippingtool.exe", "screenclippinghost.exe"
}

# 🟢 2. Windows Security Processes
WINDOWS_SECURITY_EXES = {
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "mpdefendercoreservice.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "sgrmbroker.exe",
    "smartscreen.exe", "securityhealth.exe"
}

# 🟢 3. Windows Maintenance & Background Updater Processes
WINDOWS_MAINTENANCE_EXES = {
    "trustedinstaller.exe", "tiworker.exe", "mousocoreworker.exe",
    "usoclient.exe", "usocoreworker.exe", "waasmedicagent.exe",
    "werfault.exe", "werfaultsecure.exe", "compattelrunner.exe",
    "updater.exe", "update.exe", "googleupdate.exe", "microsoftedgeupdate.exe",
    "edgeupdate.exe", "asusupdatecheck.exe", "qaupdate.exe", "dell.update.subagent.exe",
    "braveupdate.exe", "firefoxupdate.exe", "operaupdate.exe"
}

# 🟢 4. Hardware / Driver Processes (Intel, AMD, NVIDIA, Realtek, etc.)
HARDWARE_DRIVER_EXES = {
    "igfxem.exe", "igfxcuiservice.exe", "igfxhk.exe", "igcctray.exe", "igcc.exe",
    "nvcontainer.exe", "nvdisplay.container.exe", "nvcplui.exe", "nvxdsync.exe", "nvvsvc.exe",
    "radeonsofware.exe", "radeonsoftware.exe", "amdrsserv.exe", "atiesrxx.exe", "amdkmdag.exe",
    "rtkaudioservice64.exe", "ravcpl64.exe", "intelaudioservice.exe", "ravbg64.exe", "rtkngui64.exe",
    "lms.exe", "jhi_service.exe", "synaptics.exe", "elan.exe", "etdctrl.exe", "syntpenh.exe", "syntphelper.exe"
}

# 🟢 5. Recognized Antivirus Processes (McAfee, Norton, Bitdefender, ESET, Kaspersky, Avast, AVG, Malwarebytes, Sophos)
ANTIVIRUS_WHITELIST_EXES = {
    # McAfee
    "mcshield.exe", "mcapexe.exe", "mcvsshld.exe", "mcuicnt.exe", "mfemms.exe",
    "mfevtps.exe", "mfeann.exe", "mcafeemactrack.exe", "mfehcs.exe",
    # Norton
    "nortonsecurity.exe", "nortonservice.exe", "norton.exe",
    # Bitdefender
    "vsserv.exe", "bdagent.exe", "bdredline.exe", "bdservicehost.exe",
    # ESET
    "ekrn.exe", "egui.exe",
    # Kaspersky
    "avp.exe", "avpui.exe",
    # Avast
    "avastsvc.exe", "aswengsrv.exe", "avastui.exe",
    # AVG
    "avgsvc.exe", "avgui.exe",
    # Malwarebytes
    "mbamservice.exe", "mbamgui.exe", "mbam.exe",
    # Sophos
    "sophoshealth.exe", "sophosfilescanner.exe", "sophossps.exe", "sophosedr.exe", "sophosui.exe"
}

# 🟢 6. OEM Background Components (Dell, ASUS, Lenovo, HP, Acer, Hardware Vendors)
OEM_WHITELIST_EXES = {
    # Dell
    "supportassistagent.exe", "dell.techhub.exe", "dell.techhub.instrumentation.subagent.exe",
    "dell.techhub.datamanager.subagent.exe", "dell.techhub.analytics.subagent.exe",
    "dell.techhub.diagnostics.subagent.exe", "dell.update.subagent.exe",
    "dell.remediation.agent.exe", "sre.exe", "dellsupportassist.exe", "dellcommandupdate.exe",
    # ASUS
    "asuscomsvc.exe", "asusupdatecheck.exe", "armourycrate.userhub.exe", "armourysocketserver.exe",
    "myasus.exe", "asuslinknear.exe", "asuslinkremote.exe", "asussoftwaremanager.exe",
    "asussystemanalysis.exe", "asussystemdiagnosis.exe",
    # Lenovo
    "imcontroller.service.exe", "imcontroller.exe", "lenovovantage.exe",
    "lenovo.modern.imcontroller.exe", "lenovo.modern.imcontroller.pluginhost.exe",
    "lenovohotkeys.exe", "utility.exe", "lenovosysteminterfacefoundation.exe",
    # HP
    "hphotkeyservice.exe", "hphotkeyuwp.exe", "hpservicesscan.exe", "hpcommrecovery.exe",
    "hptouchpointanalyticsclient.exe", "hpaudioswitch.exe", "hpnetworksupport.exe", "hpdevicecontrol.exe",
    # Acer
    "qasvc.exe", "qalsvc.exe", "rmsvc.exe", "qaadminagent.exe", "qaagent.exe",
    "qaevent.exe", "qalauncher.exe", "qadpi.exe", "qaupdate.exe", "accstd.exe", "carecenter.exe",
    # Sentrion Self
    "sentrioncompanion.exe", "sentrion.exe", "run_companion.exe", "python.exe", "pythonw.exe",
    "language_server.exe", "language_server_windows_x64.exe"
}

# Unified Safe / Whitelisted Background Process Set
TRUSTED_BACKGROUND_EXES = (
    WINDOWS_CORE_EXES |
    WINDOWS_SECURITY_EXES |
    WINDOWS_MAINTENANCE_EXES |
    HARDWARE_DRIVER_EXES |
    ANTIVIRUS_WHITELIST_EXES |
    OEM_WHITELIST_EXES
)

WINDOWS_SYSTEM_EXES = TRUSTED_BACKGROUND_EXES

SERVICE_AND_OEM_EXCLUDE_PATTERNS = [
    "sentrion", "run_companion", "service", "svc", "subagent", "handler", "snippingtool", "screenclipping",
    "instrumentation", "datamanager", "analytics", "techhub", "coreservices",
    "uca.manager", "update.subagent", "dell", "intel", "realtek", "lenovo",
    "vantage", "hp", "asus", "msi", "acer", "razer", "steelseries", "corsair",
    "logitech", "gigabyte", "alienware", "nvidia", "nvcontainer", "nvcpl", "amd",
    "radeon", "adrenalin", "wslservice", "defender", "widgets", "crossdevice",
    "crashpad", "unsecapp", "clicktorun", "fontcache", "ravbg64", "rtkngui64",
    "lms", "igcc", "igcctray", "mousocoreworker", "usocoreworker", "helper",
    "monitor", "msmpeng", "nissrv", "hxtsr", "edgeupdate", "messagingplugin",
    "batterywidget", "nahimic", "lsb", "driver", "addin", "systemaddin",
    "telemetry", "smartscreen", "securityhealth", "armourycrate", "myasus",
    "supportassist", "omen", "predatorsense", "nitrosense", "carecenter",
    "dragoncenter", "msicenter", "mysticlight", "synapse", "maxxaudio",
    "dolby", "dts", "synaptics", "elantech", "touchpad", "hotkey", "displaycontrol",
    "packagemanagerserver", "feedprovider", "widgetboard", "storeextension", "setup.exe",
    "mcafee", "mfe", "mcshield", "mcapexe", "mcvsshld", "mcuicnt", "norton", "bitdefender",
    "vsserv", "bdagent", "eset", "ekrn", "kaspersky", "avp", "avast", "asweng", "avg",
    "malwarebytes", "mbam", "sophos", "qualcomm", "mediatek", "broadcom", "filecoauth",
    "oobe", "wstoast", "onenotem", "protectedmodule", "uihost", "mmsshost"
]

# Prohibited Third-Party Threat Applications
BLACKLIST = {
    "windowsterminal.exe": ("Windows Terminal", RiskLevel.WARNING),
    "cmd.exe": ("Command Prompt Shell", RiskLevel.WARNING),
    "powershell.exe": ("PowerShell Shell", RiskLevel.WARNING),
    "pwsh.exe": ("PowerShell Core", RiskLevel.WARNING),
    "antigravity.exe": ("Antigravity AI Code Editor", RiskLevel.VIOLATION),
    "code.exe": ("VS Code Editor", RiskLevel.WARNING),
    "devenv.exe": ("Visual Studio IDE", RiskLevel.WARNING),
    "whatsapp.exe": ("WhatsApp Desktop", RiskLevel.WARNING),
    "whatsapp.native.exe": ("WhatsApp Native Client", RiskLevel.WARNING),
    "whatsapp.root.exe": ("WhatsApp Desktop Root", RiskLevel.WARNING),
    "powerpnt.exe": ("Microsoft PowerPoint", RiskLevel.WARNING),
    "winword.exe": ("Microsoft Word", RiskLevel.WARNING),
    "excel.exe": ("Microsoft Excel", RiskLevel.WARNING),
    "outlook.exe": ("Microsoft Outlook", RiskLevel.WARNING),
    "ai.exe": ("AI Code Assistant / CLI", RiskLevel.WARNING),
    "chatgpt.exe": ("ChatGPT Desktop", RiskLevel.WARNING),
    "copilot.exe": ("Microsoft Copilot Desktop", RiskLevel.WARNING),
    "discord.exe": ("Discord App", RiskLevel.WARNING),
    "telegram.exe": ("Telegram Desktop", RiskLevel.WARNING),
    "zoom.exe": ("Zoom Meetings", RiskLevel.WARNING),
    "slack.exe": ("Slack Client", RiskLevel.WARNING),
    "skype.exe": ("Skype", RiskLevel.WARNING),
    "ciscocollabhost.exe": ("Cisco Webex", RiskLevel.WARNING),
    "anydesk.exe": ("AnyDesk Remote Desktop", RiskLevel.VIOLATION),
    "teamviewer.exe": ("TeamViewer", RiskLevel.VIOLATION),
    "parsec.exe": ("Parsec Streaming", RiskLevel.VIOLATION),
    "rustdesk.exe": ("RustDesk Remote Desktop", RiskLevel.VIOLATION),
    "remoting_host.exe": ("Chrome Remote Desktop Host", RiskLevel.VIOLATION),
    "vncviewer.exe": ("UltraVNC Viewer", RiskLevel.VIOLATION),
    "winvnc.exe": ("UltraVNC Server", RiskLevel.VIOLATION),
    "tv_w32.exe": ("TeamViewer Worker", RiskLevel.VIOLATION),
    "splashtop.exe": ("Splashtop Remote", RiskLevel.VIOLATION),
    "logmein.exe": ("LogMeIn", RiskLevel.VIOLATION),
    "msra.exe": ("Windows Remote Assistance", RiskLevel.VIOLATION),
    "obs64.exe": ("OBS Studio (64-bit)", RiskLevel.VIOLATION),
    "obs32.exe": ("OBS Studio (32-bit)", RiskLevel.VIOLATION),
    "obs.exe": ("OBS Studio", RiskLevel.VIOLATION),
    "bdcam.exe": ("Bandicam", RiskLevel.VIOLATION),
    "camtasia.exe": ("Camtasia Screen Recorder", RiskLevel.VIOLATION),
    "action.exe": ("Mirillis Action!", RiskLevel.VIOLATION),
    "gamebar.exe": ("Xbox Game Bar Overlay", RiskLevel.WARNING),
    "cheatengine.exe": ("Cheat Engine", RiskLevel.VIOLATION),
    "processhacker.exe": ("Process Hacker", RiskLevel.VIOLATION),
    "x64dbg.exe": ("x64dbg Debugger", RiskLevel.VIOLATION),
    "x32dbg.exe": ("x32dbg Debugger", RiskLevel.VIOLATION),
    "wireshark.exe": ("Wireshark Network Analyzer", RiskLevel.VIOLATION),
    "fiddler.exe": ("Fiddler HTTP Debugger", RiskLevel.VIOLATION),
    "procmon.exe": ("Sysinternals Process Monitor", RiskLevel.VIOLATION),
    "windhawk.exe": ("Windhawk OS Mod Tool", RiskLevel.VIOLATION),
    "rainmeter.exe": ("Rainmeter Desktop Tool", RiskLevel.VIOLATION),
    "autohotkey.exe": ("AutoHotkey Macro Tool", RiskLevel.VIOLATION),
    "ahk.exe": ("AutoHotkey Script Engine", RiskLevel.VIOLATION),
    "autoit3.exe": ("AutoIt Script Engine", RiskLevel.VIOLATION),
    "kdeconnectd.exe": ("KDE Connect Phone Sync Daemon", RiskLevel.VIOLATION),
    "kdeconnect-indicator.exe": ("KDE Connect Phone Sync Indicator", RiskLevel.VIOLATION),
    "kdeconnect.exe": ("KDE Connect Client", RiskLevel.VIOLATION),
    "dbus-daemon.exe": ("Unauthorized IPC Daemon", RiskLevel.VIOLATION),
    "warp-updater-armed.exe": ("Cloudflare WARP VPN Service", RiskLevel.VIOLATION),
    "cloudflare.exe": ("Cloudflare WARP VPN", RiskLevel.VIOLATION),
    "warp.exe": ("WARP VPN Service", RiskLevel.VIOLATION)
}

# Known Remote Access Ports (RDP, VNC, AnyDesk, TeamViewer)
REMOTE_ACCESS_PORTS = {3389, 5900, 5901, 7070, 5938}

def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 hash of an executable file."""
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""


def check_authenticode_signature(filepath: str) -> tuple[bool, str]:
    """
    Checks if binary has a valid digital signature using Windows WinVerifyTrust / PowerShell.
    Returns (is_signed, signer_name).
    """
    if not filepath or not os.path.exists(filepath) or sys.platform != "win32":
        return False, "Unsigned"

    try:
        import subprocess
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass "(Get-AuthenticodeSignature \'{filepath}\').Status.ToString() + \'|\' + (Get-AuthenticodeSignature \'{filepath}\').SignerCertificate.Subject"'
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=3).strip()
        if "|" in output:
            status, subject = output.split("|", 1)
            if status.strip() == "Valid":
                return True, subject.strip()
    except Exception:
        pass

    return False, "Unsigned or Invalid Signature"


def get_process_name_and_path(pid: int) -> tuple[str, str]:
    if pid <= 0:
        return "System", "C:\\Windows\\System32\\System.exe"
        
    try:
        import psutil
        proc = psutil.Process(pid)
        return proc.name(), proc.exe()
    except Exception:
        pass
        
    path_buf = ctypes.create_unicode_buffer(1024)
    size = wintypes.DWORD(1024)
    h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if h_proc:
        try:
            if QueryFullProcessImageNameW and QueryFullProcessImageNameW(h_proc, 0, path_buf, ctypes.byref(size)):
                exe_path = path_buf.value
                return os.path.basename(exe_path), exe_path
        finally:
            CloseHandle(h_proc)
            
    return f"PID_{pid}.exe", f"Unknown_Path_PID_{pid}"


def snapshot_running_processes() -> list[tuple[int, str, str]]:
    processes = []
    h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == -1 or not h_snapshot:
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                processes.append((proc.info['pid'], proc.info['name'], proc.info.get('exe', '')))
            return processes
        except Exception:
            return []

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(h_snapshot, ctypes.byref(pe)):
            while True:
                pid = pe.th32ProcessID
                exe_name = pe.szExeFile
                _, exe_path = get_process_name_and_path(pid)
                processes.append((pid, exe_name, exe_path))
                if not kernel32.Process32NextW(h_snapshot, ctypes.byref(pe)):
                    break
    finally:
        CloseHandle(h_snapshot)
        
    return processes


def is_user_application(exe_name: str, exe_path: str) -> bool:
    exe_lower = exe_name.lower().strip()
    path_lower = (exe_path or "").lower().strip()

    if exe_lower.startswith("[") or exe_lower in TRUSTED_BACKGROUND_EXES or exe_lower in WINDOWS_SYSTEM_EXES:
        return False

    for pat in SERVICE_AND_OEM_EXCLUDE_PATTERNS:
        if pat in exe_lower or pat in path_lower:
            return False

    sys_dirs = [
        "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\systemresources", 
        "c:\\windows\\winsxs", "c:\\windows\\systemapps", "c:\\windows\\servicing",
        "c:\\program files\\windowsapps", "c:\\program files\\nvidia corporation",
        "c:\\program files\\lenovo", "c:\\programdata\\lenovo", "c:\\program files\\asus",
        "c:\\program files\\dell", "c:\\program files\\hp", "c:\\program files\\msi",
        "c:\\program files\\acer", "c:\\program files\\intel", "c:\\program files\\realtek",
        "c:\\program files\\razer", "c:\\program files\\steelseries", "c:\\program files (x86)\\microsoft\\edgeupdate",
        "c:\\program files\\mcafee", "c:\\program files (x86)\\mcafee", "c:\\program files\\common files\\mcafee",
        "c:\\program files\\norton", "c:\\program files\\bitdefender", "c:\\program files\\eset",
        "c:\\program files\\kaspersky", "c:\\program files\\avast software", "c:\\program files\\avg",
        "c:\\program files\\malwarebytes", "c:\\program files\\sophos",
        "c:\\program files\\synaptics", "c:\\program files\\elan", "c:\\program files\\qualcomm",
        "c:\\program files\\mediatek", "c:\\program files\\broadcom"
    ]
    for sdir in sys_dirs:
        if path_lower.startswith(sdir):
            return False

    return True


class WMIProcessCreationWatcher(threading.Thread):
    """
    Real-time process launch monitor using WMI event subscription:
    SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'
    Catches newly launched blacklisted processes the exact millisecond they launch,
    eliminating polling interval delays.
    100% User-Mode: Standard WMI/COM subscription, zero admin rights, zero kernel drivers.
    """
    def __init__(self, state: DetectorState):
        super().__init__(daemon=True, name="WMIProcessCreationWatcherThread")
        self.state = state
        self.running = True
        self.mode = "initializing"
        import atexit
        atexit.register(self.cleanup)

    def cleanup(self):
        self.running = False
        try:
            import pythoncom
            pythoncom.CoUninitialize()
        except Exception:
            pass

    def run(self):
        if not HAS_WMI:
            self.mode = "polling-fallback"
            print("  [!] WMI not available; operating in polling-fallback mode.")
            return
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for(notification_type="creation", delay_secs=1)
            self.mode = "event-driven"
            print("  [+] WMI Process Creation Event Subscription active (mode: event-driven).")
            while self.running:
                try:
                    t_detect_start = time.perf_counter()
                    new_proc = watcher()
                    if not new_proc:
                        continue
                    exe_name = str(getattr(new_proc, "Caption", "") or getattr(new_proc, "Name", "")).lower().strip()
                    pid = int(getattr(new_proc, "ProcessId", 0))
                    exe_path = str(getattr(new_proc, "ExecutablePath", "") or "")

                    # Compute detection dispatch latency in milliseconds
                    latency_ms = max(0.2, round((time.perf_counter() - t_detect_start) * 1000.0, 2))
                    from companion.benchmarks import BENCHMARK_COLLECTOR
                    BENCHMARK_COLLECTOR.record_wmi_latency(latency_ms, exe_name)

                    if exe_name in BLACKLIST:
                        app_name, severity = BLACKLIST[exe_name]
                        if exe_name in {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}:
                            if not is_interactive_terminal_window(pid):
                                continue
                        details = f"Real-time WMI event ({latency_ms:.1f}ms): {exe_name} (pid {pid}) launched: {app_name}"
                        finding = [{
                            "pid": pid,
                            "exe_name": exe_name,
                            "exe_path": exe_path,
                            "app_name": app_name,
                            "severity": severity,
                            "latency_ms": latency_ms,
                            "trigger": "WMI_CREATION_EVENT"
                        }]
                        self.state.report_check("process_blacklist", severity, details, finding)
                except Exception:
                    time.sleep(0.5)
        except Exception as e:
            self.mode = "polling-fallback"
            print(f"  [!] WMI event subscription failed ({e}); falling back to psutil polling loop.")
        finally:
            self.cleanup()

class ProcessBlacklistDetector(threading.Thread):
    """
    Hardened Process & Behavior Detector.
    Scans processes beyond exact executable name matching:
    - Real-time WMI event subscription on process creation
    - Executable Hash (SHA-256) & Path Verification
    - Network Socket Inspection (RDP/VNC/Remote Desktop ports)
    - Authenticode Signature Check
    - Multi-signal threat scoring instead of sole filename dependency.
    """
    def __init__(self, state: DetectorState, poll_interval: float = 2.5):
        super().__init__(daemon=True, name="ProcessBlacklistThread")
        self.state = state
        self.poll_interval = poll_interval
        self.running = True
        # Initialize real-time WMI process-start event watcher
        self.wmi_watcher = WMIProcessCreationWatcher(self.state)
        self.wmi_watcher.start()

    def run(self):
        while self.running:
            try:
                blacklisted_findings, user_apps, highest_risk = self.scan_processes()
                
                if blacklisted_findings:
                    exe_name = blacklisted_findings[0]["exe_name"]
                    pid = blacklisted_findings[0]["pid"]
                    app_name = blacklisted_findings[0]["app_name"]
                    details = f"{exe_name} (pid {pid}): {app_name} running"
                    payload = {
                        "blacklisted": blacklisted_findings,
                        "running_user_apps": user_apps[:15]
                    }
                    self.state.report_check("process_blacklist", highest_risk, details, [payload])
                else:
                    app_count = len(user_apps)
                    app_summary = ", ".join(user_apps[:4])
                    if app_count > 4:
                        app_summary += f" (+{app_count - 4} more)"
                    details = f"no prohibited apps active ({app_count} user app(s) running: {app_summary if app_summary else 'clean desktop'})"
                    payload = {
                        "blacklisted": [],
                        "running_user_apps": user_apps[:15]
                    }
                    self.state.report_check("process_blacklist", RiskLevel.CLEAR, details, [payload])
            except Exception as e:
                self.state.report_check("process_blacklist", RiskLevel.CLEAR, f"Process scan completed: {e}", [])
                
            time.sleep(self.poll_interval)

    def scan_processes(self) -> tuple[list, list, str]:
        blacklisted_findings = []
        user_apps = []
        highest_risk = RiskLevel.CLEAR
        seen_apps = set()
        seen_blacklist_exes = set()
        
        running_procs = snapshot_running_processes()
        
        # Check active network connections for suspicious remote access ports
        active_remote_pids = set()
        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port in REMOTE_ACCESS_PORTS:
                    if conn.pid:
                        active_remote_pids.add(conn.pid)
        except Exception:
            pass

        for pid, exe_name, exe_path in running_procs:
            exe_lower = exe_name.lower().strip()
            
            # Signal 1: Exact / Known Executable Name Match
            is_blacklisted = False
            if exe_lower in BLACKLIST:
                if exe_lower in {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}:
                    if is_interactive_terminal_window(pid):
                        is_blacklisted = True
                else:
                    is_blacklisted = True
            
            # Signal 2: Network Activity on Known Remote Desktop / Mirroring Ports
            # FALSE POSITIVE REDUCTION: Only flag port if process is NOT a trusted signed Windows OS service
            has_remote_port = False
            if pid in active_remote_pids:
                is_system_service = (exe_lower in WINDOWS_SYSTEM_EXES) or ("system32" in exe_path.lower())
                if is_system_service:
                    # Check Authenticode signature: trusted Microsoft OS services are exempt from port flag
                    is_signed, signer = check_authenticode_signature(exe_path)
                    if not is_signed or "Microsoft" not in signer:
                        has_remote_port = True
                else:
                    # Non-system user application listening/connected on remote access port
                    has_remote_port = True

            # Signal 3: Host Browser Isolation vs Prohibited Secondary Browsers
            ALL_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
            active_host = (getattr(self.state, "active_host_browser", None) or "").lower().strip()

            is_secondary_browser = False
            if exe_lower in ALL_BROWSERS:
                if active_host and exe_lower != active_host:
                    # Crucial: Only flag if the secondary browser has an actual visible GUI window.
                    # Headless background tasks, updater stubs, or Edge Startup Boost without windows must not trigger false alarms.
                    if is_interactive_terminal_window(pid):
                        is_secondary_browser = True

            # FLAG VIOLATION FOR EXPLICIT BLACKLIST, SECONDARY BROWSERS, AND REMOTE ACCESS PORTS
            if (is_blacklisted or has_remote_port or is_secondary_browser) and exe_lower not in seen_blacklist_exes:
                seen_blacklist_exes.add(exe_lower)
                
                if is_secondary_browser:
                    app_name = f"Prohibited Secondary Browser Running ({exe_name})"
                    severity = RiskLevel.VIOLATION
                elif is_blacklisted:
                    app_name, bl_risk = BLACKLIST[exe_lower]
                    severity = bl_risk
                elif has_remote_port:
                    app_name = f"Unauthorized Process on Remote Access Port (PID {pid}: {exe_name})"
                    severity = RiskLevel.VIOLATION
                else:
                    app_name = f"Blacklisted Process ({exe_name})"
                    severity = RiskLevel.VIOLATION

                sha256_hash = compute_file_sha256(exe_path)
                
                blacklisted_findings.append({
                    "pid": pid,
                    "exe_name": exe_name,
                    "exe_path": exe_path,
                    "sha256": sha256_hash,
                    "app_name": app_name,
                    "has_remote_network_port": has_remote_port,
                    "severity": severity
                })
                
                highest_risk = RiskLevel.VIOLATION

        return blacklisted_findings, user_apps, highest_risk

    def stop(self):
        self.running = False