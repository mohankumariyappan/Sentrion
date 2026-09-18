import ctypes
from ctypes import wintypes
import time
import threading
import os
from companion.state import DetectorState, RiskLevel

# Win32 Window Extended Style Flags
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020
WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

EnumWindows = user32.EnumWindows
GetWindowLongPtrW = getattr(user32, 'GetWindowLongPtrW', getattr(user32, 'GetWindowLongW'))
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowTextW = user32.GetWindowTextW
IsWindowVisible = user32.IsWindowVisible
GetWindowRect = user32.GetWindowRect
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetForegroundWindow = user32.GetForegroundWindow

QueryFullProcessImageNameW = getattr(kernel32, 'QueryFullProcessImageNameW', None)
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Low-level Windows OS Compositor Threads & System UI Brokers (Non-interactive)
SYSTEM_SHELL_EXECUTABLES = {
    "dwm.exe", "sihost.exe", "ctfmon.exe", "taskhostw.exe", "textinputhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe", "applicationframehost.exe",
    "systemsettings.exe", "searchhost.exe", "searchapp.exe", "consent.exe",
    "credentialuibroker.exe", "runtimebroker.exe", "smartscreen.exe", "audiodg.exe",
    "system", "system.exe", "idle",
    "snippingtool.exe", "screenclippinghost.exe", "screensketch.exe"
}

BROWSER_EXECUTABLES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "vivaldi.exe", "python.exe", "pythonw.exe"
}

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
    h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if h_proc:
        try:
            if QueryFullProcessImageNameW:
                size = wintypes.DWORD(1024)
                if QueryFullProcessImageNameW(h_proc, 0, path_buf, ctypes.byref(size)):
                    full_path = path_buf.value
                    return os.path.basename(full_path), full_path
        finally:
            CloseHandle(h_proc)
            
    return f"PID_{pid}.exe", f"Unknown_Path_PID_{pid}"


WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002
EVENT_SYSTEM_FOREGROUND = 0x0003

class WinEventFocusHookListener(threading.Thread):
    """
    Global OS-Level Window Focus Hook (User-Mode WinEvent).
    Uses user32.SetWinEventHook(EVENT_SYSTEM_FOREGROUND, ...) to receive immediate
    system-wide foreground focus notifications from the Windows kernel/DWM without
    polling, and without requiring DLL injection or administrative privileges.
    """
    def __init__(self, detector):
        super().__init__(daemon=True, name="WinEventFocusHookThread")
        self.detector = detector
        self.running = True
        self.hook = None
        self._proc_ref = None

    def run(self):
        try:
            def event_callback(hWinEventHook, event, hwnd, idObject, idChild, idEventThread, dwmsEventTime):
                if not hwnd or not self.running:
                    return
                try:
                    cur_tick = kernel32.GetTickCount()
                    latency_ms = max(0.1, float(cur_tick - dwmsEventTime)) if dwmsEventTime else 0.5
                    from companion.benchmarks import BENCHMARK_COLLECTOR

                    finding, risk = self.detector.evaluate_foreground_window(hwnd)
                    if finding:
                        BENCHMARK_COLLECTOR.record_focus_latency(latency_ms, finding.get("title", ""))
                    if risk == RiskLevel.VIOLATION and finding:
                        exe_name = finding.get("exe_name", "app")
                        pid = finding.get("pid", 0)
                        reason = finding.get("reason", "focus loss")
                        self.detector.state.report_check("overlay", risk, f"{exe_name} (pid {pid}): {reason}", [finding])
                except Exception:
                    pass

            WINEVENTPROC = ctypes.WINFUNCTYPE(
                None,
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.HWND,
                wintypes.LONG,
                wintypes.LONG,
                wintypes.DWORD,
                wintypes.DWORD
            )
            self._proc_ref = WINEVENTPROC(event_callback)
            self.hook = user32.SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_FOREGROUND,
                0,
                self._proc_ref,
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
            )
            
            if self.hook:
                self.detector.mode = "event-driven"
                print("  [+] SetWinEventHook registered successfully (mode: event-driven).")
            else:
                self.detector.mode = "polling-fallback"
                print("  [!] SetWinEventHook registration failed; falling back to polling mode.")
            
            msg = wintypes.MSG()
            while self.running and user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as e:
            self.detector.mode = "polling-fallback"
            print(f"  [!] SetWinEventHook exception ({e}); continuing in polling-fallback mode.")
        finally:
            if self.hook:
                try:
                    user32.UnhookWinEvent(self.hook)
                except Exception:
                    pass

# Legitimate Software & Desktop Infrastructure Overlay Allowlist (False-Positive Mitigation)
LEGITIMATE_OVERLAY_ALLOWLIST = {
    "explorer.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "taskhostw.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchhost.exe", "searchapp.exe", "applicationframehost.exe", "systemsettings.exe",
    "narrator.exe", "nvda.exe", "jaws.exe", "magnify.exe", "osk.exe",
    "sentrioncompanion.exe", "python.exe", "pythonw.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    "snippingtool.exe", "screenclippinghost.exe", "screensketch.exe"
}

class OverlayDetector(threading.Thread):
    """
    Scans for:
    1. Focus loss when candidate switches away to any other application (Notepad, Word, Antigravity, File Explorer, Calculator, Settings, etc.) via event-driven SetWinEventHook + polling.
    2. Any third-party overlay window sitting on top (WS_EX_TOPMOST, WS_EX_LAYERED, WS_EX_TRANSPARENT, WS_EX_NOACTIVATE).
    """
    def __init__(self, state: DetectorState, poll_interval: float = 1.0):
        super().__init__(daemon=True, name="OverlayDetectorThread")
        self.state = state
        self.poll_interval = poll_interval
        self.running = True
        # Initialize event-driven system-wide focus hook listener
        self.focus_hook = WinEventFocusHookListener(self)
        self.focus_hook.start()

    def evaluate_foreground_window(self, fg_hwnd):
        if not fg_hwnd:
            return None, RiskLevel.CLEAR
        pid = wintypes.DWORD()
        GetWindowThreadProcessId(fg_hwnd, ctypes.byref(pid))
        if pid.value <= 0:
            return None, RiskLevel.CLEAR
        fg_exe_name, fg_exe_path = get_process_name_and_path(pid.value)
        fg_lower = fg_exe_name.lower()
        active_host = (getattr(self.state, "active_host_browser", None) or "").lower().strip()
        allowed_foreground = {active_host, "python.exe", "pythonw.exe", "sentrioncompanion.exe"} if active_host else BROWSER_EXECUTABLES

        # Allow Windows Snipping Tool / Screen Clipping Host without reporting focus loss
        if (
            fg_lower in {"snippingtool.exe", "screenclippinghost.exe", "screensketch.exe"}
            or "snipping" in fg_lower
            or "screenclip" in fg_lower
        ):
            return None, RiskLevel.CLEAR

        if fg_lower == "explorer.exe":
            length = GetWindowTextLengthW(fg_hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(fg_hwnd, buf, length + 1)
            fg_title = buf.value.strip()
            if fg_title and fg_title.lower() != "program manager":
                finding = {
                    "type": "FOCUS_LOSS",
                    "title": fg_title,
                    "pid": pid.value,
                    "exe_name": fg_exe_name,
                    "exe_path": fg_exe_path,
                    "reason": f"Exam lost focus — Candidate switched to File Explorer window '{fg_title}'"
                }
                return finding, RiskLevel.VIOLATION
        elif fg_lower not in allowed_foreground and fg_lower not in SYSTEM_SHELL_EXECUTABLES:
            length = GetWindowTextLengthW(fg_hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(fg_hwnd, buf, length + 1)
            fg_title = buf.value or "<External Application>"
            finding = {
                "type": "FOCUS_LOSS",
                "title": fg_title,
                "pid": pid.value,
                "exe_name": fg_exe_name,
                "exe_path": fg_exe_path,
                "reason": f"Exam lost focus — Candidate switched to '{fg_title}' ({fg_exe_name})"
            }
            return finding, RiskLevel.VIOLATION
        return None, RiskLevel.CLEAR

    def run(self):
        while self.running:
            try:
                findings, risk = self.scan_overlay_and_focus()
                if risk != RiskLevel.CLEAR:
                    exe_name = findings[0].get("exe_name", "unknown")
                    pid = findings[0].get("pid", 0)
                    reason = findings[0].get("reason", "overlay detected")
                    details = f"{exe_name} (pid {pid}): {reason}"
                    self.state.report_check("overlay", risk, details, findings)
                else:
                    self.state.report_check("overlay", RiskLevel.CLEAR, "no active overlays or focus loss detected", [])
            except Exception as e:
                self.state.report_check("overlay", RiskLevel.CLEAR, f"scan completed: {e}", [])
                
            time.sleep(self.poll_interval)

    def scan_overlay_and_focus(self) -> tuple[list, str]:
        findings = []
        highest_risk = RiskLevel.CLEAR

        # 1. Check Foreground Window Focus Loss (Polling verification)
        fg_hwnd = GetForegroundWindow()
        fg_finding, fg_risk = self.evaluate_foreground_window(fg_hwnd)
        if fg_risk == RiskLevel.VIOLATION and fg_finding:
            findings.append(fg_finding)
            highest_risk = RiskLevel.VIOLATION

        # 2. Scan Desktop for Overlay / Always-On-Top Windows
        def enum_window_callback(hwnd, lparam):
            if not IsWindowVisible(hwnd):
                return True

            rect = wintypes.RECT()
            if not GetWindowRect(hwnd, ctypes.byref(rect)):
                return True

            width = rect.right - rect.left
            height = rect.bottom - rect.top

            if width < 50 or height < 50:
                return True

            ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE)

            is_topmost = bool(ex_style & WS_EX_TOPMOST)
            is_layered = bool(ex_style & WS_EX_LAYERED)
            is_transparent = bool(ex_style & WS_EX_TRANSPARENT)
            is_noactivate = bool(ex_style & WS_EX_NOACTIVATE)

            if is_topmost or (is_layered and is_transparent) or (is_noactivate and is_topmost):
                pid = wintypes.DWORD()
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                
                exe_name, exe_path = get_process_name_and_path(pid.value)
                exe_lower = exe_name.lower()
                
                # Exclude Windows system desktop shell infrastructure and legitimate allowlisted applications
                if (
                    exe_lower in LEGITIMATE_OVERLAY_ALLOWLIST
                    or "snipping" in exe_lower
                    or "screenclip" in exe_lower
                ):
                    return True

                length = GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value or "<Overlay Window>"

                reasons = []
                if is_topmost:
                    reasons.append("Always-on-top window (WS_EX_TOPMOST)")
                if is_layered and is_transparent:
                    reasons.append("Click-through transparent overlay (WS_EX_LAYERED + WS_EX_TRANSPARENT)")
                if is_noactivate:
                    reasons.append("Focusless window (WS_EX_NOACTIVATE)")

                findings.append({
                    "type": "OVERLAY_WINDOW",
                    "title": title,
                    "pid": pid.value,
                    "exe_name": exe_name,
                    "exe_path": exe_path,
                    "dimensions": f"{width}x{height}",
                    "reasons": reasons,
                    "reason": f"{', '.join(reasons)}: '{title}' ({exe_name})",
                    "ex_style_hex": hex(ex_style)
                })

            return True

        cb = WNDENUMPROC(enum_window_callback)
        EnumWindows(cb, 0)

        if findings and highest_risk == RiskLevel.CLEAR:
            highest_risk = RiskLevel.VIOLATION

        return findings, highest_risk

    def stop(self):
        self.running = False
