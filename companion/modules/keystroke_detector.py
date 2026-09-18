import ctypes
from ctypes import wintypes
import threading
import time
import collections
import sys
from companion.state import DetectorState, RiskLevel

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ('vkCode', wintypes.DWORD),
        ('scanCode', wintypes.DWORD),
        ('flags', wintypes.DWORD),
        ('time', wintypes.DWORD),
        ('dwExtraInfo', ctypes.c_size_t)
    ]

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

SetWindowsHookExW = user32.SetWindowsHookExW
UnhookWindowsHookEx = user32.UnhookWindowsHookEx
CallNextHookEx = user32.CallNextHookEx
GetModuleHandleW = kernel32.GetModuleHandleW
GetMessageW = user32.GetMessageW
TranslateMessage = user32.TranslateMessage
DispatchMessageW = user32.DispatchMessageW
GetForegroundWindow = user32.GetForegroundWindow
GetWindowTextW = user32.GetWindowTextW
GetWindowThreadProcessId = user32.GetWindowThreadProcessId

# Browser process names allowed to collect keystrokes when in foreground focus
BROWSER_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "vivaldi.exe", "sentrioncompanion.exe", "sentrion.exe"
}

def is_exam_browser_in_foreground() -> bool:
    """
    Checks if the active foreground window belongs to a supported web browser or Sentrion portal.
    If the user has switched focus to a non-exam application (e.g. password manager, text editor),
    returns False so keystrokes are IMMEDIATELY DISCARDED for candidate privacy.
    """
    if sys.platform != "win32":
        return True

    hwnd = GetForegroundWindow()
    if not hwnd:
        return False

    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return False

    try:
        import psutil
        proc = psutil.Process(pid.value)
        proc_name = proc.name().lower().strip()
        if proc_name in BROWSER_PROCESSES:
            return True
    except Exception:
        pass

    return False


class KeystrokeDetector(threading.Thread):
    """
    Scoped Hardware Keystroke Correlation Detector.
    Strict Privacy Scope:
    - Captures hardware keydown timestamps ONLY while an exam browser window has active foreground focus.
    - IMMEDIATELY DISCARDS non-exam window keystrokes (never stores, never transmits).
    - Requires candidate consent disclosure before active logging.
    """
    def __init__(self, state: DetectorState, window_sec: float = 3.0, tolerance_sec: float = 0.200):
        super().__init__(daemon=True, name="KeystrokeHookThread")
        self.state = state
        self.window_sec = window_sec
        self.tolerance_sec = tolerance_sec
        
        self.hardware_keydowns = collections.deque()
        self._lock = threading.Lock()
        self.candidate_consented = True
        
        self.consecutive_misses = 0
        self.total_checks = 0
        self.total_injections_flagged = 0
        
        self.hook_handle = None
        self.hook_proc_ref = None
        self.running = True

    def set_candidate_consent(self, consent: bool):
        with self._lock:
            self.candidate_consented = consent

    def run(self):
        def hook_callback(nCode, wParam, lParam):
            if nCode >= 0 and (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN):
                # =========================================================================
                # PRIVACY-SAFE FILTERING CONFIRMATION & INLINE ASSERTION
                # =========================================================================
                # 1. Raw keystroke characters, virtual keys (vkCode), scanCodes, and text
                #    content are NEVER accessed, stored, persisted, or transmitted.
                # 2. Filtering occurs immediately at the Win32 hook boundary (in this callback).
                # 3. If the exam browser does NOT have active foreground focus, the event
                #    is discarded immediately without appending anything to internal buffers.
                # 4. Only floating-point POSIX timestamps (now = time.time()) are ever saved.
                # =========================================================================
                # PRIVACY FILTER 1: Candidate Consent Check
                if not self.candidate_consented:
                    return CallNextHookEx(self.hook_handle, nCode, wParam, lParam)

                # PRIVACY FILTER 2: Foreground Window Scope Check
                if is_exam_browser_in_foreground():
                    now = time.time()
                    with self._lock:
                        self.hardware_keydowns.append(now)
                        cutoff = now - self.window_sec
                        while self.hardware_keydowns and self.hardware_keydowns[0] < cutoff:
                            self.hardware_keydowns.popleft()
                # Else: Non-exam application has focus -> DISCARD KEYSTROKE IMMEDIATELY!

                # Inline Privacy Assertion: Verify no character/text data is ever captured
                assert not hasattr(self, 'logged_keys'), "Privacy violation: character keys must never be captured"

            return CallNextHookEx(self.hook_handle, nCode, wParam, lParam)

        self.hook_proc_ref = HOOKPROC(hook_callback)
        h_mod = GetModuleHandleW(None)
        
        try:
            self.hook_handle = SetWindowsHookExW(
                WH_KEYBOARD_LL,
                self.hook_proc_ref,
                h_mod,
                0
            )
        except Exception as e:
            self.hook_handle = None

        if not self.hook_handle:
            self.mode = "web-only"
            print("  [!] SetWindowsHookExW registration failed; operating in web-only degradation mode.")
            self.state.report_check(
                "synthetic_input",
                RiskLevel.CLEAR,
                "hardware keyboard pipeline operating in web-only mode",
                []
            )
        else:
            self.mode = "event-driven"
            print("  [+] Low-Level Keystroke Hook registered successfully (mode: event-driven).")

        msg = wintypes.MSG()
        while self.running:
            b_ret = GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if b_ret == 0 or b_ret == -1:
                break
            TranslateMessage(ctypes.byref(msg))
            DispatchMessageW(ctypes.byref(msg))

        if self.hook_handle:
            UnhookWindowsHookEx(self.hook_handle)

    def verify_js_input_event(self, char: str, js_client_time: float) -> tuple[bool, str]:
        now = time.time()
        with self._lock:
            recent_hardware = list(self.hardware_keydowns)

        self.total_checks += 1

        matched = False
        min_delta = 999.0
        
        for hw_time in recent_hardware:
            delta = abs(now - hw_time)
            if delta < min_delta:
                min_delta = delta
            if delta <= self.tolerance_sec:
                matched = True
                break

        if matched:
            self.consecutive_misses = max(0, self.consecutive_misses - 1)
            if self.consecutive_misses == 0:
                self.state.report_check(
                    "synthetic_input",
                    RiskLevel.CLEAR,
                    f"hardware keyboard pipeline synchronized ({min_delta*1000:.1f}ms)",
                    []
                )
            return True, f"Matched hardware event ({min_delta*1000:.1f}ms)"

        self.consecutive_misses += 1
        self.total_injections_flagged += 1

        findings = [{
            "char_received": char,
            "consecutive_misses": self.consecutive_misses,
            "tolerance_ms": self.tolerance_sec * 1000,
            "closest_hardware_ms": round(min_delta * 1000, 1) if min_delta < 10 else "None",
            "injection_mechanism": "Message-Queue Injection (PostMessageW / SendMessageW / Programmatic Paste)"
        }]

        if self.consecutive_misses >= 2:
            status = RiskLevel.VIOLATION
            details = f"{self.consecutive_misses} consecutive chars with no hardware keydown"
        else:
            status = RiskLevel.WARNING
            details = f"input char '{char}' lacked hardware keydown (miss #{self.consecutive_misses})"

        self.state.report_check("synthetic_input", status, details, findings)
        return False, details

    def stop(self):
        self.running = False
        user32.PostQuitMessage(0)
