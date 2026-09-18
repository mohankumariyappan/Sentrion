import ctypes
from ctypes import wintypes
import threading
import time
from collections import deque
from companion.state import DetectorState, RiskLevel

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Win32 Low-Level Keyboard Hook Constants
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ('vkCode', wintypes.DWORD),
        ('scanCode', wintypes.DWORD),
        ('flags', wintypes.DWORD),
        ('time', wintypes.DWORD),
        ('dwExtraInfo', ctypes.c_ulonglong)
    ]

HOOKPROC = ctypes.WINFUNCTYPE(
    ctypes.c_int64,
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.POINTER(KBDLLHOOKSTRUCT)
)

class SyntheticInputDetector(threading.Thread):
    def __init__(self, state: DetectorState, time_window_seconds: float = 3.0):
        super().__init__(daemon=True, name="SyntheticInputThread")
        self.state = state
        self.time_window = time_window_seconds
        
        self.hardware_keydowns = deque(maxlen=200)
        self.flight_times = deque(maxlen=20)
        
        self.last_hardware_time = 0.0
        self.consecutive_misses = 0
        self.key_blocking_enabled = False # KEY BLOCKING DISABLED AS REQUESTED
        self.hook_id = None
        self._hook_proc_ref = None
        self.running = True

    def run(self):
        def low_level_keyboard_proc(nCode, wParam, lParam):
            if nCode >= 0 and lParam:
                kb = lParam.contents
                vk = kb.vkCode
                
                # Log Hardware Keystrokes for Synthetic Input Correlation
                if wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                    now = time.time()
                    if self.last_hardware_time > 0:
                        flight = (now - self.last_hardware_time) * 1000.0
                        self.flight_times.append(flight)
                        
                        if len(self.flight_times) >= 10:
                            avg_flight = sum(self.flight_times) / len(self.flight_times)
                            variance = sum((f - avg_flight) ** 2 for f in self.flight_times) / len(self.flight_times)
                            if variance < 1.0 and avg_flight < 35.0:
                                self.state.report_check(
                                    "synthetic_input",
                                    RiskLevel.VIOLATION,
                                    f"Bot Macro Injected Typing Detected (Flight Variance: {variance:.2f}ms)",
                                    []
                                )

                    self.last_hardware_time = now
                    self.hardware_keydowns.append((now, vk, kb.scanCode))
                    
            return user32.CallNextHookEx(self.hook_id, nCode, wParam, lParam)

        self._hook_proc_ref = HOOKPROC(low_level_keyboard_proc)
        h_module = kernel32.GetModuleHandleW(None)
        
        self.hook_id = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            self._hook_proc_ref,
            h_module,
            0
        )
        
        if not self.hook_id:
            self.state.report_check(
                "synthetic_input",
                RiskLevel.WARNING,
                "Failed to install WH_KEYBOARD_LL hardware key monitor",
                []
            )
            return

        self.state.report_check(
            "synthetic_input",
            RiskLevel.CLEAR,
            "WH_KEYBOARD_LL active (Keystroke correlation monitor)",
            []
        )

        msg = wintypes.MSG()
        while self.running:
            b_ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if b_ret == 0 or b_ret == -1:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        if self.hook_id:
            user32.UnhookWindowsHookEx(self.hook_id)

    def verify_character_event(self, char: str, client_timestamp: float) -> tuple[bool, str]:
        now = time.time()
        recent_matches = [
            t for (t, vk, scan) in list(self.hardware_keydowns)
            if (now - t) <= self.time_window
        ]
        
        if recent_matches:
            self.consecutive_misses = 0
            self.state.report_check("synthetic_input", RiskLevel.CLEAR, f"input char '{char}' matched hardware keydown", [])
            return True, "Matched hardware keydown"
        else:
            self.consecutive_misses += 1
            severity = RiskLevel.WARNING if self.consecutive_misses < 3 else RiskLevel.VIOLATION
            msg = f"input char '{char}' lacked hardware keydown (miss #{self.consecutive_misses})"
            self.state.report_check("synthetic_input", severity, msg, [])
            return False, msg

    def stop(self):
        self.running = False
        if self.hook_id:
            user32.UnhookWindowsHookEx(self.hook_id)
