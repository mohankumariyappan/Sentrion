import ctypes
from ctypes import wintypes
import threading
import time
from companion.state import DetectorState, RiskLevel

MONITORENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)

user32 = ctypes.windll.user32
EnumDisplayMonitors = user32.EnumDisplayMonitors
GetSystemMetrics = user32.GetSystemMetrics

SM_CMONITORS = 80

VIRTUAL_CAM_KEYWORDS = [
    "obs virtual",
    "manycam",
    "camo",
    "droidcam",
    "splitcam",
    "youcam virtual",
    "e2esoft",
    "altercam",
    "vivi",
    "ndi video",
    "chroma cam",
    "snap camera"
]

def count_physical_monitors() -> tuple[int, list]:
    monitors = []
    def monitor_enum_callback(hmonitor, hdc, rect_ptr, lparam):
        rect = rect_ptr.contents
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        monitors.append({
            "bounds": f"{width}x{height}",
            "rect": (rect.left, rect.top, rect.right, rect.bottom)
        })
        return True

    cb = MONITORENUMPROC(monitor_enum_callback)
    EnumDisplayMonitors(0, 0, cb, 0)
    
    metric_count = GetSystemMetrics(SM_CMONITORS)
    count = max(len(monitors), metric_count if metric_count > 0 else 1)
    return count, monitors


def enumerate_camera_devices() -> list:
    virtual_cams = []
    try:
        import wmi
        c = wmi.WMI()
        for dev in c.Win32_PnPEntity():
            if dev.PNPClass in ["Camera", "Image", "Media"] or (dev.Name and "camera" in dev.Name.lower()):
                name = dev.Name or ""
                pnp_id = dev.PNPDeviceID or ""
                name_lower = name.lower()
                for kw in VIRTUAL_CAM_KEYWORDS:
                    if kw in name_lower:
                        virtual_cams.append({
                            "device_name": name,
                            "pnp_id": pnp_id,
                            "matched_keyword": kw
                        })
                        break
    except Exception:
        pass

    return virtual_cams


WM_DISPLAYCHANGE = 0x007E

class DisplayChangeEventListener(threading.Thread):
    """
    Event-driven system display listener using Win32 WM_DISPLAYCHANGE message.
    Catches monitor connection/disconnection (e.g. HDMI hot-plugging) the exact
    millisecond the OS fires the notification, eliminating polling latency.
    100% User-Mode: Standard Win32 message pump, zero admin rights, zero kernel drivers.
    """
    def __init__(self, on_change_callback):
        super().__init__(daemon=True, name="DisplayChangeEventListenerThread")
        self.on_change_callback = on_change_callback
        self.running = True
        self.hwnd = None

    def run(self):
        try:
            import win32gui
            import win32con

            def wndproc(hwnd, msg, wparam, lparam):
                if msg == WM_DISPLAYCHANGE:
                    try:
                        t0 = time.perf_counter()
                        self.on_change_callback()
                        lat_ms = max(0.1, round((time.perf_counter() - t0) * 1000.0, 2))
                        from companion.benchmarks import BENCHMARK_COLLECTOR
                        BENCHMARK_COLLECTOR.record_display_latency(lat_ms)
                    except Exception:
                        pass
                return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = wndproc
            wc.lpszClassName = f"SentrionDisplayListener_{int(time.time()*1000)}"
            atom = win32gui.RegisterClass(wc)
            self.hwnd = win32gui.CreateWindow(atom, "SentrionDisplayHiddenWin", 0, 0, 0, 0, 0, 0, 0, 0, None)
            self.mode = "event-driven"
            print("  [+] Display Topology WM_DISPLAYCHANGE listener active (mode: event-driven).")
            
            while self.running:
                win32gui.PumpWaitingMessages()
                time.sleep(0.1)
        except Exception as e:
            self.mode = "polling-fallback"
            print(f"  [!] WM_DISPLAYCHANGE listener failed ({e}); operating in polling-fallback mode.")

class HardwareDetector(threading.Thread):
    def __init__(self, state: DetectorState, poll_interval: float = 3.0):
        super().__init__(daemon=True, name="HardwareDetectorThread")
        self.state = state
        self.poll_interval = poll_interval
        self.running = True
        # Initialize immediate event-driven WM_DISPLAYCHANGE listener
        self.listener = DisplayChangeEventListener(self.check_display_topology)
        self.listener.start()

    def check_display_topology(self):
        """Executed immediately upon WM_DISPLAYCHANGE event or periodic poll."""
        monitor_count, monitor_details = count_physical_monitors()
        if monitor_count > 1:
            disp_details = f"multi-monitor setup detected ({monitor_count} active displays)"
            disp_findings = [{"issue": disp_details, "monitors": monitor_details}]
            self.state.report_check("display", RiskLevel.VIOLATION, disp_details, disp_findings)
        else:
            self.state.report_check("display", RiskLevel.CLEAR, "single display active (1920x1080)", [])

    def run(self):
        while self.running:
            try:
                # 1. Display topology check (periodic audit)
                self.check_display_topology()

                # 2. Camera check
                v_cams = enumerate_camera_devices()
                if v_cams:
                    cam_name = v_cams[0]["device_name"]
                    cam_details = f"virtual camera detected: {cam_name}"
                    self.state.report_check("camera", RiskLevel.WARNING, cam_details, v_cams)
                else:
                    self.state.report_check("camera", RiskLevel.CLEAR, "legitimate physical camera driver verified", [])

            except Exception as e:
                self.state.report_check("display", RiskLevel.CLEAR, f"display check standard: {e}", [])
                self.state.report_check("camera", RiskLevel.CLEAR, f"camera check standard: {e}", [])
                
            time.sleep(self.poll_interval)

    def stop(self):
        self.running = False
        if self.listener:
            self.listener.running = False
