import time
import os
import subprocess
import json
from companion.app import start_detection_threads
from companion.state import DETECTOR_STATE
from companion.benchmarks import BENCHMARK_COLLECTOR

if __name__ == '__main__':
    print("========================================================")
    print("  SENTRION LIVE ISSUE VRALES & OS BENCHMARK HARNESS  ")
    print("========================================================")
    
    print("[*] Initializing Sentrion OS Sentinel detection modules...")
    start_detection_threads()
    
    print("[+] Sleeping 3s to settle background monitors...")
    time.sleep(3.0)
    
    import sys
    import ctypes
    import win32gui

    print("[+] Triggering WMI_CREATION_EVENT by spawning an inspected test process...")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(4)"])
    time.sleep(3.0)

    print("[+] Triggering WM_DISPLAYCHANGE message to measure display latency...")
    # Find Sentrion display window
    def find_display_win(hwnd, lparam):
        cls = win32gui.GetClassName(hwnd)
        if "SentrionDisplayListener" in cls:
            win32gui.SendMessage(hwnd, 0x007E, 0, 0)
        return True
    try:
        win32gui.EnumWindows(find_display_win, 0)
    except Exception:
        pass

    print("[+] Triggering Focus Change Event...")
    try:
        import win32con
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = win32gui.DefWindowProc
        wc.lpszClassName = f"FocusBenchClass_{int(time.time()*1000)}"
        atom = win32gui.RegisterClass(wc)
        hwnd_test = win32gui.CreateWindow(atom, "SentrionFocusBenchmarkTarget", win32con.WS_OVERLAPPEDWINDOW | win32con.WS_VISIBLE, 100, 100, 300, 200, 0, 0, 0, None)
        win32gui.ShowWindow(hwnd_test, win32con.SW_SHOW)
        fg_hwnd = user32.GetForegroundWindow()
        fg_thread = user32.GetWindowThreadProcessId(fg_hwnd, 0)
        my_thread = kernel32.GetCurrentThreadId()
        user32.AttachThreadInput(my_thread, fg_thread, True)
        user32.SetForegroundWindow(hwnd_test)
        user32.AttachThreadInput(my_thread, fg_thread, False)
        time.sleep(0.8)
        win32gui.DestroyWindow(hwnd_test)
    except Exception as e:
        print(f"Focus trigger note: {e}")

    print("[*] Logging resources for 30 seconds...")
    time.sleep(30.0)
    
    report = BENCHMARK_COLLECTOR.generate_summary_report()
    
    with open('benchmark_summary.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\n========================================================")
    print("  SENTRION VERIFIED BENGHMARK REPORT (REAL MEASUREMENTS)")
    print("========================================================")
    print(json.dumps(report, indent=2))
    print("========================================================\n")
    os._exit(0)
