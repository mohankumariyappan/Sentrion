import ctypes
from ctypes import wintypes
import time
import win32gui
import subprocess
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

EVENT_SYSTEM_FOREGROUND = 0x0003
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002

focus_events = []

def event_cb(hHook, evt, hwnd, idObj, idChild, idThread, dwmsTime):
    cur_tick = kernel32.GetTickCount()
    lat = max(0.1, float(cur_tick - dwmsTime)) if dwmsTime else 1.0
    title = win32gui.GetWindowText(hwnd)
    focus_events.append((lat, title))
    print(f'[+] WinEventFocus Callback: latency={lat:.2}ms, title={title}')

WINEVENTPROC = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD, wintypes.HWND, wintypes.LONG, wintypes.LONG, wintypes.DWORD, wintypes.DWORD)
proc_ref = WINEVENTPROC(event_cb)
hook = user32.SetWinEventHook(
    EVENT_SYSTEM_FOREGROUND,
    EVENT_SYSTEM_FOREGROUND,
    0,
    proc_ref,
    0,
    0,
    WINEVENT_OUTOFCONTEXT
)

print('[+] SetWinEventHook registered, spawning notepad...')
p = subprocess.Popen(['notepad.exe'])
t0 = time.time()
while time.time() - t0 < 2.5:
    win32gui.PumpWaitingMessages()
    time.sleep(0.05)

p.run_command = p.kill()
user32.UnhookWinEvent(hook)
print(f'Total events recorded: {len(focus_events)}')
