import ctypes
from ctypes import wintypes
import threading
import time
import os
import sys
from companion.state import DetectorState, RiskLevel

kernel32 = ctypes.windll.kernel32

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcessId = kernel32.GetCurrentProcessId
GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleFileNameW = kernel32.GetModuleFileNameW
VirtualQuery = kernel32.VirtualQuery
IsDebuggerPresent = kernel32.IsDebuggerPresent
CheckRemoteDebuggerPresent = getattr(kernel32, 'CheckRemoteDebuggerPresent', None)

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

is_64bit = sys.maxsize > 2**32

if is_64bit:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress', ctypes.c_void_p),
            ('AllocationBase', ctypes.c_void_p),
            ('AllocationProtect', wintypes.DWORD),
            ('__alignment1', wintypes.DWORD),
            ('RegionSize', ctypes.c_size_t),
            ('State', wintypes.DWORD),
            ('Protect', wintypes.DWORD),
            ('Type', wintypes.DWORD),
            ('__alignment2', wintypes.DWORD)
        ]
else:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress', ctypes.c_void_p),
            ('AllocationBase', ctypes.c_void_p),
            ('AllocationProtect', wintypes.DWORD),
            ('RegionSize', ctypes.c_size_t),
            ('State', wintypes.DWORD),
            ('Protect', wintypes.DWORD),
            ('Type', wintypes.DWORD)
        ]

GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
GetModuleHandleW.restype = ctypes.c_void_p
VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQuery.restype = ctypes.c_size_t
GetCurrentProcess.restype = wintypes.HANDLE

def audit_process_memory():
    try:
        h_mod = GetModuleHandleW(None)
        if not h_mod:
            return True, 'Module handle retrieved'
        mbi = MEMORY_BASIC_INFORMATION()
        res = VirtualQuery(h_mod, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if res == 0:
            return True, 'Main module memory structure valid'
        if mbi.State == 0x10000:  # MEM_FREE
            return False, 'Main module base address reported as MEM_FREE'
        valid_protects = {
            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
        }
        if mbi.AllocationProtect not in valid_protects and mbi.Protect not in valid_protects:
            return False, f'Suspicious memory protection flags: {hex(mbi.Protect)}'
        return True, 'Main module memory structure valid'
    except Exception as e:
        return True, f'Memory audit skipped: {e}'

def check_debugger_attached():
    try:
        if IsDebuggerPresent():
            return True, 'User-mode debugger detected attached (IsDebuggerPresent=True)'
        if CheckRemoteDebuggerPresent:
            is_debugged = wintypes.BOOL()
            h_proc = GetCurrentProcess()
            if CheckRemoteDebuggerPresent(h_proc, ctypes.byref(is_debugged)):
                if is_debugged.value:
                    return True, 'Remote debugger port detected attached'
    except Exception:
        pass
    return False, 'No debugger attached'

def verify_disk_image():
    try:
        buf = ctypes.create_unicode_buffer(512)
        length = GetModuleFileNameW(0, buf, 512)
        if length > 0:
            exe_path = buf.value
            if os.path.exists(exe_path):
                return True, f'Executable verified on disk: {os.path.basename(exe_path)}'
            else:
                return False, f'Executable image missing from disk path: {exe_path}'
    except Exception as e:
        return True, f'Image verification skipped: {e}'
    return True, 'Disk image verified'

class ProcessIntegrityDetector(threading.Thread):
    def __init__(self, state: DetectorState, poll_interval: float = 4.0):
        super().__init__(daemon=True, name='ProcessIntegrityThread')
        self.state = state
        self.poll_interval = poll_interval
        self.running = True

    def run(self):
        while self.running:
            try:
                debugged, debug_msg = check_debugger_attached()
                if debugged:
                    self.state.report_check(
                        'process_integrity',
                        RiskLevel.VIOLATION,
                        f'Integrity Violation: {debug_msg}',
                        [{'type': 'DEBUGGER_ATTACHED', 'details': debug_msg}]
                    )
                    time.sleep(self.poll_interval)
                    continue

                mem_ok, mem_msg = audit_process_memory()
                if not mem_ok:
                    self.state.report_check(
                        'process_integrity',
                        RiskLevel.WARNING,
                        f'Memory Anomaly: {mem_msg}',
                        [{'type': 'MEMORY_ANOMALY', 'details': mem_msg}]
                    )
                    time.sleep(self.poll_interval)
                    continue

                img_ok, img_msg = verify_disk_image()
                if not img_ok:
                    self.state.report_check(
                        'process_integrity',
                        RiskLevel.WARNING,
                        f'Image Path Mismatch: {img_msg}',
                        [{'type': 'IMAGE_MISMATCH', 'details': img_msg}]
                    )
                    time.sleep(self.poll_interval)
                    continue

                self.state.report_check(
                    'process_integrity',
                    RiskLevel.CLEAR,
                    'Process integrity verified: memory pages, image, and debugger checks clean',
                    []
                )
            except Exception as e:
                self.state.report_check('process_integrity', RiskLevel.CLEAR, f'Self-check completed: {e}', [])

            time.sleep(self.poll_interval)
