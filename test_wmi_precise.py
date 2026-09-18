import pythoncom
import wmi
import subprocess
import sys
import time

pythoncom.CoInitialize()
c = wmi.WMI()
watcher = c.Win32_Process.watch_for(notification_type='creation', delay_secs=1)

print('[*] Watcher active, launching test process...')
t_spawn = time.time()
p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1)'])

new_proc = watcher(timeout_ms=5000)
t_recv = time.time()

dt_mp = (max(0.1, (t_recv - t_spawn)) * 1000.0)
print(f"[J] Caught {new_proc.Caption} (pid {new_proc.ProcessId}) in {dt_mp:1f}ms")
