import sys
import os
import threading
import time
import webbrowser
from companion.app import app, start_detection_threads

def start_flask_server():
    # Disable default Flask startup logs to keep terminal clean
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    start_detection_threads()
    app.run(host="127.0.0.1", port=9999, debug=False, use_reloader=False)

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    
    print("========================================================")
    print("  SENTRION EXAM INTEGRITY NATIVE ENGINE & DESKTOP APP")
    print("  Native Security Bridge Active")
    print("========================================================")
    
    # 1. Start Flask API server in a background thread
    server_thread = threading.Thread(target=start_flask_server, daemon=True)
    server_thread.start()
    
    # Give Flask 0.6 seconds to bind to port 9999
    time.sleep(0.6)
    
    # 2. Launch Native Desktop App GUI on main thread
    from companion_gui import launch_desktop_gui
    launch_desktop_gui()
