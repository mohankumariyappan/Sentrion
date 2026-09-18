import tkinter as tk
import webbrowser
import threading
import time

class SentrionDesktopGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SENTRION · Security Sentinel")
        self.root.geometry("460x520")
        self.root.resizable(False, False)
        self.root.configure(bg="#080B11")
        
        # Windows Topmost Window
        try:
            self.root.wm_attributes("-topmost", 1)
        except Exception:
            pass

        self.scanning = True
        self.scan_dots = 0
        
        self.build_ui()
        self.start_live_updates()

    def build_ui(self):
        # Header Canvas Container with Custom Cyber Radar Emblem
        header_frame = tk.Frame(self.root, bg="#0F141F", bd=0, highlightthickness=1, highlightbackground="#1E2738")
        header_frame.pack(fill="x", padx=16, pady=(16, 8))

        header_inner = tk.Frame(header_frame, bg="#0F141F")
        header_inner.pack(padx=14, pady=12, fill="x")

        # Cyber Radar SVG-like Canvas Emblem
        canvas = tk.Canvas(header_inner, width=44, height=44, bg="#0F141F", highlightthickness=0)
        canvas.pack(side="left", padx=(0, 12))
        
        # Draw Hexagon Outer Ring
        pts = [22, 2, 40, 11, 40, 33, 22, 42, 4, 33, 4, 11]
        canvas.create_polygon(pts, fill="#080B11", outline="#2563EB", width=2.5)
        # Radar Target Center
        canvas.create_oval(16, 16, 28, 28, outline="#2563EB", width=2)
        canvas.create_oval(19, 19, 25, 25, fill="#34D399", outline="")
        # Vertex LED Node
        canvas.create_oval(37, 9, 43, 15, fill="#34D399", outline="")

        # Title & Subtitle Text
        text_frame = tk.Frame(header_inner, bg="#0F141F")
        text_frame.pack(side="left", fill="both", expand=True)

        lbl_title = tk.Label(
            text_frame, 
            text="SENTRION", 
            font=("Space Grotesk", 16, "bold"), 
            fg="#FFFFFF", 
            bg="#0F141F"
        )
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(
            text_frame, 
            text="NATIVE EXAM SECURITY ENGINE", 
            font=("Inter", 8, "bold"), 
            fg="#3B82F6", 
            bg="#0F141F"
        )
        lbl_sub.pack(anchor="w")

        # Security Operational Banner (No port/link exposed)
        info_card = tk.Frame(self.root, bg="#0F141F", bd=0, highlightthickness=1, highlightbackground="#1E2738")
        info_card.pack(fill="x", padx=16, pady=6)

        info_inner = tk.Frame(info_card, bg="#0F141F")
        info_inner.pack(padx=14, pady=10, fill="x")

        lbl_info_header = tk.Label(
            info_inner,
            text="EXAM SENTINEL SHIELD ENGAGED",
            font=("Space Grotesk", 9, "bold"),
            fg="#38BDF8",
            bg="#0F141F"
        )
        lbl_info_header.pack(anchor="w")

        lbl_info_text = tk.Label(
            info_inner,
            text="Hardware diagnostics & focus monitoring active.\nPlease complete your assessment in the designated exam browser.",
            font=("Inter", 8),
            fg="#94A3B8",
            bg="#0F141F",
            justify="left"
        )
        lbl_info_text.pack(anchor="w", pady=(4, 0))

        # Live Scanning Status Banner Card
        status_card = tk.Frame(self.root, bg="#0F141F", bd=0, highlightthickness=1, highlightbackground="#1E2738")
        status_card.pack(fill="x", padx=16, pady=6)

        status_inner = tk.Frame(status_card, bg="#0F141F")
        status_inner.pack(padx=14, pady=10, fill="x")

        self.lbl_led = tk.Label(status_inner, text="●", font=("Inter", 12, "bold"), fg="#34D399", bg="#0F141F")
        self.lbl_led.pack(side="left", padx=(0, 6))

        self.lbl_status = tk.Label(
            status_inner, 
            text="ONLINE & MONITORING WINDOWS USER-MODE APIS", 
            font=("JetBrains Mono", 9, "bold"), 
            fg="#34D399", 
            bg="#0F141F"
        )
        self.lbl_status.pack(side="left")

        # Metrics Display Grid Card
        metrics_frame = tk.Frame(self.root, bg="#0F141F", bd=0, highlightthickness=1, highlightbackground="#1E2738")
        metrics_frame.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        metrics_inner = tk.Frame(metrics_frame, bg="#0F141F")
        metrics_inner.pack(padx=14, pady=10, fill="both", expand=True)

        lbl_sec_title = tk.Label(
            metrics_inner, 
            text="ACTIVE OS SECURITY THREADS", 
            font=("Space Grotesk", 8, "bold"), 
            fg="#64748B", 
            bg="#0F141F"
        )
        lbl_sec_title.pack(anchor="w", pady=(0, 6))

        # Active Security Modules List (Port Address Hidden)
        self.modules = [
            ("● SetWinEventHook & Overlay Sentinel", "Real-time focus intercept & transparent window scan"),
            ("● WMI Process Creation Event Watcher", "Catching prohibited binaries the millisecond they launch"),
            ("● WM_DISPLAYCHANGE Display Topology", "Instant hardware monitor & HDMI hot-plug detection"),
            ("● Virtual Machine & CPUID Inspector", "Hardware hypervisor bit & physical disk bus check"),
            ("● Process Memory & Anti-Hollowing Audit", "Continuous user-mode VirtualQuery self-integrity check"),
            ("● Low-Level Keystroke Timing Hook", "Hardware input dwell/flight analysis (privacy-isolated)")
        ]

        for title, desc in self.modules:
            row = tk.Frame(metrics_inner, bg="#0F141F")
            row.pack(fill="x", pady=3)
            
            m_title = tk.Label(row, text=title, font=("Inter", 8, "bold"), fg="#34D399", bg="#0F141F")
            m_title.pack(anchor="w")
            
            m_desc = tk.Label(row, text=desc, font=("Inter", 7), fg="#64748B", bg="#0F141F")
            m_desc.pack(anchor="w")

    def start_live_updates(self):
        def loop():
            while self.scanning:
                time.sleep(0.6)
                self.scan_dots = (self.scan_dots + 1) % 4
                dots = "." * self.scan_dots
                try:
                    self.root.after(0, lambda d=dots: self.lbl_status.config(text=f"ONLINE & MONITORING WINDOWS USER-MODE APIS{d}"))
                except Exception:
                    break

        threading.Thread(target=loop, daemon=True).start()


def launch_desktop_gui():
    root = tk.Tk()
    app = SentrionDesktopGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_desktop_gui()
