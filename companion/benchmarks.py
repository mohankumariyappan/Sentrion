import time
import os
import csv
import threading
import psutil

class BenchmarkCollector:
    def __init__(self, log_csv_path="benchmark_metrics.csv"):
        self.log_csv_path = log_csv_path
        self._lock = threading.Lock()
        self.focus_latencies = []
        self.wmi_latencies = []
        self.display_latencies = []
        self.resource_samples = []
        self.running = True
        self.proc = psutil.Process()
        with open(self.log_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_iso", "uptime_sec", "cpu_percent", "ram_rss_mb", "ram_vms_mb", "threads"])
        self._sampler_thread = threading.Thread(target=self._resource_sampler_loop, daemon=True, name="BenchmarkSamplerThread")
        self._sampler_thread.start()

    def record_focus_latency(self, latency_ms: float, window_title: str = ""):
        with self._lock:
            self.focus_latencies.append((time.time(), latency_ms, window_title))

    def record_wmi_latency(self, latency_ms: float, exe_name: str = ""):
        with self._lock:
            self.wmi_latencies.append((time.time(), latency_ms, exe_name))

    def record_display_latency(self, latency_ms: float):
        with self._lock:
            self.display_latencies.append((time.time(), latency_ms))

    def _resource_sampler_loop(self):
        start_time = time.time()
        while self.running:
            try:
                cpu_pct = self.proc.cpu_percent(interval=1.0)
                mem = self.proc.memory_info()
                rss_mb = round(mem.rss / (1024 * 1024), 2)
                vms_mb = round(mem.vms / (1024 * 1024), 2)
                threads = self.proc.num_threads()
                uptime = round(time.time() - start_time, 1)
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                with self._lock:
                    self.resource_samples.append((now_iso, uptime, cpu_pct, rss_mb, vms_mb, threads))
                    with open(self.log_csv_path, "a", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow([now_iso, uptime, cpu_pct, rss_mb, vms_mb, threads])
            except Exception:
                pass
            time.sleep(29.0)

    def generate_summary_report(self) -> dict:
        with self._lock:
            def stats(vals):
                if not vals:
                    return {"count": 0, "min_ms": 0.0, "max_ms": 0.0, "avg_ms": 0.0}
                nums = [v[1] for v in vals]
                return {
                    "count": len(nums),
                    "min_ms": round(min(nums), 2),
                    "max_ms": round(max(nums), 2),
                    "avg_ms": round(sum(nums) / len(nums), 2)
                }
            cpu_vals = [s[2] for s in self.resource_samples] if self.resource_samples else [0.0]
            ram_vals = [s[3] for s in self.resource_samples] if self.resource_samples else [0.0]
            return {
                "focus_hook": stats(self.focus_latencies),
                "wmi_process_creation": stats(self.wmi_latencies),
                "display_change": stats(self.display_latencies),
                "resources": {
                    "samples_count": len(self.resource_samples),
                    "cpu_percent_avg": round(sum(cpu_vals) / len(cpu_vals), 2),
                    "cpu_percent_max": round(max(cpu_vals), 2),
                    "ram_rss_mb_avg": round(sum(ram_vals) / len(ram_vals), 2),
                    "ram_rss_mb_max": round(max(ram_vals), 2)
                }
            }

BENCHMARK_COLLECTOR = BenchmarkCollector()
