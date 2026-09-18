import threading
import time
from datetime import datetime

class RiskLevel:
    CLEAR = "CLEAR"
    WARNING = "WARNING"
    VIOLATION = "VIOLATION"

class DetectorState:
    """
    Thread-safe shared state container for all 6 detection modules.
    Recomputes overall system risk using strict precedence:
    VIOLATION > WARNING > CLEAR.
    Implements TTL caching (500ms) to ensure near-zero CPU overhead during high-frequency API polling.
    """
    def __init__(self, cache_ttl_sec: float = 0.5):
        self._lock = threading.Lock()
        self.modules = {
            "overlay": {"status": RiskLevel.CLEAR, "details": "no suspicious overlay windows active", "findings": []},
            "vm": {"status": RiskLevel.CLEAR, "details": "physical hardware environment verified", "findings": []},
            "display": {"status": RiskLevel.CLEAR, "details": "single physical display verified", "findings": []},
            "process_blacklist": {"status": RiskLevel.CLEAR, "details": "no prohibited applications detected", "findings": []},
            "camera": {"status": RiskLevel.CLEAR, "details": "single candidate face verified (multi-person sentinel active)", "findings": []},
            "synthetic_input": {"status": RiskLevel.CLEAR, "details": "hardware keyboard pipeline synchronized", "findings": []},
            "process_integrity": {"status": RiskLevel.CLEAR, "details": "companion process memory & integrity verified", "findings": []}
        }
        self.overall_risk = RiskLevel.CLEAR
        self.event_log = []
        self.evidences = []
        self.last_evidence_time = {}
        self.max_events = 100
        self.simulated_violations = {}
        self.active_host_browser = None

        # Snapshot Caching Strategy to Eliminate CPU Spikes Under High Request Load
        self.cache_ttl_sec = cache_ttl_sec
        self._cached_snapshot = None
        self._last_snapshot_time = 0.0

    def set_active_host_browser(self, browser_exe: str):
        if browser_exe:
            with self._lock:
                self.active_host_browser = browser_exe.lower().strip()

    def report_check(self, module_name: str, status: str, details: str, findings: list = None):
        """Updates module status and recomputes overall risk precedence under lock."""
        with self._lock:
            if findings is None:
                findings = []
                
            prev_status = self.modules.get(module_name, {}).get("status")
            
            # Check if simulation is active for this module
            if module_name in self.simulated_violations:
                sim_data = self.simulated_violations[module_name]
                status = sim_data["status"]
                details = sim_data["details"]
                findings = sim_data.get("findings", findings)

            self.modules[module_name] = {
                "status": status,
                "details": details,
                "findings": findings,
                "last_updated": datetime.now().isoformat()
            }
            
            # Log event continuously for real-time telemetry streaming
            self._add_event_log_locked(module_name, status, details, findings)

            # Capture desktop screenshot evidence on security flags (with 8s cooldown guard)
            if status in (RiskLevel.WARNING, RiskLevel.VIOLATION):
                now_sec = time.time()
                last_t = self.last_evidence_time.get(module_name, 0.0)
                if (now_sec - last_t) >= 1.0:
                    self.last_evidence_time[module_name] = now_sec
                    try:
                        from companion.evidence import capture_desktop_screenshot_base64
                        b64_shot = capture_desktop_screenshot_base64()
                        if b64_shot:
                            ev_item = {
                                "id": f"EV-{int(now_sec)}-{module_name.upper()}",
                                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                "module": module_name,
                                "status": status,
                                "details": details,
                                "screenshot": b64_shot
                            }
                            self.evidences.insert(0, ev_item)
                            if len(self.evidences) > 20:
                                self.evidences.pop()
                    except Exception:
                        pass

            if status != RiskLevel.CLEAR or prev_status != status:
                try:
                    from companion.policy import POLICY_ENGINE
                    confidence = 0.80 if status == RiskLevel.VIOLATION else 0.40
                    POLICY_ENGINE.record_flag(module_name, status, confidence, details, findings)
                except Exception:
                    pass
                
            self._recompute_overall_risk_locked()
            self._cached_snapshot = None # Invalidate cache on state mutation

    def set_simulation(self, module_name: str, status: str, details: str, findings: list = None):
        """Injects a simulated event for demonstration and testing."""
        with self._lock:
            if status == RiskLevel.CLEAR or status.lower() == "clear":
                if module_name in self.simulated_violations:
                    del self.simulated_violations[module_name]
                status = RiskLevel.CLEAR
            else:
                status_upper = status.upper()
                self.simulated_violations[module_name] = {
                    "status": status_upper,
                    "details": details,
                    "findings": findings or []
                }
                status = status_upper

            current_findings = findings or []
            self.modules[module_name] = {
                "status": status,
                "details": details,
                "findings": current_findings,
                "last_updated": datetime.now().isoformat()
            }
            self._add_event_log_locked(module_name, status, f"[SIMULATED] {details}", current_findings)
            self._recompute_overall_risk_locked()
            self._cached_snapshot = None

    def set_simulated_check(self, module_name: str, status: str, details: str, findings: list = None):
        self.set_simulation(module_name, status, details, findings)

    def clear_simulations(self):
        """Clears all simulated overrides."""
        with self._lock:
            self.simulated_violations.clear()
            self._recompute_overall_risk_locked()
            self._cached_snapshot = None

    def clear_simulation(self):
        self.clear_simulations()

    def _recompute_overall_risk_locked(self):
        """Computes overall risk by strict precedence: VIOLATION > WARNING > CLEAR."""
        has_violation = any(m["status"] == RiskLevel.VIOLATION for m in self.modules.values())
        has_warning = any(m["status"] == RiskLevel.WARNING for m in self.modules.values())
        
        if has_violation:
            self.overall_risk = RiskLevel.VIOLATION
        elif has_warning:
            self.overall_risk = RiskLevel.WARNING
        else:
            self.overall_risk = RiskLevel.CLEAR

    def _add_event_log_locked(self, module_name: str, status: str, details: str, findings: list):
        event = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "module": module_name,
            "status": status,
            "details": details,
            "findings": findings
        }
        self.event_log.insert(0, event)
        if len(self.event_log) > self.max_events:
            self.event_log.pop()

    def get_snapshot(self) -> dict:
        """
        Returns cached snapshot formatted for Sentrion exam-gate-demo.html interface
        and backend API polling. Eliminates CPU spikes during high-frequency request polling.
        """
        now = time.time()
        with self._lock:
            if self._cached_snapshot and (now - self._last_snapshot_time) < self.cache_ttl_sec:
                return self._cached_snapshot

            checks_formatted = {}
            for k, v in self.modules.items():
                checks_formatted[k] = {
                    "status": v["status"].lower(),
                    "detail": v["details"],
                    "findings": v.get("findings", [])
                }

            snapshot_data = {
                "risk": self.overall_risk.lower(),
                "overall_risk": self.overall_risk,
                "timestamp": datetime.now().isoformat(),
                "checks": checks_formatted,
                "modules": {k: dict(v) for k, v in self.modules.items()},
                "event_log": list(self.event_log[:50]),
                "recent_events": list(self.event_log[:50]),
                "evidences": list(self.evidences[:15])
            }

            self._cached_snapshot = snapshot_data
            self._last_snapshot_time = now
            return snapshot_data

    def snapshot(self) -> dict:
        return self.get_snapshot()

# Shared singleton instance
DETECTOR_STATE = DetectorState()
