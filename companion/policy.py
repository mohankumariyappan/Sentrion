import os
import json
import time
from datetime import datetime
from collections import defaultdict

AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dist", "audit_log.json")

class EscalationTier:
    LOGGED_EVENT = "LOGGED_EVENT"       # Logged for audit trail & candidate appeal
    REVIEW_QUEUE = "REVIEW_QUEUE"       # Added to human proctor review queue
    TERMINATE_SESSION = "TERMINATE_SESSION" # Immediate session termination

class ViolationPolicyEngine:
    """
    Centralized Graduated Violation-Response Policy Engine.
    Routes security signals from all detection modules into a structured audit pipeline:
    1. Records every flag with timestamp, confidence, severity, and details.
    2. Persists flags to dist/audit_log.json.
    3. Escalates repeated or high-confidence signals to human proctor review queue.
    4. Triggers session termination ONLY on confirmed high-confidence violations.
    """
    def __init__(self):
        self.audit_log = []
        self.review_queue = []
        self.flag_counts = defaultdict(int)
        self.session_terminated = False
        self.termination_reason = None
        self.session_start_time = datetime.now().isoformat()

    def record_flag(
        self,
        module_name: str,
        severity: str,
        confidence: float,
        details: str,
        findings: list = None
    ) -> tuple[str, str]:
        """
        Processes a raw detection signal, determines graduated policy action,
        and logs to persistent audit record.
        Returns (escalation_tier, policy_decision_explanation).
        """
        now_dt = datetime.now()
        timestamp = now_dt.isoformat()
        
        flag_entry = {
            "id": len(self.audit_log) + 1,
            "timestamp": timestamp,
            "module": module_name,
            "severity": severity,
            "confidence": round(confidence, 3),
            "details": details,
            "findings": findings or []
        }

        # 1. Append to Audit Log
        self.audit_log.append(flag_entry)
        self.flag_counts[module_name] += 1
        count = self.flag_counts[module_name]

        # 2. Graduated Escalation Policy Decision Logic
        tier = EscalationTier.LOGGED_EVENT
        decision = "Flag logged to candidate audit trail."

        # High-confidence explicit threat binaries or VM hypervisors trigger termination
        if severity == "VIOLATION" and confidence >= 0.50:
            if count >= 2 or confidence >= 0.70:
                tier = EscalationTier.TERMINATE_SESSION
                self.session_terminated = True
                self.termination_reason = f"Confirmed High-Confidence Violation: {details}"
                decision = "Session Termination Triggered: Confirmed high-confidence threat."
            else:
                tier = EscalationTier.REVIEW_QUEUE
                decision = "Escalated to Proctor Review Queue (First Violation Flag)."
        elif severity == "WARNING" or count >= 2:
            tier = EscalationTier.REVIEW_QUEUE
            decision = f"Escalated to Proctor Review Queue (Repeated Flag #{count})."

        flag_entry["escalation_tier"] = tier
        flag_entry["policy_decision"] = decision

        if tier == EscalationTier.REVIEW_QUEUE:
            self.review_queue.append(flag_entry)

        # 3. Persist to Disk JSON Audit File
        self._persist_audit_file()
        return tier, decision

    def export_audit_log(self) -> dict:
        """Generates exportable JSON audit log for post-exam review or appeals."""
        return {
            "session_meta": {
                "session_start": self.session_start_time,
                "export_timestamp": datetime.now().isoformat(),
                "total_flags_recorded": len(self.audit_log),
                "review_queue_count": len(self.review_queue),
                "session_terminated": self.session_terminated,
                "termination_reason": self.termination_reason
            },
            "proctor_review_queue": self.review_queue,
            "audit_trail": self.audit_log
        }

    def _persist_audit_file(self):
        try:
            dist_dir = os.path.dirname(AUDIT_LOG_FILE)
            if not os.path.exists(dist_dir):
                os.makedirs(dist_dir, exist_ok=True)
            with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.export_audit_log(), f, indent=2)
        except Exception:
            pass

# Shared singleton instance
POLICY_ENGINE = ViolationPolicyEngine()
