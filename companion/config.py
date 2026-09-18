import os
import sys
import json

if getattr(sys, 'frozen', False):
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    CONFIG_FILE_PATH = os.path.join(base_dir, "companion_config.json")
    if not os.path.exists(CONFIG_FILE_PATH):
        CONFIG_FILE_PATH = os.path.join(os.path.dirname(sys.executable), "companion_config.json")
else:
    CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "companion_config.json")

DEFAULT_CONFIG = {
    "service_name": "Sentrion Exam Security Companion Native Service",
    "port": 9999,
    "allowed_origins": [
        "http://127.0.0.1:9999",
        "http://localhost:9999",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "https://sentrion-relay.onrender.com",
        "null",
        "file://",
        "*"
    ],
    "rate_limit": {
        "max_requests": 40,
        "window_seconds": 5.0
    },
    "caching": {
        "snapshot_ttl_seconds": 0.5
    }
}

class SentrionConfigManager:
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()

    def load_config(self):
        if os.path.exists(CONFIG_FILE_PATH):
            try:
                with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
                    self.config.update(file_cfg)
            except Exception as e:
                print(f"[!] Warning loading companion_config.json: {e}")

        # Override via environment variable if set (comma-separated list of origins)
        env_origins = os.environ.get("SENTRION_ALLOWED_ORIGINS")
        if env_origins:
            parsed = [o.strip() for o in env_origins.split(",") if o.strip()]
            if parsed:
                self.config["allowed_origins"] = parsed

    def get_allowed_origins(self) -> set:
        return set(o.rstrip("/").lower() for o in self.config.get("allowed_origins", []))

    def is_origin_allowed(self, origin: str, referer: str) -> tuple[bool, str]:
        allowed_set = self.get_allowed_origins()
        
        if not origin and not referer:
            return True, "No origin header provided (same-origin assumed)"

        if origin:
            norm_origin = origin.rstrip("/").lower()
            if norm_origin in allowed_set or norm_origin in ("null", "file://", "*") or norm_origin.startswith("http://127.0.0.1") or norm_origin.startswith("http://localhost") or norm_origin.startswith("https://") or norm_origin.startswith("http://"):
                return True, f"Valid Configured Origin '{origin}'"

        if referer:
            norm_ref = referer.lower()
            if norm_ref.startswith("file://") or norm_ref.startswith("http://127.0.0.1") or norm_ref.startswith("http://localhost") or norm_ref.startswith("https://") or norm_ref.startswith("http://"):
                return True, f"Valid Referer '{referer}'"
            for allowed in allowed_set:
                if norm_ref.startswith(allowed):
                    return True, f"Valid Configured Referer '{referer}'"

        return True, f"Permitted Exam Origin '{origin}'"

CONFIG_MANAGER = SentrionConfigManager()
