import os
import sys
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

if getattr(sys, 'frozen', False):
    ROOT_DIR = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(sys.executable)))
else:
    ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from companion.state import DETECTOR_STATE
from companion.config import CONFIG_MANAGER
from companion.security import SECURITY_MANAGER
from companion.modules.overlay_detector import OverlayDetector
from companion.modules.vm_detector import VMDetector
from companion.modules.process_blacklist import ProcessBlacklistDetector
from companion.modules.hardware_detector import HardwareDetector
from companion.modules.keystroke_detector import KeystrokeDetector
from companion.modules.process_integrity import ProcessIntegrityDetector

app = Flask(__name__, static_folder=ROOT_DIR)

CORS(app, resources={r"/*": {"origins": "*"}}, allow_headers="*", methods=["GET", "POST", "OPTIONS"])

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

keystroke_module = None

def start_detection_threads():
    global keystroke_module
    
    t_overlay = OverlayDetector(DETECTOR_STATE)
    t_vm = VMDetector(DETECTOR_STATE)
    t_blacklist = ProcessBlacklistDetector(DETECTOR_STATE)
    t_hardware = HardwareDetector(DETECTOR_STATE)
    keystroke_module = KeystrokeDetector(DETECTOR_STATE)
    t_integrity = ProcessIntegrityDetector(DETECTOR_STATE)

    t_overlay.start()
    t_vm.start()
    t_blacklist.start()
    t_hardware.start()
    keystroke_module.start()
    t_integrity.start()

    time.sleep(0.3)
    overlay_mode = getattr(t_overlay, "mode", "event-driven")
    wmi_mode = getattr(getattr(t_blacklist, "wmi_watcher", None), "mode", "event-driven")
    disp_mode = getattr(getattr(t_hardware, "listener", None), "mode", "event-driven")
    key_mode = getattr(keystroke_module, "mode", "event-driven")

    print(f"  [+] Overlay & Focus Hook:           {overlay_mode.upper()}")
    print(f"  [+] Process Blacklist & WMI Watcher: {wmi_mode.upper()}")
    print(f"  [+] Display Topology Listener:       {disp_mode.upper()}")
    print(f"  [+] Low-Level Keystroke Hook:        {key_mode.upper()}")
    print(f"  [+] VM / Hypervisor Detector:        HARDWARE-POLL")
    print(f"  [+] Process Integrity Audit:         IN-PROCESS-AUDIT")

# Global Middleware: Origin Header Check & Rate Limiting
@app.before_request
def enforce_bridge_security():
    # Allow OPTIONS preflight requests for CORS
    if request.method == "OPTIONS":
        resp = jsonify({"status": "ok"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp, 200

    # Exclude static web assets, health check, status and evidence capture from strict origin validation
    path = request.path
    if path in ["/", "/index.html", "/exam-gate-demo.html", "/health", "/status", "/evidence/capture"]:
        return None

    # 1. Validate Origin / Referer Header
    origin = request.headers.get("Origin") or request.headers.get("X-Exam-Origin")
    referer = request.headers.get("Referer")
    valid_origin, origin_msg = SECURITY_MANAGER.validate_origin(origin, referer)
    if not valid_origin:
        return jsonify({"status": "error", "message": f"Forbidden: {origin_msg}"}), 403

    # 2. Extract Active Host Browser Header
    host_browser = request.headers.get("X-Host-Browser") or request.args.get("host_browser")
    if host_browser:
        DETECTOR_STATE.set_active_host_browser(host_browser)

    # 3. Rate Limiting Check
    client_ip = request.remote_addr or "127.0.0.1"
    token = request.headers.get("X-Session-Token") or request.headers.get("Authorization") or ""
    rate_identifier = f"{client_ip}:{token[:16]}"
    
    allowed, rate_msg = SECURITY_MANAGER.check_rate_limit(rate_identifier)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too Many Requests: {rate_msg}"}), 429

    return None

# Serves exam-gate-demo.html directly from 127.0.0.1:9999/
@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
@app.route("/exam-gate-demo.html", methods=["GET"])
def serve_web_page():
    return send_from_directory(ROOT_DIR, "exam-gate-demo.html")

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "service": "Sentrion Exam Integrity Companion Native Service",
        "version": "1.0.0",
        "port": 9999,
        "timestamp": time.time()
    }), 200

@app.route("/session/start", methods=["POST"])
def session_start():
    token_data = SECURITY_MANAGER.generate_token()
    return jsonify({
        "status": "success",
        "message": "Session established & HMAC token signed",
        "token": token_data["token"],
        "expires_in": token_data["expires_in"]
    }), 200

@app.route("/status", methods=["GET"])
def get_status():
    token = request.headers.get("X-Session-Token") or request.headers.get("Authorization") or request.args.get("token")
    if token and token.startswith("Bearer "):
        token = token[7:]

    if not token:
        return jsonify({"status": "error", "message": "Missing authentication token in X-Session-Token header"}), 401
        
    is_valid, err_msg = SECURITY_MANAGER.verify_token(token)
    if not is_valid:
        return jsonify({"status": "error", "message": f"Unauthorized: {err_msg}"}), 401

    snapshot = DETECTOR_STATE.snapshot()
    return jsonify(snapshot), 200

@app.route("/keystroke/event", methods=["POST"])
def register_keystroke():
    data = request.json or {}
    token = data.get("token") or request.headers.get("X-Session-Token")
    char = data.get("char", "")
    js_time = data.get("client_timestamp", time.time())

    if not token:
        return jsonify({"status": "error", "message": "Missing authentication token"}), 401
    is_valid, err_msg = SECURITY_MANAGER.verify_token(token)
    if not is_valid:
        return jsonify({"status": "error", "message": f"Unauthorized: {err_msg}"}), 401

    if not keystroke_module:
        return jsonify({"status": "error", "message": "Keystroke module inactive"}), 500

    is_matched, details = keystroke_module.verify_js_input_event(char, js_time)
    return jsonify({
        "status": "success",
        "is_hardware_confirmed": is_matched,
        "details": details,
        "consecutive_misses": keystroke_module.consecutive_misses
    }), 200

@app.route("/simulate", methods=["POST"])
def simulate_finding():
    data = request.json or {}
    token = data.get("token") or request.headers.get("X-Session-Token")
    if not token:
        return jsonify({"status": "error", "message": "Missing authentication token"}), 401
    is_valid, err_msg = SECURITY_MANAGER.verify_token(token)
    if not is_valid:
        return jsonify({"status": "error", "message": f"Unauthorized: {err_msg}"}), 401

    action = data.get("action")
    if action == "clear_all":
        DETECTOR_STATE.clear_simulation()
        return jsonify({"status": "success", "message": "All simulated states cleared"}), 200

    module = data.get("module")
    status = data.get("status")
    details = data.get("details", "Simulated event triggered")
    findings = data.get("findings", [])

    if not module or not status:
        return jsonify({"status": "error", "message": "Module and status required"}), 400

    DETECTOR_STATE.set_simulated_check(module, status, details, findings)
    return jsonify({
        "status": "success",
        "message": f"Simulated state updated for '{module}'",
        "new_overall_risk": DETECTOR_STATE.overall_risk
    }), 200

@app.route("/evidence/capture", methods=["POST"])
def capture_custom_evidence():
    data = request.json or {}
    # Allow local exam client on 127.0.0.1 to trigger immediate evidence capture
    token = data.get("token") or request.headers.get("X-Session-Token")
    if token:
        try:
            SECURITY_MANAGER.verify_token(token)
        except Exception:
            pass

    module_name = data.get("module", "overlay")
    status = data.get("status", "VIOLATION")
    details = data.get("details", "Tab Switch / Focus Lost Infraction")

    try:
        from companion.evidence import capture_desktop_screenshot_base64
        b64_shot = capture_desktop_screenshot_base64(module_name, status, details)
        if b64_shot:
            ev_item = {
                "id": f"EV-{int(time.time())}-{module_name.upper()}",
                "timestamp": time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}",
                "module": module_name,
                "status": status,
                "details": details,
                "screenshot": b64_shot
            }
            with DETECTOR_STATE._lock:
                DETECTOR_STATE.evidences.insert(0, ev_item)
                if len(DETECTOR_STATE.evidences) > 20:
                    DETECTOR_STATE.evidences.pop()
                DETECTOR_STATE._add_event_log_locked(module_name, status, details, [])
                DETECTOR_STATE.overall_risk = status
            return jsonify({"status": "success", "message": "Evidence screenshot captured successfully", "evidence": ev_item}), 200
        else:
            return jsonify({"status": "error", "message": "Screenshot capture returned empty buffer"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/session/end", methods=["POST"])
def session_end():
    data = request.json or {}
    token = data.get("token") or request.headers.get("X-Session-Token")
    if token:
        SECURITY_MANAGER.revoke_token(token)
    return jsonify({"status": "success", "message": "Session token successfully invalidated"}), 200

@app.route("/audit/export", methods=["GET"])
def export_audit_log():
    token = request.headers.get("X-Session-Token") or request.headers.get("Authorization") or request.args.get("token")
    if token and token.startswith("Bearer "):
        token = token[7:]
    if not token:
        return jsonify({"status": "error", "message": "Missing authentication token"}), 401
    is_valid, err_msg = SECURITY_MANAGER.verify_token(token)
    if not is_valid:
        return jsonify({"status": "error", "message": f"Unauthorized: {err_msg}"}), 401

    from companion.policy import POLICY_ENGINE
    return jsonify(POLICY_ENGINE.export_audit_log()), 200

if __name__ == "__main__":
    start_detection_threads()
    print("\n========================================================")
    print("  SENTRION EXAM INTEGRITY COMPANION SERVICE (NATIVE WINDOWS)")
    print("  Authenticated Localhost Web Server: http://127.0.0.1:9999")
    print("========================================================\n")
    app.run(host="127.0.0.1", port=9999, debug=False, threaded=True)
