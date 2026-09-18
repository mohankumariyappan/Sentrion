import os
import sys
import time
import unittest
import subprocess
import requests

# Add workspace root to sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
COMPANION_DIR = os.path.join(ROOT_DIR, "companion")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if COMPANION_DIR not in sys.path:
    sys.path.insert(0, COMPANION_DIR)

from companion.security import SessionSecurityManager
from companion.state import DetectorState, RiskLevel

class TestSecurityAndState(unittest.TestCase):
    def setUp(self):
        self.security = SessionSecurityManager(ttl_seconds=5)
        self.state = DetectorState()

    def test_hmac_token_generation_and_verification(self):
        token_data = self.security.generate_token()
        token = token_data["token"]
        self.assertIn(".", token)
        
        # Valid signature verification
        is_valid, msg = self.security.verify_token(token)
        self.assertTrue(is_valid, f"Verification failed: {msg}")

        # Tampered token signature verification
        tampered_token = token[:-4] + "ffff"
        is_tampered_valid, msg = self.security.verify_token(tampered_token)
        self.assertFalse(is_tampered_valid, "Tampered token should be rejected!")

    def test_token_revocation(self):
        token_data = self.security.generate_token()
        token = token_data["token"]
        
        self.assertTrue(self.security.verify_token(token)[0])
        self.security.revoke_token(token)
        
        is_valid, msg = self.security.verify_token(token)
        self.assertFalse(is_valid, "Revoked token should be rejected!")

    def test_risk_level_precedence(self):
        self.state.report_check("overlay", RiskLevel.CLEAR, "Clear details")
        self.assertEqual(self.state.overall_risk, RiskLevel.CLEAR)

        self.state.report_check("vm", RiskLevel.WARNING, "Warning details")
        self.assertEqual(self.state.overall_risk, RiskLevel.WARNING)

        self.state.report_check("process_blacklist", RiskLevel.VIOLATION, "Violation details")
        self.assertEqual(self.state.overall_risk, RiskLevel.VIOLATION)

        # Violation should override warning
        self.state.report_check("process_blacklist", RiskLevel.CLEAR, "Clear details")
        self.assertEqual(self.state.overall_risk, RiskLevel.WARNING)


def test_live_companion_server():
    print("\n--- Testing Live Sentrion Companion Server (127.0.0.1:9999) ---")
    app_path = os.path.join(COMPANION_DIR, "app.py")
    
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT_DIR + os.pathsep + env.get("PYTHONPATH", "")

    # Launch companion server process with PYTHONPATH set to workspace root
    proc = subprocess.Popen([sys.executable, app_path], env=env)
    time.sleep(2.5) # Wait for Flask server binding & detection threads startup

    base_url = "http://127.0.0.1:9999"
    try:
        # 1. Root HTML serve check (exam-gate-demo.html)
        r = requests.get(f"{base_url}/", timeout=3)
        print(f"[+] GET / -> Status {r.status_code}: Served exam-gate-demo.html ({len(r.text)} bytes)")
        assert r.status_code == 200
        assert "Sentrion" in r.text

        # 2. Health check
        r = requests.get(f"{base_url}/health", timeout=3)
        print(f"[+] GET /health -> Status {r.status_code}: {r.json()}")
        assert r.status_code == 200
        assert "Sentrion" in r.json()["service"]

        # 3. Start Session (HMAC Handshake)
        r = requests.post(f"{base_url}/session/start")
        print(f"[+] POST /session/start -> Status {r.status_code}: {r.json()}")
        assert r.status_code == 200
        token = r.json()["token"]

        # 4. Poll /status with X-Session-Token header
        headers = {"X-Session-Token": token}
        r = requests.get(f"{base_url}/status", headers=headers)
        data = r.json()
        print(f"[+] GET /status -> Status {r.status_code}: Risk = '{data['risk']}', Checks = {list(data['checks'].keys())}")
        assert r.status_code == 200
        assert data["risk"] in ["clear", "warning", "violation"]
        assert len(data["checks"]) == 6

        # 5. Keystroke Event Verification
        ks_payload = {
            "token": token,
            "char": "x",
            "client_timestamp": time.time()
        }
        r = requests.post(f"{base_url}/keystroke/event", json=ks_payload)
        print(f"[+] POST /keystroke/event -> Status {r.status_code}: {r.json()}")
        assert r.status_code == 200

        # 6. Trigger Simulation Test
        sim_payload = {
            "token": token,
            "module": "overlay",
            "status": "VIOLATION",
            "details": "ghosttool.exe (pid 8842): click-through overlay",
            "findings": [{"test": "true"}]
        }
        r = requests.post(f"{base_url}/simulate", json=sim_payload)
        print(f"[+] POST /simulate -> Status {r.status_code}: {r.json()}")
        assert r.status_code == 200

        # Check updated status
        r = requests.get(f"{base_url}/status", headers=headers)
        risk = r.json()['risk']
        print(f"[+] GET /status after simulation -> Risk = '{risk}'")
        assert risk == "violation"

        # Reset simulation
        r = requests.post(f"{base_url}/simulate", json={"token": token, "action": "clear_all"})
        print(f"[+] POST /simulate (clear_all) -> Status {r.status_code}")

        # 7. End Session
        r = requests.post(f"{base_url}/session/end", json={"token": token})
        print(f"[+] POST /session/end -> Status {r.status_code}: {r.json()}")

        print("\n[+] ALL SENTRION INTEGRATION TESTS PASSED PERFECTLY!\n")
        return True
    finally:
        proc.terminate()
        proc.wait()


if __name__ == "__main__":
    print("==========================================================")
    print("   RUNNING AUTOMATED UNIT & SECURITY INTEGRATION TESTS   ")
    print("==========================================================")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurityAndState)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)

    test_live_companion_server()
