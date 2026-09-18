import unittest
from companion.state import DetectorState, RiskLevel
from companion.evidence import EVIDENCE_VAULT, capture_desktop_screenshot_base64
from companion.app import app, start_detection_threads

class TestStateAndAPI(unittest.TestCase):
    def setUp(self):
        self.state = DetectorState()
        self.client = app.test_client()

    def test_report_check_precedence(self):
        self.state.report_check("overlay", RiskLevel.CLEAR, "clear")
        self.assertEqual(self.state.overall_risk, RiskLevel.CLEAR)

        self.state.report_check("vm", RiskLevel.WARNING, "unsure")
        self.assertEqual(self.state.overall_risk, RiskLevel.WARNING)

        self.state.report_check("display", RiskLevel.VIOLATION, "multi-monitor")
        self.assertEqual(self.state.overall_risk, RiskLevel.VIOLATION)

    def test_evidence_fallback_generation(self):
        # Verify fallback badge generation is always a valid base64 jpeg
        b64_data = capture_desktop_screenshot_base64("overlay", "VIOLATION", "Test infraction")
        self.assertTrue(b64_data.startswith("data:image/jpeg;base64,"))
        self.assertGreater(len(b64_data), 100)

    def test_flask_api_flow(self):
        # 1. Health
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)

        # 2. Session Start
        res = self.client.post('/session/start', json={})
        self.assertEqual(res.status_code, 200)
        token = res.get_json()['token']

        # 3. Status with token
        res = self.client.get('/status', headers={'X-Session-Token': token})
        self.assertEqual(res.status_code, 200)

        # 4. Evidence Capture
        res = self.client.post('/evidence/capture', json={'module': 'overlay', 'status': 'VIOLATION', 'token': token})
        self.assertEqual(res.status_code, 200)

        # 5. Audit Export
        res = self.client.get('/audit/export', headers={'X-Session-Token': token})
        self.assertEqual(res.status_code, 200)

        # 6. Session End
        res = self.client.post('/session/end', json={'token': token})
        self.assertEqual(res.status_code, 200)

if __name__ == '__main__':
    unittest.main()
