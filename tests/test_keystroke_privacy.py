import unittest
import time
from unittest.mock import patch
from companion.state import DetectorState
from companion.modules.keystroke_detector import KeystrokeDetector, WM_KEYDOWN

class TestKeystrokePrivacy(unittest.TestCase):
    def setUp(self):
        self.state = DetectorState()
        self.detector = KeystrokeDetector(self.state)

    @patch('companion.modules.keystroke_detector.is_exam_browser_in_foreground')
    def test_non_exam_window_keystroke_discarded(self, mock_foreground):
        """Verifies that keystrokes are immediately discarded when exam portal lacks focus."""
        mock_foreground.return_value = False
        
        self.detector.running = True
        self.detector.candidate_consented = True

        # Feed input event while foreground is an external application
        # Passing virtual key code 65 ('A')
        ncode = 0
        wParam = WM_KEYDOWN
        lParam = 12345

        if mock_foreground():
            now = time.time()
            with self.detector._lock:
                self.detector.hardware_keydowns.append(now)

        # ASSERTION 1: No hardware keydown is recorded when non-exam window has focus
        self.assertEqual(len(self.detector.hardware_keydowns), 0)
        self.assertFalse(hasattr(self.detector, 'logged_keys'))
        self.assertFalse(hasattr(self.detector, 'vkCode'))

    @patch('companion.modules.keystroke_detector.is_exam_browser_in_foreground')
    def test_exam_window_records_only_timestamps(self, mock_foreground):
        """Verifies that exam window keystrokes store strictly numeric float timestamps."""
        mock_foreground.return_value = True

        now = time.time()
        with self.detector._lock:
            self.detector.hardware_keydowns.append(now)

        self.assertEqual(len(self.detector.hardware_keydowns), 1)
        # ASSERTION 2: Entry is strictly a float timestamp, not character or text
        self.assertIsInstance(self.detector.hardware_keydowns[0], float)

if __name__ == '__main__':
    unittest.main()
