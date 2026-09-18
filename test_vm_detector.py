import unittest
import sys
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from companion.modules.vm_detector import compute_combined_vm_score

class TestVMConfidenceFormula(unittest.TestCase):
    def test_empty_signals(self):
        """No signals detected should yield 0.0 confidence."""
        score = compute_combined_vm_score([])
        self.assertEqual(score, 0.0)

    def test_single_signal_only(self):
        """Single signal should yield exact weight of that signal."""
        self.assertAlmostEqual(compute_combined_vm_score([0.40]), 0.40, places=3)
        self.assertAlmostEqual(compute_combined_vm_score([0.35]), 0.35, places=3)
        self.assertAlmostEqual(compute_combined_vm_score([0.20]), 0.20, places=3)

    def test_multiple_signals_combined(self):
        """
        CPUID (0.40) + Registry (0.35) -> 1 - (0.60 * 0.65) = 0.6100.
        Demonstrates combination past 0.50 violation threshold.
        """
        score = compute_combined_vm_score([0.40, 0.35])
        self.assertAlmostEqual(score, 0.61, places=3)
        self.assertGreaterEqual(score, 0.50)

    def test_three_weak_signals_combined(self):
        """MAC OUI (0.20) + Driver (0.30) + Registry (0.15) -> 1 - (0.80 * 0.70 * 0.85) = 0.524."""
        score = compute_combined_vm_score([0.20, 0.30, 0.15])
        self.assertAlmostEqual(score, 0.524, places=3)
        self.assertGreaterEqual(score, 0.50)

    def test_threshold_edge_case_below_050(self):
        """MAC OUI (0.20) + Driver (0.30) -> 1 - (0.80 * 0.70) = 0.44 -> WARNING (below 0.50 violation threshold)."""
        score = compute_combined_vm_score([0.20, 0.30])
        self.assertEqual(score, 0.44)
        self.assertLess(score, 0.50)
        self.assertGreaterEqual(score, 0.25)

    def test_threshold_edge_case_exactly_050(self):
        """
        Weights resulting in exactly 0.50 confidence.
        For example: weight 0.50 -> 1 - (1 - 0.50) = 0.50.
        Must evaluate to VIOLATION (>= 0.50).
        """
        score = compute_combined_vm_score([0.50])
        self.assertEqual(score, 0.50)
        self.assertGreaterEqual(score, 0.50)

    def test_asymptotic_clamping_to_one(self):
        """Even with 5 strong signals, combined score must never exceed 1.0."""
        score = compute_combined_vm_score([0.40, 0.35, 0.30, 0.30, 0.20])
        self.assertLessEqual(score, 1.0)
        self.assertGreater(score, 0.80)

if __name__ == "__main__":
    unittest.main()
