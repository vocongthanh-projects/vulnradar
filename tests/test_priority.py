import unittest

from vulnradar.priority import calculate_priority


class PriorityTests(unittest.TestCase):
    def test_priority_is_explainable_and_bounded(self):
        result = calculate_priority(in_kev=True, cvss_score=9.8, epss_score=0.8)
        self.assertEqual(result.score, 97.4)
        self.assertEqual(result.level, "critical")
        self.assertEqual(
            result.reasons,
            ("listed in CISA KEV", "CVSS 9.8", "EPSS 80.0%"),
        )

    def test_priority_handles_missing_signals(self):
        result = calculate_priority(in_kev=False, cvss_score=None, epss_score=None)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "low")
        self.assertEqual(result.reasons, ("limited evidence",))
