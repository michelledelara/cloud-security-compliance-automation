import unittest
from src.dashboard import build_dashboard


class TestDashboard(unittest.TestCase):
    def test_dashboard_contains_core_sections_and_author(self):
        findings = [
            {
                "control_id": "IAM-01",
                "title": "MFA enabled for console users",
                "status": "FAIL",
                "severity": "HIGH",
                "service": "iam",
                "resource": "user/alice",
                "nist_csf_2_0": ["PR.AA"],
                "lgpd": ["Art. 46"],
                "recommendation": "Enable MFA.",
            },
            {
                "control_id": "CT-01",
                "title": "CloudTrail enabled",
                "status": "PASS",
                "severity": "INFO",
                "service": "cloudtrail",
                "resource": "account/cloudtrail",
                "nist_csf_2_0": ["DE.CM"],
                "lgpd": ["Art. 46"],
                "recommendation": "Keep logging enabled.",
            },
        ]

        html = build_dashboard(findings, "123456789012", "us-east-1")

        self.assertIn("Security Control Dashboard", html)
        self.assertIn("50.0%", html)
        self.assertIn("NIST CSF 2.0 mapping", html)
        self.assertIn("LGPD mapping", html)
        self.assertIn("Michelle de Lara Ferraz Silveira Almeida", html)


if __name__ == "__main__":
    unittest.main()
