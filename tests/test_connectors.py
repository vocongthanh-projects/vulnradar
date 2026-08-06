import unittest
from unittest.mock import Mock, patch

from vulnradar.connectors.cisa_kev import CISAKEVConnector
from vulnradar.connectors.nvd import NVDConnector


class ConnectorTests(unittest.TestCase):
    @patch("vulnradar.connectors.cisa_kev.requests.get")
    def test_cisa_connector_maps_kev_record(self, mock_get):
        response = Mock(status_code=200)
        response.__bool__ = Mock(return_value=True)
        response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-0100",
                    "vulnerabilityName": "Synthetic auth bypass",
                    "shortDescription": "Authentication bypass",
                    "requiredAction": "Apply the vendor update",
                    "dateAdded": "2099-01-01",
                }
            ]
        }
        mock_get.return_value = response

        records = CISAKEVConnector().fetch()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source_id"], "CVE-2099-0100")
        self.assertTrue(records[0]["in_kev"])
        self.assertIn("auth-bypass", records[0]["vuln_tags"])

    @patch("vulnradar.connectors.nvd.time.sleep")
    @patch("vulnradar.connectors.nvd.requests.get")
    def test_nvd_connector_maps_cvss_and_tags(self, mock_get, _mock_sleep):
        response = Mock(status_code=200)
        response.__bool__ = Mock(return_value=True)
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0101",
                        "published": "2099-01-01T00:00:00.000Z",
                        "descriptions": [
                            {"lang": "en", "value": "SQL injection allows code execution"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        records = NVDConnector().fetch(days=1)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cvss_score"], 9.8)
        self.assertIn("sqli", records[0]["vuln_tags"])
        self.assertIn("rce", records[0]["vuln_tags"])
