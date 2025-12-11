import unittest
import os
import sys
import json
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tianlu_intel_collectors')))

from tianlu_intel_collectors.utils import get_session
from tianlu_intel_collectors.nvd import parse_nvd_cve
from tianlu_intel_collectors.cisa_kev import parse_cisa_kev
from tianlu_intel_collectors.models import NormalizedCVE
from tianlu_intel_collectors.errors import ErrorCode, CollectorError, NetworkError

class TestUtils(unittest.TestCase):
    @patch('requests.Session')
    def test_get_session(self, mock_session):
        session = get_session()
        self.assertIsNotNone(session)
        # Verify that we are mounting the adapter
        self.assertTrue(session.mount.called)

class TestModels(unittest.TestCase):
    def test_valid_cve_id(self):
        cve = NormalizedCVE(cve_id="CVE-2023-12345")
        self.assertEqual(cve.cve_id, "CVE-2023-12345")

    def test_invalid_cve_id(self):
        with self.assertRaises(ValueError):
            NormalizedCVE(cve_id="INVALID-ID")

    def test_model_defaults(self):
        cve = NormalizedCVE(cve_id="CVE-2023-0001")
        self.assertEqual(cve.vendors, [])
        self.assertIsNone(cve.severity)

class TestErrors(unittest.TestCase):
    def test_error_codes(self):
        err = NetworkError("Connection failed")
        self.assertEqual(err.code, ErrorCode.NETWORK_ERROR)
        self.assertIn("E101", str(err))

class TestNVDParser(unittest.TestCase):
    def test_parse_nvd_cve_valid(self):
        cve_item = {
            "id": "CVE-2023-1234",
            "descriptions": [{"lang": "en", "value": "Test description"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8, 
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL"
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9
                }]
            },
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-01-02T00:00:00.000"
        }
        normalized = parse_nvd_cve(cve_item)
        self.assertEqual(normalized.cve_id, "CVE-2023-1234")
        self.assertEqual(normalized.cvss_v3_score, 9.8)
        self.assertEqual(normalized.severity, "CRITICAL")
        self.assertEqual(normalized.description, "Test description")

    def test_parse_nvd_cve_missing_fields(self):
        cve_item = {
            "id": "CVE-2023-5678",
            "descriptions": [{"lang": "en", "value": "Minimal info"}]
        }
        normalized = parse_nvd_cve(cve_item)
        self.assertEqual(normalized.cve_id, "CVE-2023-5678")
        self.assertIsNone(normalized.cvss_v3_score)
        self.assertIsNone(normalized.severity)

class TestCISAKEVParser(unittest.TestCase):
    def test_parse_cisa_kev_valid(self):
        item = {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4j RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "Remote code execution vulnerability",
            "requiredAction": "Patch",
            "dueDate": "2021-12-24"
        }
        normalized = parse_cisa_kev(item)
        self.assertEqual(normalized.cve_id, "CVE-2021-44228")
        self.assertTrue(normalized.is_in_kev)
        self.assertEqual(normalized.title, "Log4j RCE")
        self.assertIn("Apache", normalized.vendors)

if __name__ == '__main__':
    unittest.main()
