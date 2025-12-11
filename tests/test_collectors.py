import unittest
import os
import sys
import json
import io
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tianlu_intel_collectors')))

from tianlu_intel_collectors.epss import fetch_epss_data
from tianlu_intel_collectors.exploit_db import fetch_exploit_db
from tianlu_intel_collectors.github_poc import search_github_pocs
from tianlu_intel_collectors.msrc import fetch_msrc_cves
from tianlu_intel_collectors.models import NormalizedCVE

class TestEPSS(unittest.TestCase):
    @patch('requests.get')
    def test_fetch_epss_data(self, mock_get):
        # Mock response content (gzipped csv)
        import gzip
        import io
        
        csv_content = "cve,epss,percentile\nCVE-2023-1234,0.95,0.99\n"
        compressed_content = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_content, mode='wb') as f:
            f.write(csv_content.encode('utf-8'))
        
        mock_response = MagicMock()
        mock_response.raw = io.BytesIO(compressed_content.getvalue())
        mock_response.raw.read = io.BytesIO(compressed_content.getvalue()).read
        mock_response.raw.readinto = io.BytesIO(compressed_content.getvalue()).readinto
        mock_get.return_value.__enter__.return_value = mock_response
        
        # Capture stdout
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            fetch_epss_data()
        finally:
            sys.stdout = sys.__stdout__
            
        output = captured_output.getvalue()
        self.assertIn("CVE-2023-1234", output)
        self.assertIn("0.95", output)

class TestExploitDB(unittest.TestCase):
    @patch('tianlu_intel_collectors.exploit_db.get_session')
    def test_fetch_exploit_db(self, mock_get_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        # Mock raw response for codecs.getreader
        # Columns: id, file, description, date, author, type, platform, port, date_added, date_updated, verified, codes
        csv_data = b"id,file,description,date,author,type,platform,port,d1,d2,verified,codes\n12345,file.py,Test Exploit,2023-01-01,Author,remote,linux,80,2023-01-01,2023-01-01,1,CVE-2023-1234\n"
        mock_response.raw = io.BytesIO(csv_data)
        mock_session.get.return_value.__enter__.return_value = mock_response
        mock_get_session.return_value = mock_session
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            fetch_exploit_db()
        finally:
            sys.stdout = sys.__stdout__
            
        output = captured_output.getvalue()
        self.assertIn("Test Exploit", output)
        self.assertIn("12345", output)

class TestGitHubPoC(unittest.TestCase):
    @patch('tianlu_intel_collectors.github_poc.get_session')
    def test_search_github_pocs(self, mock_get_session):
        mock_session = MagicMock()
        mock_response_1 = MagicMock()
        mock_response_1.json.return_value = {
            "total_count": 1,
            "items": [{
                "name": "CVE-2023-1234-PoC",
                "html_url": "https://github.com/user/CVE-2023-1234-PoC",
                "description": "PoC for CVE-2023-1234",
                "stargazers_count": 10,
                "updated_at": "2023-01-01T00:00:00Z"
            }]
        }
        mock_response_1.links = {}
        mock_response_1.status_code = 200

        mock_response_2 = MagicMock()
        mock_response_2.json.return_value = {
            "total_count": 1,
            "items": []
        }
        mock_response_2.links = {}
        mock_response_2.status_code = 200
        
        mock_session.get.side_effect = [mock_response_1, mock_response_2]
        mock_get_session.return_value = mock_session
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            search_github_pocs(since_date=datetime(2023, 1, 1))
        finally:
            sys.stdout = sys.__stdout__
            
        output = captured_output.getvalue()
        self.assertIn("CVE-2023-1234-PoC", output)

class TestMSRC(unittest.TestCase):
    @patch('tianlu_intel_collectors.msrc.get_session')
    def test_fetch_msrc_cves(self, mock_get_session):
        mock_session = MagicMock()
        
        # Mock updates response
        mock_updates_response = MagicMock()
        mock_updates_response.json.return_value = {
            "value": [{
                "ID": "2023-Jan",
                "CurrentReleaseDate": "2023-01-10T00:00:00Z",
                "CvrfUrl": "http://test.url/cvrf"
            }]
        }
        
        # Mock CVRF response
        mock_cvrf_response = MagicMock()
        cvrf_xml = """
        <cvrf:cvrfdoc xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1" xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1">
            <vuln:Vulnerability>
                <vuln:CVE>CVE-2023-9999</vuln:CVE>
                <vuln:Title>Test Vulnerability</vuln:Title>
                <vuln:Notes>
                    <vuln:Note Type="Description" Ordinal="1">Test Description</vuln:Note>
                </vuln:Notes>
            </vuln:Vulnerability>
        </cvrf:cvrfdoc>
        """
        mock_cvrf_response.content = cvrf_xml.encode('utf-8')
        mock_cvrf_response.text = cvrf_xml
        
        mock_session.get.side_effect = [mock_updates_response, mock_cvrf_response]
        mock_get_session.return_value = mock_session
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            fetch_msrc_cves(month="2023-Jan")
        finally:
            sys.stdout = sys.__stdout__
            
        output = captured_output.getvalue()
        self.assertIn("CVE-2023-9999", output)

if __name__ == '__main__':
    unittest.main()
