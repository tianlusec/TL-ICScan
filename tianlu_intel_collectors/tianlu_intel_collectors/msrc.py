import argparse
import json
import sys
import requests
import xml.etree.ElementTree as ET
try:
    from defusedxml import ElementTree as DefusedET
    _DEFUSEDXML_AVAILABLE = True
except Exception:
    DefusedET = None
    _DEFUSEDXML_AVAILABLE = False
from datetime import datetime
from typing import Optional, List, Dict

from .models import NormalizedCVE
from .utils import get_session

MSRC_API_UPDATES = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
MSRC_API_CVRF_BASE = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf"

def fetch_msrc_cves(month: Optional[str] = None):
    """
    Fetch MSRC CVEs.
    month: YYYY-MMM format (e.g. 2025-Nov) or None for latest.
    """
    session = get_session()
    
    try:
        resp = session.get(MSRC_API_UPDATES, timeout=30)
        resp.raise_for_status()
        updates = resp.json()
        
        target_update = None
        if month:
            for up in updates.get("value", []):
                if up.get("ID") == month:
                    target_update = up
                    break
            if not target_update:
                sys.stderr.write(f"Update for month {month} not found.\n")
                return
        else:
            updates_list = updates.get("value", [])
            if not updates_list:
                sys.stderr.write("No updates found from MSRC.\n")
                return
            updates_list.sort(key=lambda x: x.get("InitialReleaseDate", ""), reverse=True)
            target_update = updates_list[0]
            
        cvrf_url = target_update.get("CvrfUrl")
        if not cvrf_url:
            cvrf_url = f"{MSRC_API_CVRF_BASE}/{target_update['ID']}"
            
        sys.stderr.write(f"Fetching MSRC CVRF from: {cvrf_url}\n")
        
        resp = session.get(cvrf_url, timeout=60)
        resp.raise_for_status()

        MAX_BYTES = 50 * 1024 * 1024
        content_length = resp.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_BYTES:
                    sys.stderr.write("MSRC CVRF too large, rejecting to avoid OOM.\n")
                    return
            except Exception:
                pass

        content = resp.text
        if len(content.encode('utf-8')) > MAX_BYTES:
            sys.stderr.write("MSRC CVRF content exceeds size limit, rejecting.\n")
            return
        
        if not _DEFUSEDXML_AVAILABLE:
            if "<!DOCTYPE" in content or "<!ENTITY" in content:
                 sys.stderr.write("Security Warning: MSRC response contains DOCTYPE/ENTITY, rejecting to prevent XXE.\n")
                 return

        if _DEFUSEDXML_AVAILABLE:
            try:
                root = DefusedET.fromstring(content)
            except Exception as e:
                sys.stderr.write(f"Error parsing MSRC XML (defusedxml): {e}\n")
                return
        else:
            try:
                root = ET.fromstring(content)
            except Exception as e:
                sys.stderr.write(f"Error parsing MSRC XML: {e}\n")
                return
        
        ns = {'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
              'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
              'prod': 'http://www.icasi.org/CVRF/schema/prod/1.1'}
        
        for vuln in root.findall('.//vuln:Vulnerability', ns):
            try:
                normalized = parse_msrc_vuln(vuln, ns)
                if normalized:
                    print(normalized.model_dump_json())
            except Exception as e:
                sys.stderr.write(f"Error parsing MSRC vuln: {e}\n")
                
    except Exception as e:
        sys.stderr.write(f"Error fetching MSRC data: {e}\n")

def parse_msrc_vuln(vuln: ET.Element, ns: Dict) -> Optional[NormalizedCVE]:
    title_elem = vuln.find('vuln:Title', ns)
    title = title_elem.text if title_elem is not None else None
    
    cve_elem = vuln.find('vuln:CVE', ns)
    cve_id = cve_elem.text if cve_elem is not None else None
    
    if not cve_id:
        return None
        
    description = None
    notes = vuln.find('vuln:Notes', ns)
    if notes is not None:
        for note in notes.findall('vuln:Note', ns):
            if note.get('Type') == 'Description':
                description = note.text
                break
                
    cvss_v3_score = None
    severity = None
    cvss_sets = vuln.find('vuln:CVSSScoreSets', ns)
    if cvss_sets is not None:
        max_score = 0.0
        for score_set in cvss_sets.findall('vuln:ScoreSet', ns):
            base_score_elem = score_set.find('vuln:BaseScore', ns)
            if base_score_elem is not None:
                try:
                    score = float(base_score_elem.text)
                    if score > max_score:
                        max_score = score
                except:
                    pass
        if max_score > 0:
            cvss_v3_score = max_score
            
            if max_score >= 9.0: severity = "CRITICAL"
            elif max_score >= 7.0: severity = "HIGH"
            elif max_score >= 4.0: severity = "MEDIUM"
            else: severity = "LOW"

    references = []
    refs = vuln.find('vuln:References', ns)
    if refs is not None:
        for ref in refs.findall('vuln:Reference', ns):
            url_elem = ref.find('vuln:URL', ns)
            if url_elem is not None:
                references.append(url_elem.text)

    products = ["Microsoft Products"] 
    vendors = ["Microsoft"]

    publish_date = None
    rev_history = vuln.find('vuln:RevisionHistory', ns)
    if rev_history is not None:
        revisions = rev_history.findall('vuln:Revision', ns)
        if revisions:
            first_rev = revisions[0]
            date_elem = first_rev.find('vuln:Date', ns)
            if date_elem is not None:
                try:
                    publish_date = datetime.fromisoformat(date_elem.text)
                except:
                    pass

    exploit_exists = False
    threats = vuln.find('vuln:Threats', ns)
    if threats is not None:
        for threat in threats.findall('vuln:Threat', ns):
            if threat.get('Type') == 'Exploit Status':
                desc = threat.find('vuln:Description', ns)
                if desc is not None and "Exploited:Yes" in desc.text:
                    exploit_exists = True
                    break
    
    poc_risk_label = "trusted" if exploit_exists else None

    extra = {"msrc_raw": "omitted_xml"}

    return NormalizedCVE(
        cve_id=cve_id,
        title=title,
        description=description,
        severity=severity,
        cvss_v3_score=cvss_v3_score,
        publish_date=publish_date,
        vendors=vendors,
        products=products,
        references=references,
        extra=extra,
        exploit_exists=exploit_exists,
        poc_risk_label=poc_risk_label,
        feed_version=datetime.now().isoformat()
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--month", help="Month ID (e.g. 2025-Nov)")
    args = parser.parse_args()
    
    fetch_msrc_cves(args.month)
