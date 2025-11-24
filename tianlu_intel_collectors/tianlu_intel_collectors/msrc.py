import argparse
import json
import sys
import requests
import xml.etree.ElementTree as ET
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
    
    # 1. Get list of updates
    try:
        resp = session.get(MSRC_API_UPDATES, timeout=30)
        resp.raise_for_status()
        updates = resp.json()
        
        # Filter updates
        target_update = None
        if month:
            # MSRC ID format is usually YYYY-MMM (e.g. 2024-Nov)
            # But the API returns a list of objects with "ID"
            for up in updates.get("value", []):
                if up.get("ID") == month:
                    target_update = up
                    break
            if not target_update:
                sys.stderr.write(f"Update for month {month} not found.\n")
                return
        else:
            # Get latest
            updates_list = updates.get("value", [])
            if not updates_list:
                sys.stderr.write("No updates found from MSRC.\n")
                return
            # Sort by Date? Or just take the first one? The list seems to be ordered or we can parse dates.
            # The ID is YYYY-MMM. Let's assume the first one is recent or sort.
            # Actually, let's just take the latest based on ID parsing or Date.
            # For simplicity, let's take the first one which is usually the latest in their response?
            # Let's sort by InitialReleaseDate
            updates_list.sort(key=lambda x: x.get("InitialReleaseDate", ""), reverse=True)
            target_update = updates_list[0]
            
        cvrf_url = target_update.get("CvrfUrl")
        if not cvrf_url:
            # Construct it
            cvrf_url = f"{MSRC_API_CVRF_BASE}/{target_update['ID']}"
            
        sys.stderr.write(f"Fetching MSRC CVRF from: {cvrf_url}\n")
        
        # 2. Fetch CVRF XML
        resp = session.get(cvrf_url, timeout=60)
        resp.raise_for_status()
        
        # Remove encoding declaration if present to avoid parsing issues with strings
        content = resp.text
        
        root = ET.fromstring(content)
        
        # Namespaces
        ns = {'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
              'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
              'prod': 'http://www.icasi.org/CVRF/schema/prod/1.1'}
        
        # Parse Vulnerabilities
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
    # Title
    title_elem = vuln.find('vuln:Title', ns)
    title = title_elem.text if title_elem is not None else None
    
    # CVE ID
    cve_elem = vuln.find('vuln:CVE', ns)
    cve_id = cve_elem.text if cve_elem is not None else None
    
    if not cve_id:
        return None
        
    # Description
    description = None
    notes = vuln.find('vuln:Notes', ns)
    if notes is not None:
        for note in notes.findall('vuln:Note', ns):
            if note.get('Type') == 'Description':
                description = note.text
                break
                
    # CVSS Score
    cvss_v3_score = None
    severity = None
    cvss_sets = vuln.find('vuln:CVSSScoreSets', ns)
    if cvss_sets is not None:
        # There might be multiple scores for different products. We'll take the max base score.
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
            
            # Map score to severity roughly if not provided
            if max_score >= 9.0: severity = "CRITICAL"
            elif max_score >= 7.0: severity = "HIGH"
            elif max_score >= 4.0: severity = "MEDIUM"
            else: severity = "LOW"

    # References
    references = []
    refs = vuln.find('vuln:References', ns)
    if refs is not None:
        for ref in refs.findall('vuln:Reference', ns):
            url_elem = ref.find('vuln:URL', ns)
            if url_elem is not None:
                references.append(url_elem.text)

    # Products (Affected)
    # This is complex in CVRF as it uses ProductID mapping. 
    # For simplicity in v0.3, we might skip detailed product mapping or just grab the ProductStatuses if easy.
    # But MSRC CVRF separates ProductTree and Vulnerability.
    # We'll leave products empty for now or try to fetch from a simplified view if possible.
    # Actually, let's just put "Microsoft Products" as a placeholder or try to parse.
    products = ["Microsoft Products"] 
    vendors = ["Microsoft"]

    # Publish Date (from Revision History usually, or the update date)
    # We can use the RevisionHistory of the Vulnerability
    publish_date = None
    rev_history = vuln.find('vuln:RevisionHistory', ns)
    if rev_history is not None:
        # Find the first revision
        revisions = rev_history.findall('vuln:Revision', ns)
        if revisions:
            # Sort by date?
            first_rev = revisions[0] # Usually the first one listed is the first? Or check Date.
            date_elem = first_rev.find('vuln:Date', ns)
            if date_elem is not None:
                try:
                    # Format: 2024-11-12T00:00:00
                    publish_date = datetime.fromisoformat(date_elem.text)
                except:
                    pass

    # Exploit Status
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

    extra = {"msrc_raw": "omitted_xml"} # XML is too verbose to dump in JSON usually

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
