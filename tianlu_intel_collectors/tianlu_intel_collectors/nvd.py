import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

from .models import NormalizedCVE
from .utils import get_session

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_cves(since: Optional[str] = None, api_key: Optional[str] = None):
    session = get_session()
    if api_key:
        session.headers.update({"apiKey": api_key})
        sleep_time = 0.6  # With API key: 50 req / 30 sec ~= 0.6s
    else:
        sleep_time = 6.0  # Without API key: 5 req / 30 sec = 6s

    start_date = datetime.now() - timedelta(days=7)
    if since:
        try:
            start_date = datetime.fromisoformat(since)
        except ValueError:
            sys.stderr.write(f"Invalid date format: {since}\n")
            return

    end_date = datetime.now()
    
    # NVD API limits time range to 120 days. We split larger ranges into chunks.
    current_start = start_date
    while current_start < end_date:
        current_end = current_start + timedelta(days=120)
        if current_end > end_date:
            current_end = end_date
            
        sys.stderr.write(f"Fetching NVD data from {current_start.date()} to {current_end.date()}...\n")
        fetch_nvd_chunk(session, current_start, current_end, sleep_time)
        
        current_start = current_end

def fetch_nvd_chunk(session, start_dt, end_dt, sleep_time):
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_dt.isoformat(),
        "pubEndDate": end_dt.isoformat()
    }

    while True:
        try:
            response = session.get(NVD_API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                try:
                    normalized = parse_nvd_cve(cve_item)
                    print(normalized.model_dump_json())
                except Exception as e:
                    sys.stderr.write(f"Error parsing CVE: {e}\n")
            
            total_results = data.get("totalResults", 0)
            start_index = data.get("startIndex", 0)
            results_per_page = data.get("resultsPerPage", 0)
            
            if start_index + results_per_page >= total_results:
                break
                
            params["startIndex"] += results_per_page
            time.sleep(sleep_time) 
            
        except Exception as e:
            sys.stderr.write(f"Error fetching NVD data: {e}\n")
            break

def parse_nvd_cve(cve: dict) -> NormalizedCVE:
    cve_id = cve.get("id")
    
    # Descriptions
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
    
    # Metrics
    metrics = cve.get("metrics", {})
    cvss_v3_score = None
    severity = None
    
    # v0.2 Fields
    attack_vector = None
    privileges_required = None
    user_interaction = None
    confidentiality_impact = None
    integrity_impact = None
    availability_impact = None

    cvss_metric = None
    if "cvssMetricV31" in metrics:
        cvss_metric = metrics["cvssMetricV31"][0]["cvssData"]
    elif "cvssMetricV30" in metrics:
        cvss_metric = metrics["cvssMetricV30"][0]["cvssData"]
    
    if cvss_metric:
        cvss_v3_score = cvss_metric.get("baseScore")
        severity = cvss_metric.get("baseSeverity")
        attack_vector = cvss_metric.get("attackVector")
        privileges_required = cvss_metric.get("privilegesRequired")
        user_interaction = cvss_metric.get("userInteraction")
        confidentiality_impact = cvss_metric.get("confidentialityImpact")
        integrity_impact = cvss_metric.get("integrityImpact")
        availability_impact = cvss_metric.get("availabilityImpact")
        
    cvss_v2_score = None
    if "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_v2_score = cvss_data.get("baseScore")
        
    # CWEs
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                val = desc.get("value")
                if val and val.startswith("CWE-"):
                    cwe_ids.append(val)
    
    # Dates
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    
    publish_date = datetime.fromisoformat(published) if published else None
    update_date = datetime.fromisoformat(last_modified) if last_modified else None
    
    # References
    references = [ref.get("url") for ref in cve.get("references", [])]
    
    # Vendors/Products
    vendors = set()
    products = set()
    
    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria")
                if criteria:
                    # Parse CPE 2.3 string
                    # cpe:2.3:part:vendor:product:version:...
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor and vendor != "*":
                            vendors.add(vendor)
                        if product and product != "*":
                            products.add(product)
    
    vendors = list(vendors)
    products = list(products)
    
    # v0.5 PoC Extraction
    poc_sources = []
    exploit_exists = False
    
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        url = ref.get("url", "")
        if "Exploit" in tags:
            exploit_exists = True
            if "exploit-db" in url:
                poc_sources.append("exploit-db")
            elif "github" in url:
                poc_sources.append("github")
            elif "packetstorm" in url:
                poc_sources.append("packetstorm")
            else:
                poc_sources.append("other_nvd_ref")
    
    poc_sources = list(set(poc_sources)) if poc_sources else None
    poc_risk_label = "unknown" if exploit_exists else None

    # Extra
    extra = {"nvd_raw": cve}
    
    return NormalizedCVE(
        cve_id=cve_id,
        title=cve_id, # NVD doesn't have a separate title usually
        description=description,
        severity=severity,
        cvss_v2_score=cvss_v2_score,
        cvss_v3_score=cvss_v3_score,
        publish_date=publish_date,
        update_date=update_date,
        vendors=vendors,
        products=products,
        references=references,
        extra=extra,
        # v0.2 Fields
        cwe_ids=cwe_ids,
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        confidentiality_impact=confidentiality_impact,
        integrity_impact=integrity_impact,
        availability_impact=availability_impact,
        is_in_kev=False, # NVD doesn't explicitly say this, we rely on CISA collector or merge logic
        exploit_exists=exploit_exists,
        # v0.5 Fields
        poc_sources=poc_sources,
        poc_risk_label=poc_risk_label,
        feed_version=datetime.now().isoformat()
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", help="Start date (ISO 8601), e.g. 2025-11-01")
    parser.add_argument("--api-key", help="NVD API Key")
    args = parser.parse_args()
    
    since = args.since
    if not since:
        # Default to 7 days ago
        since = (datetime.now() - timedelta(days=7)).date().isoformat()
        
    fetch_nvd_cves(since, args.api_key)
