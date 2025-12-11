import argparse
import json
import sys
import time
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import NormalizedCVE
from .utils import get_session, get_logger, measure_time
from . import config
import re

logger = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

@measure_time
def fetch_nvd_cves(since: Optional[str] = None, api_key: Optional[str] = None, cve_id: Optional[str] = None):
    """
    Fetch CVEs from NVD API.

    Args:
        since (Optional[str]): Start date for fetching CVEs. Can be an ISO format date string or relative days (e.g., '7d').
        api_key (Optional[str]): NVD API Key. If not provided, tries to load from NVD_API_KEY env var.
        cve_id (Optional[str]): Specific CVE ID to fetch. If provided, 'since' is ignored.
    """
    session = get_session()
    
    final_api_key = api_key or os.environ.get("NVD_API_KEY")
    
    if final_api_key:
        session.headers.update({"apiKey": final_api_key})
        sleep_time = 0.6
    else:
        logger.warning("No NVD API Key provided (via arg or NVD_API_KEY env var). Using strict rate limits.")
        sleep_time = 6.0

    if cve_id:
        logger.info(f"Fetching specific CVE: {cve_id}...")
        fetch_nvd_single(session, cve_id, sleep_time)
        return

    start_date = datetime.now(timezone.utc) - timedelta(days=7)
    state_file = "nvd_state.json"

    if since:
        if since.endswith('d'):
            try:
                days = int(since[:-1])
                start_date = datetime.now(timezone.utc) - timedelta(days=days)
            except ValueError:
                sys.stderr.write(f"Invalid relative date format: {since}\n")
                return
        else:
            try:
                start_date = datetime.fromisoformat(since)
            except ValueError:
                sys.stderr.write(f"Invalid date format: {since}\n")
                return
    elif os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                if "last_success" in state:
                    start_date = datetime.fromisoformat(state["last_success"])
                    logger.info(f"Resuming from checkpoint: {start_date}")
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")

    end_date = datetime.now(timezone.utc)
    
    CHUNK_DAYS = config.NVD_CHUNK_DAYS
    current_start = start_date
    while current_start < end_date:
        current_end = current_start + timedelta(days=CHUNK_DAYS)
        if current_end > end_date:
            current_end = end_date
            
        logger.info(f"Fetching NVD data from {current_start.date()} to {current_end.date()}...")
        try:
            fetch_nvd_chunk(session, current_start, current_end, sleep_time)
            with open(state_file, 'w') as f:
                json.dump({"last_success": current_end.isoformat()}, f)
        except Exception as e:
            logger.error(f"Error in chunk {current_start} - {current_end}: {e}")
            raise
        
        current_start = current_end

def fetch_nvd_single(session, cve_id, sleep_time):
    """
    Fetch a single CVE from NVD API.

    Args:
        session (requests.Session): HTTP session to use for requests.
        cve_id (str): The CVE ID to fetch.
        sleep_time (float): Time to sleep between requests to respect rate limits.
    """
    params = {
        "cveId": cve_id
    }
    
    for attempt in range(3):
        try:
            response = session.get(NVD_API_URL, params=params, timeout=30)
            
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                logger.warning(f"NVD API Rate Limit (429). Sleeping for {retry_after} seconds.")
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                try:
                    normalized = parse_nvd_cve(cve_item)
                    print(normalized.model_dump_json())
                except Exception as e:
                    logger.error(f"Error parsing CVE: {e}")
            
            time.sleep(sleep_time)
            return

        except Exception as e:
            logger.error(f"Error fetching NVD data (attempt {attempt+1}/3): {e}")
            time.sleep(sleep_time * (attempt + 1))
    
    logger.error(f"Failed to fetch NVD data for {cve_id} after 3 attempts.")

def fetch_nvd_chunk(session, start_dt, end_dt, sleep_time):
    """
    Fetch a chunk of CVEs from NVD API based on publication date range.

    Args:
        session (requests.Session): HTTP session.
        start_dt (datetime): Start datetime.
        end_dt (datetime): End datetime.
        sleep_time (float): Sleep time between requests.
    """
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_dt.isoformat(),
        "pubEndDate": end_dt.isoformat()
    }

    loop_count = 0
    MAX_PAGES = config.NVD_MAX_PAGES

    while True:
        loop_count += 1
        if loop_count > MAX_PAGES:
            logger.error("NVD fetch aborted: exceeded max page iterations.")
            break

        success = False
        for attempt in range(3):
            try:
                response = session.get(NVD_API_URL, params=params, timeout=30)
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 30))
                    logger.warning(f"NVD API Rate Limit (429). Sleeping for {retry_after} seconds.")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                data = response.json()
                success = True
                break
            except Exception as e:
                logger.error(f"Error fetching NVD data (attempt {attempt+1}/3): {e}")
                time.sleep(sleep_time * (attempt + 1) * 2)

        if not success:
            logger.error(f"Failed to fetch chunk starting at {params['startIndex']} after 3 attempts. Aborting to prevent data gap.")
            raise RuntimeError(f"NVD fetch failed for chunk {start_dt} - {end_dt}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning(f"Warning: Received empty vulnerabilities list at index {params['startIndex']}. Stopping chunk fetch.")
            break

        for item in vulnerabilities:
            cve_item = item.get("cve", {})
            try:
                normalized = parse_nvd_cve(cve_item)
                if normalized:
                    if re.match(r'^CVE-\d{4}-\d{4,}$', normalized.cve_id or ''):
                        print(normalized.model_dump_json())
                    else:
                        logger.warning(f"Skipping invalid CVE id: {normalized.cve_id}")
            except Exception as e:
                logger.error(f"Error parsing CVE: {e}")

        total_results = data.get("totalResults", 0)
        start_index = data.get("startIndex", 0)
        items_count = len(vulnerabilities)

        if items_count == 0:
             break

        if total_results and start_index + items_count >= total_results:
            break

        params["startIndex"] += items_count
        time.sleep(sleep_time)

def parse_nvd_cve(cve: dict) -> NormalizedCVE:
    """
    Parse a raw NVD CVE dictionary into a NormalizedCVE object.

    Args:
        cve (dict): The raw CVE dictionary from NVD API.

    Returns:
        NormalizedCVE: The normalized CVE object.
    """
    cve_id = cve.get("id")
    
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
    
    metrics = cve.get("metrics", {})
    cvss_v3_score = None
    severity = None
    
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
        
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                val = desc.get("value")
                if val and val.startswith("CWE-"):
                    cwe_ids.append(val)
    
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    
    def parse_dt(dt_str):
        if not dt_str: return None
        try:
            dt = datetime.fromisoformat(dt_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError as e:
            logger.warning(f"Warning: Failed to parse date '{dt_str}': {e}")
            return None

    publish_date = parse_dt(published)
    update_date = parse_dt(last_modified)
    
    references = [ref.get("url") for ref in cve.get("references", [])]
    
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

    extra = {"nvd_raw": cve}
    
    return NormalizedCVE(
        cve_id=cve_id,
        title=cve_id,
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
        cwe_ids=cwe_ids,
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        confidentiality_impact=confidentiality_impact,
        integrity_impact=integrity_impact,
        availability_impact=availability_impact,
        is_in_kev=False,
        exploit_exists=exploit_exists,
        poc_sources=poc_sources,
        poc_risk_label=poc_risk_label,
        feed_version=datetime.now(timezone.utc).isoformat()
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", help="Start date (ISO 8601), e.g. 2025-11-01")
    parser.add_argument("--api-key", help="NVD API Key")
    parser.add_argument("--cve-id", help="Specific CVE ID to fetch")
    args = parser.parse_args()
    
    if args.cve_id:
        fetch_nvd_cves(cve_id=args.cve_id, api_key=args.api_key)
    else:
        since = args.since
        if not since:
            since = (datetime.now() - timedelta(days=7)).date().isoformat()
            
        fetch_nvd_cves(since=since, api_key=args.api_key)
