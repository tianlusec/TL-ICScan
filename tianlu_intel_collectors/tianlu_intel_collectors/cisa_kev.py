import argparse
import json
import sys
from datetime import datetime

from .models import NormalizedCVE
from .utils import get_session

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    session = get_session()
    try:
        response = session.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            try:
                normalized = parse_cisa_kev(item)
                print(normalized.model_dump_json())
            except Exception as e:
                sys.stderr.write(f"Error parsing CISA KEV item: {e}\n")
                
    except Exception as e:
        sys.stderr.write(f"Error fetching CISA KEV data: {e}\n")

def parse_cisa_kev(item: dict) -> NormalizedCVE:
    cve_id = item.get("cveID")
    
    # Dates in CISA are usually YYYY-MM-DD
    date_added = item.get("dateAdded")
    publish_date = None
    if date_added:
        try:
            publish_date = datetime.strptime(date_added, "%Y-%m-%d")
        except ValueError:
            pass
            
    description = item.get("shortDescription")
    title = item.get("vulnerabilityName")
    
    vendor = item.get("vendorProject")
    product = item.get("product")
    
    vendors = [vendor] if vendor else []
    products = [product] if product else []
    
    # CISA doesn't provide CVSS or Severity directly in this feed usually, 
    # but we can leave them None.
    
    extra = {"cisa_kev_raw": item}
    
    return NormalizedCVE(
        cve_id=cve_id,
        title=title,
        description=description,
        publish_date=publish_date,
        vendors=vendors,
        products=products,
        extra=extra,
        is_in_kev=True,
        exploit_exists=True,
        poc_risk_label="trusted",
        feed_version=datetime.now().isoformat()
    )

if __name__ == "__main__":
    fetch_cisa_kev()
