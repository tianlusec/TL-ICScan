import argparse
import json
import sys
import ijson
from datetime import datetime, timezone

from .models import NormalizedCVE
from .utils import get_session, get_logger, measure_time

logger = get_logger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@measure_time
def fetch_cisa_kev():
    """
    Fetch Known Exploited Vulnerabilities from CISA.
    """
    session = get_session()
    try:
        response = session.get(CISA_KEV_URL, timeout=30, stream=True)
        response.raise_for_status()
        
        f = response.raw
        f.decode_content = True
        
        vulnerabilities = ijson.items(f, 'vulnerabilities.item')
        
        for item in vulnerabilities:
            try:
                normalized = parse_cisa_kev(item)
                print(normalized.model_dump_json())
            except Exception as e:
                logger.error(f"Error parsing CISA KEV item: {e}")
                
    except Exception as e:
        logger.error(f"Error fetching CISA KEV data: {e}")

def parse_cisa_kev(item: dict) -> NormalizedCVE:
    """
    Parse a CISA KEV item into a NormalizedCVE object.

    Args:
        item (dict): The raw item from CISA KEV JSON.

    Returns:
        NormalizedCVE: The normalized CVE object.
    """
    cve_id = item.get("cveID")
    
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
        feed_version=datetime.now(timezone.utc).isoformat()
    )

if __name__ == "__main__":
    fetch_cisa_kev()
