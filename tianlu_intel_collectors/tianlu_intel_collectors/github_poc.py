import requests
import json
import sys
import os
import re
import time
import argparse
from datetime import datetime, timedelta
from .utils import get_session, get_logger, measure_time
from typing import List, Dict, Any

logger = get_logger(__name__)

GITHUB_API_URL = "https://api.github.com/search/repositories"

def get_github_headers():
    token = os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

@measure_time
def search_github_pocs(since_date: datetime, keywords: List[str] = None):
    """
    Search GitHub for repositories related to CVEs.
    """
    if not keywords:
        keywords = ["CVE"]

    date_str = since_date.strftime("%Y-%m-%d")
    
    query_parts = [f"pushed:>{date_str}"]
    
    if keywords:
        keyword_query = " OR ".join(keywords)
        query_parts.append(f"({keyword_query})")
    
    query = " ".join(query_parts)
    
    session = get_session()
    page = 1
    max_pages = 50
    consecutive_errors = 0
    MAX_RETRIES = 5

    while True:
        if page > max_pages:
            logger.warning("Aborting GitHub search: exceeded maximum pages.")
            break

        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 100,
            "page": page
        }

        try:
            response = session.get(GITHUB_API_URL, headers=get_github_headers(), params=params, timeout=30)

            if response.status_code == 403:
                consecutive_errors += 1
                if consecutive_errors > MAX_RETRIES:
                    logger.error("Max retries exceeded for GitHub API 403.")
                    break

                reset_time = response.headers.get("X-RateLimit-Reset")
                if reset_time:
                    sleep_seconds = int(reset_time) - int(time.time()) + 5
                    if sleep_seconds > 0:
                        logger.warning(f"Rate limit exceeded. Sleeping for {sleep_seconds} seconds...")
                        time.sleep(sleep_seconds)
                        continue

                logger.error("Error: GitHub API rate limit exceeded and no reset time found.")
                time.sleep(300)
                logger.info("Retrying after 5 minutes wait...")
                continue
            
            consecutive_errors = 0
            response.raise_for_status()
            try:
                data = response.json()
            except Exception:
                logger.error("Error decoding GitHub response as JSON.")
                break

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                process_repo_item(item)

            page += 1

            time.sleep(2.0)

        except Exception as e:
            logger.error(f"Error searching GitHub: {e}")
            time.sleep(5)

CVE_PATTERN = re.compile(r'(CVE-\d{4}-\d{4,})', re.IGNORECASE | re.ASCII)

def extract_cve_ids(text: str) -> List[str]:
    """Extract CVE IDs from text using regex and validate year."""
    if not text:
        return []
    
    candidates = CVE_PATTERN.findall(text)
    valid_cves = []
    
    current_year = datetime.now().year
    
    for cve in candidates:
        parts = cve.split('-')
        if len(parts) >= 2:
            try:
                year = int(parts[1])
                # Validate year range (1999 to current year)
                if 1999 <= year <= current_year:
                    valid_cves.append(cve)
            except ValueError:
                continue
                
    return valid_cves

def process_repo_item(item: Dict[str, Any]):
    """
    Process a single GitHub repository item and print NormalizedCVE JSONL.
    """
    name = item.get("name", "")
    description = item.get("description", "") or ""
    html_url = item.get("html_url", "")
    pushed_at = item.get("pushed_at", "")
    stargazers_count = item.get("stargazers_count", 0)
    forks_count = item.get("forks_count", 0)
    
    cve_ids = set(extract_cve_ids(name) + extract_cve_ids(description))
    
    if not cve_ids:
        return

    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        
        record = {
            "cve_id": cve_id,
            "exploit_exists": True,
            "poc_sources": [html_url],
            "extra": {
                "source": "github_poc",
                "github_repo": {
                    "name": item.get("full_name"),
                    "url": html_url,
                    "description": description,
                    "stars": stargazers_count,
                    "forks": forks_count,
                    "updated_at": pushed_at
                }
            }
        }
        
        print(json.dumps(record))

def main():
    parser = argparse.ArgumentParser(description="Collect CVE PoC information from GitHub")
    parser.add_argument("--since", help="Filter by date (YYYY-MM-DD) or relative (e.g. 7d)", default="7d")
    parser.add_argument("--keywords", nargs="+", help="Additional keywords to search")
    
    args = parser.parse_args()
    
    since_date = datetime.now()
    if args.since.endswith("d"):
        days = int(args.since[:-1])
        since_date = datetime.now() - timedelta(days=days)
    else:
        try:
            since_date = datetime.strptime(args.since, "%Y-%m-%d")
        except ValueError:
            logger.warning(f"Invalid date format: {args.since}. Using 7d ago.")
            since_date = datetime.now() - timedelta(days=7)

    search_github_pocs(since_date, args.keywords)

if __name__ == "__main__":
    main()
