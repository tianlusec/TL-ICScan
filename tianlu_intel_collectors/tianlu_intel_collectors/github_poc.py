import requests
import json
import sys
import os
import re
import time
import argparse
from datetime import datetime, timedelta
from .utils import get_session
from typing import List, Dict, Any

GITHUB_API_URL = "https://api.github.com/search/repositories"

def get_github_headers():
    token = os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

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
    while True:
        if page > max_pages:
            sys.stderr.write("Aborting GitHub search: exceeded maximum pages.\n")
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
                reset_time = response.headers.get("X-RateLimit-Reset")
                if reset_time:
                    sleep_seconds = int(reset_time) - int(time.time()) + 5
                    if sleep_seconds > 0:
                        sys.stderr.write(f"Rate limit exceeded. Sleeping for {sleep_seconds} seconds...\n")
                        time.sleep(sleep_seconds)
                        continue

                sys.stderr.write("Error: GitHub API rate limit exceeded and no reset time found.\n")
                time.sleep(60)
                sys.stderr.write("Aborting search to prevent IP ban.\n")
                break

            response.raise_for_status()
            try:
                data = response.json()
            except Exception:
                sys.stderr.write("Error decoding GitHub response as JSON.\n")
                break

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                process_repo_item(item)

            page += 1
            if page > 10:
                break

            time.sleep(2.0)

        except Exception as e:
            sys.stderr.write(f"Error searching GitHub: {e}\n")
            time.sleep(5)

def extract_cve_ids(text: str) -> List[str]:
    """Extract CVE IDs from text using regex."""
    if not text:
        return []
    return re.findall(r'(CVE-\d{4}-\d{4,})', text, re.IGNORECASE | re.ASCII)

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
            sys.stderr.write(f"Invalid date format: {args.since}. Using 7d ago.\n")
            since_date = datetime.now() - timedelta(days=7)

    search_github_pocs(since_date, args.keywords)

if __name__ == "__main__":
    main()
