import requests
import json
import sys
import os
import re
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any

# GitHub API URL
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
        # Default to searching for generic CVE pattern if no specific keywords
        # We search for repositories created or updated recently containing "CVE"
        keywords = ["CVE"]

    # Format date for GitHub query
    date_str = since_date.strftime("%Y-%m-%d")
    
    # Construct query
    # We want repos that mention CVE and were pushed recently
    query_parts = [f"pushed:>{date_str}"]
    
    # Join keywords with OR is not directly supported in the same way as simple text, 
    # but we can just search for "CVE" generally.
    # A better approach for a broad monitor is just "CVE" in name/desc
    query_parts.append("CVE")
    
    query = " ".join(query_parts)
    
    page = 1
    while True:
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 100,  # Max per page
            "page": page
        }

        try:
            response = requests.get(GITHUB_API_URL, headers=get_github_headers(), params=params)
            
            if response.status_code == 403:
                # Rate limit hit
                sys.stderr.write("Error: GitHub API rate limit exceeded. Please set GITHUB_TOKEN environment variable.\n")
                return
                
            response.raise_for_status()
            data = response.json()
            
            items = data.get("items", [])
            if not items:
                break
            
            for item in items:
                process_repo_item(item)
            
            page += 1
            # GitHub Search API limits to 1000 results (10 pages)
            if page > 10:
                break
                
        except Exception as e:
            sys.stderr.write(f"Error searching GitHub: {e}\n")
            break

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
    
    # Try to find CVE ID in name or description
    cve_ids = set(extract_cve_ids(name) + extract_cve_ids(description))
    
    if not cve_ids:
        # If no CVE ID found, we might skip or output with a placeholder if we want to track "potential" PoCs
        # For now, let's skip to keep noise down
        return

    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        
        # Construct NormalizedCVE object
        # Note: We might generate multiple records for the same repo if it mentions multiple CVEs
        
        record = {
            "cve_id": cve_id,
            # We don't overwrite title/desc from official sources usually, 
            # but if this is a new CVE, this might be useful.
            # However, the aggregator logic usually merges.
            # Let's put the repo info in extra and poc_sources
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
    
    # Parse since argument
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
