import requests
import gzip
import csv
import json
import sys
import io
from datetime import datetime

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

def fetch_epss_data():
    try:
        response = requests.get(EPSS_URL, stream=True)
        response.raise_for_status()
        
        # Decompress gzip content
        with gzip.open(io.BytesIO(response.content), 'rt') as f:
            # Skip comments (lines starting with #)
            # The file usually has 1 header line: cve,epss,percentile
            # But sometimes metadata lines start with #
            
            reader = csv.reader(filter(lambda row: not row.startswith('#'), f))
            headers = next(reader, None)
            
            if not headers:
                return

            # Map headers to indices
            try:
                cve_idx = headers.index('cve')
                epss_idx = headers.index('epss')
                percentile_idx = headers.index('percentile')
            except ValueError:
                sys.stderr.write("Error: Unexpected CSV headers in EPSS data.\n")
                return

            for row in reader:
                if len(row) < 3:
                    continue
                
                cve_id = row[cve_idx]
                epss_score = float(row[epss_idx])
                epss_percentile = float(row[percentile_idx])

                record = {
                    "cve_id": cve_id,
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "extra": {
                        "source": "epss",
                        "fetched_at": datetime.now().isoformat()
                    }
                }
                
                print(json.dumps(record))

    except Exception as e:
        sys.stderr.write(f"Error fetching EPSS data: {e}\n")

if __name__ == "__main__":
    fetch_epss_data()
