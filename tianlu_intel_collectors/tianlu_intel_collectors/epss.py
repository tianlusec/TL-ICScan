import requests
import gzip
import csv
import json
import sys
import io
from datetime import datetime, timezone
from .models import NormalizedCVE
from .utils import get_logger, measure_time
from . import config

logger = get_logger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
MAX_EPSS_SIZE = config.EPSS_MAX_SIZE  # Configurable limit for decompressed data

class LimitedReader(io.RawIOBase):
    def __init__(self, raw_stream, limit):
        self.raw_stream = raw_stream
        self.limit = limit
        self.bytes_read = 0

    def read(self, n=-1):
        chunk = self.raw_stream.read(n)
        if chunk:
            self.bytes_read += len(chunk)
            if self.bytes_read > self.limit:
                raise RuntimeError(f"EPSS data exceeded size limit of {self.limit} bytes")
        return chunk
        
    def readinto(self, b):
        n = self.raw_stream.readinto(b)
        if n:
            self.bytes_read += n
            if self.bytes_read > self.limit:
                raise RuntimeError(f"EPSS data exceeded size limit of {self.limit} bytes")
        return n

    def readable(self):
        return True

@measure_time
def fetch_epss_data():
    try:
        with requests.get(EPSS_URL, stream=True) as response:
            response.raise_for_status()
            
            # Wrap response.raw with size limiter
            limited_raw = LimitedReader(response.raw, MAX_EPSS_SIZE)
            
            with gzip.GzipFile(fileobj=limited_raw) as f:
                text_reader = io.TextIOWrapper(f, encoding='utf-8')
                
                reader = csv.reader(filter(lambda row: not row.startswith('#'), text_reader))
                headers = next(reader, None)
                
                if not headers:
                    return

                try:
                    cve_idx = headers.index('cve')
                    epss_idx = headers.index('epss')
                    percentile_idx = headers.index('percentile')
                except ValueError:
                    logger.error("Error: Unexpected CSV headers in EPSS data.")
                    return

                for row in reader:
                    if len(row) < 3:
                        continue
                    
                    cve_id = row[cve_idx]
                    try:
                        epss_score = float(row[epss_idx])
                        epss_percentile = float(row[percentile_idx])
                    except ValueError:
                        logger.warning(f"Skipping invalid EPSS data for {cve_id}")
                        continue

                    record = NormalizedCVE(
                        cve_id=cve_id,
                        epss_score=epss_score,
                        epss_percentile=epss_percentile,
                        extra={
                            "source": "epss",
                            "fetched_at": datetime.now(timezone.utc).isoformat()
                        }
                    )
                    
                    print(record.model_dump_json())

    except RuntimeError as e:
        if "exceeded size limit" in str(e):
             logger.error(f"Error: EPSS data too large: {e}")
        else:
             logger.error(f"RuntimeError fetching EPSS data: {e}")
    except Exception as e:
        logger.error(f"Error fetching EPSS data: {e}")

if __name__ == "__main__":
    fetch_epss_data()
