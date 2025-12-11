import os

# NVD Settings
NVD_CHUNK_DAYS = int(os.getenv("NVD_CHUNK_DAYS", 120))
NVD_MAX_PAGES = int(os.getenv("NVD_MAX_PAGES", 250))

# EPSS Settings
EPSS_MAX_SIZE = int(os.getenv("EPSS_MAX_SIZE", 500 * 1024 * 1024))
