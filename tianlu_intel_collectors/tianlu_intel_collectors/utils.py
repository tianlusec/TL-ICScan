import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import certifi

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        """Create and initialize the urllib3 PoolManager."""
        ctx = ssl.create_default_context()
        try:
            ctx.load_verify_locations(certifi.where())
        except Exception:
            pass
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self._pool_kwargs = {}
        
        super(TLSAdapter, self).init_poolmanager(connections, maxsize, block, ssl_context=ctx)

def get_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = TLSAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
