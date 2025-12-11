import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import certifi
import logging
import sys

def get_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

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

def get_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = TLSAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

import time
import functools
from typing import Dict, Any

class PerformanceMonitor:
    """
    Simple performance monitoring singleton.
    """
    _instance = None
    _metrics: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PerformanceMonitor, cls).__new__(cls)
            cls._instance._metrics = {
                "execution_times": {},
                "counters": {}
            }
        return cls._instance

    def record_time(self, name: str, duration: float):
        if name not in self._metrics["execution_times"]:
            self._metrics["execution_times"][name] = []
        self._metrics["execution_times"][name].append(duration)

    def increment_counter(self, name: str):
        self._metrics["counters"][name] = self._metrics["counters"].get(name, 0) + 1

    def get_metrics(self) -> Dict[str, Any]:
        stats = {
            "counters": self._metrics["counters"],
            "timings": {}
        }
        for name, times in self._metrics["execution_times"].items():
            if times:
                stats["timings"][name] = {
                    "count": len(times),
                    "avg": sum(times) / len(times),
                    "max": max(times),
                    "min": min(times),
                    "total": sum(times)
                }
        return stats

    def print_stats(self):
        logger = get_logger("Performance")
        logger.info("Performance Metrics:")
        logger.info(f"Counters: {self._metrics['counters']}")
        for name, times in self._metrics["execution_times"].items():
            avg = sum(times) / len(times)
            logger.info(f"Timer [{name}]: Count={len(times)}, Avg={avg:.4f}s, Total={sum(times):.4f}s")

def measure_time(func):
    """Decorator to measure execution time of a function."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            monitor = PerformanceMonitor()
            monitor.record_time(func.__name__, duration)
            # Also log immediately for visibility
            logger = get_logger(func.__module__)
            logger.info(f"Function {func.__name__} took {duration:.4f} seconds")
    return wrapper
