"""Rate limiting for HTTP servers."""
import time
import threading
from typing import Tuple
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    requests_per_second: int = 0
    burst: int = 10


class TokenBucket:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def allow(self) -> bool:
        if self.rate <= 0:
            return True
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
    
    def get_retry_after(self) -> int:
        if self.rate <= 0:
            return 0
        with self.lock:
            if self.tokens >= 1:
                return 0
            return int((1 - self.tokens) / self.rate) + 1


class RateLimiter:
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.buckets: dict = {}
        self.lock = threading.Lock()
    
    def allow(self, client_id: str) -> Tuple[bool, int]:
        if self.config.requests_per_second <= 0:
            return True, 0
        with self.lock:
            if client_id not in self.buckets:
                self.buckets[client_id] = TokenBucket(self.config.requests_per_second, self.config.burst)
            bucket = self.buckets[client_id]
            allowed = bucket.allow()
            return allowed, bucket.get_retry_after() if not allowed else 0


def create_rate_limiter(rate_per_second: int = 0, burst: int = 10) -> RateLimiter:
    return RateLimiter(RateLimitConfig(rate_per_second, burst))