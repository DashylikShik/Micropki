"""Tests for Sprint 7 - Rate Limiting."""
import time
import pytest

from micropki.ratelimit import TokenBucket, RateLimiter, RateLimitConfig


class TestRateLimiting:
    """Test rate limiting system."""
    
    def test_token_bucket_allow(self):
        """Test token bucket allows requests within limit."""
        bucket = TokenBucket(rate=2.0, capacity=5)  # 2 tokens per second, max 5
        
        # First 5 requests should be allowed
        for i in range(5):
            assert bucket.allow() is True
        
        # 6th request should be denied (no tokens)
        assert bucket.allow() is False
    
    def test_token_bucket_refill(self):
        """Test token bucket refills over time."""
        bucket = TokenBucket(rate=1.0, capacity=2)
        
        # Use all tokens
        assert bucket.allow() is True
        assert bucket.allow() is True
        assert bucket.allow() is False
        
        # Wait for refill
        time.sleep(1.1)
        
        # Should have at least 1 token
        assert bucket.allow() is True
    
    def test_rate_limiter_per_client(self):
        """Test rate limiter tracks clients separately."""
        config = RateLimitConfig(requests_per_second=1, burst=2)
        limiter = RateLimiter(config)
        
        # Client A
        allowed, _ = limiter.allow("clientA")
        assert allowed is True
        allowed, _ = limiter.allow("clientA")
        assert allowed is True
        allowed, _ = limiter.allow("clientA")
        assert allowed is False  # Burst exceeded
        
        # Client B - should be unaffected
        allowed, _ = limiter.allow("clientB")
        assert allowed is True
        allowed, _ = limiter.allow("clientB")
        assert allowed is True
    
    def test_rate_limiter_retry_after(self):
        """Test rate limiter returns retry-after time."""
        config = RateLimitConfig(requests_per_second=1, burst=1)
        limiter = RateLimiter(config)
        
        # First request allowed
        allowed, retry = limiter.allow("client")
        assert allowed is True
        
        # Second request denied
        allowed, retry = limiter.allow("client")
        assert allowed is False
        assert retry > 0