import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class TokenBucket:
    """ A simple Token Bucket implementation for rate limiting """
    def __init__(self, capacity: int, fill_rate: int):
        self.capacity = float(capacity)
        self.fill_rate = float(fill_rate)
        self.tokens = float(capacity)
        self.last_update = time.time()
        
    def consume(self, tokens: int) -> bool:
        """ Returns True if tokens could be consumed, False if rate limited """
        now = time.time()
        time_passed = now - self.last_update
        
        # Add new tokens
        self.tokens += (time_passed * self.fill_rate)
        if self.tokens > self.capacity:
            self.tokens = self.capacity
            
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

class RateLimiterEngine:
    """ Manages bandwidth per IP or per User using Token Buckets """
    
    def __init__(self):
        # Maps IP to TokenBucket
        self.buckets: Dict[str, TokenBucket] = {}
        # Default 1MB/s, 5MB burst
        self.default_capacity = 5 * 1024 * 1024
        self.default_fill_rate = 1 * 1024 * 1024
        
    def check_traffic(self, ip: str, payload_size_bytes: int) -> bool:
        """ Returns True if traffic is allowed, False if it should be dropped (shaped) """
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket(self.default_capacity, self.default_fill_rate)
            
        bucket = self.buckets[ip]
        allowed = bucket.consume(payload_size_bytes)
        
        if not allowed:
            logger.debug(f"QoS Rate Limited: {ip} tried to send {payload_size_bytes} bytes")
            
        return allowed
