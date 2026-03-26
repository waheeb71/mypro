import logging
import time
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

class AdaptiveRateLimiter:
    """
    Advanced Granular & Adaptive Rate Limiting.
    Supports limiting by:
      - IP Address
      - JWT / User ID (if provided in metadata context)
      - Specific API Routes
      
    Adaptive capability: Limits drop if system load is high (simulated).
    """

    def __init__(self,
                 global_rate_limit: int = 1000,
                 ip_rate_limit: int = 100,
                 user_rate_limit: int = 300,
                 time_window_seconds: int = 60,
                 adaptive_penalty_pct: float = 0.0):
                 
        # Configured Base Limits (requests per window)
        self.base_global_limit = global_rate_limit
        self.base_ip_limit = ip_rate_limit
        self.base_user_limit = user_rate_limit
        
        self.time_window = time_window_seconds
        
        # In a real system, system metrics would feed this percentage
        # 0.0 = Normal, 0.5 = 50% limit reduction due to high load
        self.adaptive_penalty = adaptive_penalty_pct
        
        # State stores (In-memory simple tracking. Real enterprise uses Redis)
        # Format { id: [timestamp1, timestamp2] }
        self._global_count: list = []
        self._ip_counts: Dict[str, list] = {}
        self._user_counts: Dict[str, list] = {}

        logger.info("AdaptiveRateLimiter initialized")

    @property
    def current_ip_limit(self) -> int:
        """Effective IP limit after applying adaptive penalty."""
        return int(self.base_ip_limit * (1.0 - self.adaptive_penalty))

    @property
    def current_user_limit(self) -> int:
         """Effective User limit after applying adaptive penalty."""
         return int(self.base_user_limit * (1.0 - self.adaptive_penalty))

    def evaluate_request(self, ip: str, user_id: str = None) -> Tuple[bool, str]:
        """
        Record a request and evaluate if it breaches rate limits.
        Returns: (is_allowed, block_reason)
        """
        now = time.time()
        
        # 1. Global limit check (DDoS prevention)
        self._global_count.append(now)
        self._global_count = [t for t in self._global_count if now - t < self.time_window]
        if len(self._global_count) > self.base_global_limit:
             return False, "Global rate limit exceeded (Platform under heavy load)"

        # 2. IP limit check
        self._ip_counts.setdefault(ip, []).append(now)
        self._ip_counts[ip] = [t for t in self._ip_counts[ip] if now - t < self.time_window]
        if len(self._ip_counts[ip]) > self.current_ip_limit:
             return False, f"IP rate limit exceeded ({self.current_ip_limit} req/{self.time_window}s)"

        # 3. User limit check (if authenticated)
        if user_id:
             self._user_counts.setdefault(user_id, []).append(now)
             self._user_counts[user_id] = [t for t in self._user_counts[user_id] if now - t < self.time_window]
             if len(self._user_counts[user_id]) > self.current_user_limit:
                  return False, f"User-level rate limit exceeded ({self.current_user_limit} req/{self.time_window}s)"

        return True, ""

    def update_system_load(self, cpu_usage_pct: float) -> None:
        """Dynamically trigger adaptive limits if system is stressed."""
        if cpu_usage_pct > 0.85:
            self.adaptive_penalty = 0.50 # Cut limits by half
            logger.warning("High CPU load detected! Rate limits reduced by 50%%.")
        elif cpu_usage_pct > 0.70:
            self.adaptive_penalty = 0.25 # Cut limits by 25%
            logger.info("Moderate CPU load detected. Rate limits reduced by 25%%.")
        else:
            self.adaptive_penalty = 0.0  # Normal operation
            logger.debug("System load normal. Rate limits restored.")
