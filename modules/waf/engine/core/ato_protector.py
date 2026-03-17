import logging
import time
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

class ATOProtector:
    """
    Account Takeover (ATO) & Credential Stuffing Protector.
    
    Tracks login attempts per IP and per Username across endpoints.
    If it detects rapid, distributed login attempts, it flags them 
    with a high risk score.
    """
    
    def __init__(self, 
                 login_endpoints: list = ["/login", "/api/auth/login", "/auth/token"],
                 max_attempts_per_ip: int = 20, 
                 max_attempts_per_user: int = 5,
                 time_window_seconds: int = 300):
        
        self.login_endpoints = set(login_endpoints)
        self.max_attempts_per_ip = max_attempts_per_ip
        self.max_attempts_per_user = max_attempts_per_user
        self.time_window = time_window_seconds
        
        # Simple in-memory storage for demonstration.
        # Format: { "ip": [timestamp1, timestamp2, ...] }
        self._ip_attempts: Dict[str, list] = {}
        self._user_attempts: Dict[str, list] = {}
        
        logger.info("ATOProtector initialized | endpoints=%s", self.login_endpoints)

    def is_login_endpoint(self, path: str) -> bool:
        """Check if the requested path is a monitored login endpoint."""
        for endpoint in self.login_endpoints:
            if path.rstrip("/") == endpoint.rstrip("/"):
                return True
        return False

    def track_and_evaluate(self, ip: str, username: str = None) -> Tuple[bool, float, str]:
        """
        Record a login attempt and return if it's considered an ATO attack.
        Returns: (is_attack, risk_score, reason)
        """
        now = time.time()
        
        # 1. Track IP attempts (Credential Stuffing / Brute Force)
        self._ip_attempts.setdefault(ip, []).append(now)
        # Purge old
        self._ip_attempts[ip] = [t for t in self._ip_attempts[ip] if now - t < self.time_window]
        
        ip_count = len(self._ip_attempts[ip])
        ip_risk = min(1.0, ip_count / self.max_attempts_per_ip)
        
        if ip_count > self.max_attempts_per_ip:
            return True, 0.95, f"Credential stuffing detected from {ip} ({ip_count} attempts in {self.time_window}s)"
        
        # 2. Track Username attempts (Distributed attacks guessing one user's password)
        if username:
            self._user_attempts.setdefault(username, []).append(now)
            # Purge old
            self._user_attempts[username] = [t for t in self._user_attempts[username] if now - t < self.time_window]
            
            user_count = len(self._user_attempts[username])
            user_risk = min(1.0, user_count / self.max_attempts_per_user)
            
            if user_count > self.max_attempts_per_user:
                return True, 0.90, f"Distributed brute force on user '{username}' ({user_count} attempts in {self.time_window}s)"
            
            # Combine risks (max)
            return False, max(ip_risk, user_risk), "Normal login frequency"
            
        return False, ip_risk, "Normal IP login frequency"
        
    def reset(self):
        """Clear all tracking data (Useful for tests/flushing)."""
        self._ip_attempts.clear()
        self._user_attempts.clear()
