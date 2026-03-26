"""
Enterprise CyberNexus - Recovery Manager

Handles automated rollback and recovery from mitigation actions
once a threat has passed or a false positive is identified.
"""

import logging
import time
from enum import Enum
from typing import Optional, Dict

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    ISOLATED = "isolated"

class RecoveryManager:
    """Manages system health and recovers isolated/blocked entities."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.entity_health: Dict[str, HealthStatus] = {}
        self.recovery_queue: Dict[str, float] = {}  # target -> timestamp
        
    def mark_isolated(self, target: str, duration_sec: int = 3600):
        """Mark an entity as isolated and schedule recovery."""
        self.entity_health[target] = HealthStatus.ISOLATED
        self.recovery_queue[target] = time.time() + duration_sec
        self.logger.info(f"Target {target} marked isolated. Recovery scheduled in {duration_sec}s.")
        
    def check_recoveries(self) -> list:
        """Check if any targets are due for recovery."""
        now = time.time()
        to_recover = []
        
        for target, recover_time in list(self.recovery_queue.items()):
            if now >= recover_time:
                to_recover.append(target)
                
        for target in to_recover:
            self._execute_recovery(target)
            
        return to_recover
        
    def _execute_recovery(self, target: str):
        """Execute the actual recovery process."""
        self.logger.info(f"🔄 Executing automated recovery for {target}...")
        
        # In a real system, invoke FW API or Switch API to un-isolate
        self.entity_health[target] = HealthStatus.HEALTHY
        if target in self.recovery_queue:
            del self.recovery_queue[target]
            
        self.logger.info(f"✅ Target {target} restored to HEALTHY state.")
