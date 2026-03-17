"""
Enterprise NGFW v2.0 - Inspector Plugin Base

Abstract base class for all inspection plugins.

Author: Enterprise NGFW Team
License: Proprietary
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import IntEnum


class InspectionAction(IntEnum):
    """Action to take after inspection"""
    ALLOW = 0
    BLOCK = 1
    DROP = 2  # Silent drop
    QUARANTINE = 3  # Hold for review
    LOG_ONLY = 4


class PluginPriority(IntEnum):
    """Plugin execution priority (lower = earlier)"""
    HIGHEST = 0
    HIGH = 25
    NORMAL = 50
    LOW = 75
    LOWEST = 100


@dataclass
class InspectionContext:
    """Context information for inspection"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # 'TCP', 'UDP', 'ICMP'
    direction: str  # 'inbound', 'outbound'
    flow_id: str  # Unique flow identifier
    timestamp: float
    metadata: Dict[str, Any]



@dataclass
class InspectionFinding:
    """A single finding produced by an inspection plugin"""
    plugin_name: str
    severity: str           # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    category: str           # e.g. "DLP", "SQL Injection", "XSS"
    description: str
    confidence: float = 1.0  # 0.0 – 1.0
    recommends_block: bool = False
    metadata: Dict[str, Any] = None
    evidence: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.evidence is None:
            self.evidence = {}


@dataclass
class InspectionResult:
    """Aggregated result returned by an inspection"""
    action: InspectionAction = InspectionAction.ALLOW
    findings: List[InspectionFinding] = None
    metadata: Dict[str, Any] = None
    processing_time_ms: float = 0.0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.metadata is None:
            self.metadata = {}
            
    @property
    def is_blocked(self) -> bool:
        """Check if traffic should be blocked"""
        return self.action in (InspectionAction.BLOCK, InspectionAction.DROP)





class InspectorPlugin(ABC):
    """
    Abstract base class for inspection plugins.
    
    All protocol inspectors must inherit from this class and implement
    the required methods.
    """
    
    def __init__(
        self,
        name: str,
        priority: PluginPriority = PluginPriority.NORMAL,
        logger: Optional[logging.Logger] = None
    ):
        self.name = name
        self.priority = priority
        self.logger = logger or logging.getLogger(f"{self.__class__.__name__}")
        self.enabled = True
        
        # Statistics
        self._inspected_count = 0
        self._detected_count = 0
        self._blocked_count = 0
        
    @abstractmethod
    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Check if this plugin can inspect the given traffic.
        
        Args:
            context: Inspection context
            
        Returns:
            True if plugin can handle this traffic
        """
        pass
        
    @abstractmethod
    def inspect(
        self,
        context: InspectionContext,
        data: bytes
    ) -> 'InspectionResult':
        """
        Inspect the traffic data.
        
        Args:
            context: Inspection context
            data: Raw packet/stream data
            
        Returns:
            InspectionResult with findings
        """
        pass
        
    def enable(self) -> None:
        """Enable this plugin"""
        self.enabled = True
        self.logger.info(f"Plugin {self.name} enabled")
        
    def disable(self) -> None:
        """Disable this plugin"""
        self.enabled = False
        self.logger.info(f"Plugin {self.name} disabled")
        
    def get_statistics(self) -> Dict:
        """Get plugin statistics"""
        return {
            'name': self.name,
            'enabled': self.enabled,
            'priority': self.priority,
            'inspected': self._inspected_count,
            'detected': self._detected_count,
            'blocked': self._blocked_count,
            'detection_rate': (
                self._detected_count / max(self._inspected_count, 1) * 100
            )
        }
        
    def reset_statistics(self) -> None:
        """Reset statistics counters"""
        self._inspected_count = 0
        self._detected_count = 0
        self._blocked_count = 0
        
    def __str__(self) -> str:
        return f"{self.name} (priority={self.priority}, enabled={self.enabled})"
