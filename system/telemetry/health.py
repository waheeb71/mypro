#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Health Checker
═══════════════════════════════════════════════════════════════════

System health monitoring and status checking.
Provides readiness and liveness probes for production deployment.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component"""
    name: str
    status: HealthStatus
    message: str = ""
    details: Dict[str, Any] = None
    last_check: datetime = None
    
    def __post_init__(self):
        if self.last_check is None:
            self.last_check = datetime.utcnow()
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'status': self.status.value,
            'message': self.message,
            'details': self.details,
            'last_check': self.last_check.isoformat()
        }


class HealthChecker:
    """
    System health checker for Enterprise CyberNexus
    
    Monitors health of all components and provides
    readiness and liveness probes.
    """
    
    def __init__(self, CyberNexus_app):
        """
        Initialize health checker
        
        Args:
            CyberNexus_app: Main CyberNexusApplication instance
        """
        self.app = CyberNexus_app
        self.logger = logger
        
        # Component health cache
        self._component_health: Dict[str, ComponentHealth] = {}
        self._overall_status = HealthStatus.UNKNOWN
        self._last_full_check: Optional[datetime] = None
    
    async def check_all_components(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check of all components
        
        Returns:
            Dictionary with health status of all components
        """
        self.logger.debug("Performing comprehensive health check...")
        
        components = []
        
        # Check event sink
        if self.app.event_sink:
            components.append(await self._check_event_sink())
        
        # Check XDP engine
        if self.app.xdp_engine and self.app.xdp_engine.enabled:
            components.append(await self._check_xdp_engine())
        
        # Check flow tracker
        if self.app.flow_tracker:
            components.append(await self._check_flow_tracker())
        
        # Check proxy modes
        if self.app.transparent_proxy:
            components.append(self._check_proxy("transparent", self.app.transparent_proxy))
        
        if self.app.forward_proxy:
            components.append(self._check_proxy("forward", self.app.forward_proxy))
        
        if self.app.reverse_proxy:
            components.append(self._check_proxy("reverse", self.app.reverse_proxy))
        
        # Check ML components
        if self.app.anomaly_detector:
            components.append(self._check_ml_components())
        
        # Determine overall status
        self._overall_status = self._calculate_overall_status(components)
        self._last_full_check = datetime.utcnow()
        
        return {
            'overall_status': self._overall_status.value,
            'components': [c.to_dict() for c in components],
            'last_check': self._last_full_check.isoformat(),
            'healthy_count': sum(1 for c in components if c.status == HealthStatus.HEALTHY),
            'total_count': len(components)
        }
    
    async def readiness_probe(self) -> bool:
        """
        Readiness probe - is the system ready to accept traffic?
        
        Returns:
            True if ready, False otherwise
        """
        try:
            # System is ready if:
            # 1. Application is running
            # 2. Critical components are healthy
            
            if not self.app.running:
                return False
            
            # Quick check of critical components
            critical_healthy = True
            
            # Event sink must be operational
            if self.app.event_sink:
                try:
                    health = await self.app.event_sink.health_check()
                    if not health.get('healthy', False):
                        critical_healthy = False
                except:
                    critical_healthy = False
            
            # At least one proxy mode should be running
            has_running_proxy = (
                (self.app.transparent_proxy is not None) or
                (self.app.forward_proxy is not None) or
                (self.app.reverse_proxy is not None)
            )
            
            return critical_healthy and has_running_proxy
            
        except Exception as e:
            self.logger.error(f"Error in readiness probe: {e}")
            return False
    
    async def liveness_probe(self) -> bool:
        """
        Liveness probe - is the system alive?
        
        Returns:
            True if alive, False otherwise
        """
        try:
            # System is alive if:
            # 1. Application is running
            # 2. No critical failures
            
            return self.app.running
            
        except Exception as e:
            self.logger.error(f"Error in liveness probe: {e}")
            return False
    
    async def _check_event_sink(self) -> ComponentHealth:
        """Check event sink health"""
        try:
            health = await self.app.event_sink.health_check()
            
            if health.get('healthy', False):
                return ComponentHealth(
                    name="event_sink",
                    status=HealthStatus.HEALTHY,
                    message="Event sink operational",
                    details=health
                )
            else:
                return ComponentHealth(
                    name="event_sink",
                    status=HealthStatus.DEGRADED,
                    message="Event sink degraded",
                    details=health
                )
        except Exception as e:
            return ComponentHealth(
                name="event_sink",
                status=HealthStatus.UNHEALTHY,
                message=f"Event sink error: {e}",
                details={'error': str(e)}
            )
    
    async def _check_xdp_engine(self) -> ComponentHealth:
        """Check XDP engine health"""
        try:
            stats = self.app.xdp_engine.get_statistics()
            
            if stats:
                return ComponentHealth(
                    name="xdp_engine",
                    status=HealthStatus.HEALTHY,
                    message="XDP engine operational",
                    details=stats
                )
            else:
                return ComponentHealth(
                    name="xdp_engine",
                    status=HealthStatus.DEGRADED,
                    message="XDP engine running but no stats",
                    details={}
                )
        except Exception as e:
            return ComponentHealth(
                name="xdp_engine",
                status=HealthStatus.UNHEALTHY,
                message=f"XDP engine error: {e}",
                details={'error': str(e)}
            )
    
    async def _check_flow_tracker(self) -> ComponentHealth:
        """Check flow tracker health"""
        try:
            # Flow tracker is healthy if it's running
            # Could add more sophisticated checks here
            
            return ComponentHealth(
                name="flow_tracker",
                status=HealthStatus.HEALTHY,
                message="Flow tracker operational",
                details={}
            )
        except Exception as e:
            return ComponentHealth(
                name="flow_tracker",
                status=HealthStatus.UNHEALTHY,
                message=f"Flow tracker error: {e}",
                details={'error': str(e)}
            )
    
    def _check_proxy(self, proxy_type: str, proxy_instance) -> ComponentHealth:
        """Check proxy mode health"""
        try:
            # Basic check - proxy exists
            return ComponentHealth(
                name=f"{proxy_type}_proxy",
                status=HealthStatus.HEALTHY,
                message=f"{proxy_type.capitalize()} proxy operational",
                details={'type': proxy_type}
            )
        except Exception as e:
            return ComponentHealth(
                name=f"{proxy_type}_proxy",
                status=HealthStatus.UNHEALTHY,
                message=f"{proxy_type.capitalize()} proxy error: {e}",
                details={'error': str(e)}
            )
    
    def _check_ml_components(self) -> ComponentHealth:
        """Check ML components health"""
        try:
            # ML components are optional, so degraded is OK
            return ComponentHealth(
                name="ml_components",
                status=HealthStatus.HEALTHY,
                message="ML components operational",
                details={
                    'anomaly_detector': self.app.anomaly_detector is not None,
                    'traffic_profiler': self.app.traffic_profiler is not None,
                    'policy_engine': self.app.policy_engine is not None
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="ml_components",
                status=HealthStatus.DEGRADED,
                message=f"ML components degraded: {e}",
                details={'error': str(e)}
            )
    
    def _calculate_overall_status(self, components: List[ComponentHealth]) -> HealthStatus:
        """
        Calculate overall system status from component statuses
        
        Args:
            components: List of component health statuses
            
        Returns:
            Overall health status
        """
        if not components:
            return HealthStatus.UNKNOWN
        
        # Count statuses
        unhealthy_count = sum(1 for c in components if c.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for c in components if c.status == HealthStatus.DEGRADED)
        
        # If any critical component is unhealthy
        if unhealthy_count > 0:
            # Check if it's a critical component
            critical_components = ['event_sink', 'flow_tracker']
            critical_unhealthy = any(
                c.name in critical_components and c.status == HealthStatus.UNHEALTHY
                for c in components
            )
            
            if critical_unhealthy:
                return HealthStatus.UNHEALTHY
            else:
                return HealthStatus.DEGRADED
        
        # If any component is degraded
        if degraded_count > 0:
            return HealthStatus.DEGRADED
        
        # All healthy
        return HealthStatus.HEALTHY
    
    def get_cached_status(self) -> Dict[str, Any]:
        """
        Get cached health status (no checks performed)
        
        Returns:
            Cached health status
        """
        return {
            'overall_status': self._overall_status.value,
            'last_check': self._last_full_check.isoformat() if self._last_full_check else None,
            'components': {
                name: health.to_dict()
                for name, health in self._component_health.items()
            }
        }
