"""
Core Router Package
Modular routing engine.
"""

from .manager import TrafficRouter
from .types import RoutingDecision, ProxyMode

__all__ = ["TrafficRouter", "RoutingDecision", "ProxyMode"]
