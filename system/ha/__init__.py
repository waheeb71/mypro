"""
Enterprise NGFW - High Availability (HA)

Provides Active-Passive clustering capabilities.
"""

from .heartbeat import HAManager, NodeState

__all__ = [
    'HAManager',
    'NodeState'
]
