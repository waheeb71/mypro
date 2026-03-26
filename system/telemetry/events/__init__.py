"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Events Module
═══════════════════════════════════════════════════════════════════

Unified event collection and processing system.
Provides centralized event sink for all traffic paths (XDP + Normal).

Author: Enterprise Security Team
License: Proprietary
"""

from .event_schema import EventSchema, EventDirection, EventVerdict, EventMetadata
from .unified_sink import UnifiedEventSink, SinkConfig

__all__ = [
    'EventSchema',
    'EventDirection',
    'EventVerdict',
    'EventMetadata',
    'UnifiedEventSink',
    'SinkConfig',
]
