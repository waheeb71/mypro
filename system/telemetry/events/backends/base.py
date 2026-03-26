#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Event Backend Base Class
═══════════════════════════════════════════════════════════════════

Abstract base class for event backends.
All backends must implement this interface.

Author: Enterprise Security Team
License: Proprietary
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..event_schema import EventSchema


class EventBackend(ABC):
    """
    Abstract base class for event backends
    
    All backends (file, database, streaming) must implement
    this interface to be used by UnifiedEventSink.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize backend with configuration
        
        Args:
            config: Backend configuration dictionary
        """
        self.config = config
        self._stats = {
            'events_written': 0,
            'events_failed': 0,
            'bytes_written': 0,
        }
    
    @abstractmethod
    async def initialize(self):
        """
        Initialize the backend (create connections, files, etc.)
        Must be called before using the backend.
        """
        pass
    
    @abstractmethod
    async def write_batch(self, events: List[EventSchema]):
        """
        Write a batch of events to the backend
        
        Args:
            events: List of events to write
            
        Raises:
            Exception: If write fails
        """
        pass
    
    @abstractmethod
    async def close(self):
        """
        Close the backend and cleanup resources
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the backend
        
        Returns:
            Dictionary with health status
        """
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get backend statistics
        
        Returns:
            Dictionary with statistics
        """
        return self._stats.copy()
    
    def _update_stats(self, events_count: int, bytes_count: int = 0, failed: bool = False):
        """
        Update internal statistics
        
        Args:
            events_count: Number of events processed
            bytes_count: Bytes written
            failed: Whether operation failed
        """
        if failed:
            self._stats['events_failed'] += events_count
        else:
            self._stats['events_written'] += events_count
            self._stats['bytes_written'] += bytes_count
