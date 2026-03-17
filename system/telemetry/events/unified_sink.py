#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - Unified Event Sink
═══════════════════════════════════════════════════════════════════

Centralized event collection point for all traffic paths.
Receives events from XDP and Normal (Proxy) paths and forwards
them to configured backends (file, database, streaming).

Features:
- Async event submission
- Batch processing
- Multiple backend support
- Error handling and retry logic
- Event buffering

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .event_schema import EventSchema
from .backends.base import EventBackend
from .backends.file_backend import FileBackend
from .backends.database_backend import DatabaseBackend
from .backends.streaming_backend import StreamingBackend


logger = logging.getLogger(__name__)


@dataclass
class SinkConfig:
    """Configuration for Unified Event Sink"""
    
    # Buffer settings
    buffer_size: int = 1000  # Max events in buffer before flush
    flush_interval: float = 1.0  # Seconds between flushes
    
    # Backend configurations
    backends: List[Dict[str, Any]] = field(default_factory=list)
    
    # Error handling
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # Performance
    batch_size: int = 100  # Events per batch to backends
    
    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> 'SinkConfig':
        """Create config from dictionary"""
        return cls(
            buffer_size=config.get('buffer_size', 1000),
            flush_interval=config.get('flush_interval', 1.0),
            backends=config.get('backends', []),
            max_retries=config.get('max_retries', 3),
            retry_delay=config.get('retry_delay', 1.0),
            batch_size=config.get('batch_size', 100),
        )


class UnifiedEventSink:
    """
    Unified Event Sink for Enterprise NGFW
    
    Receives events from all traffic paths and forwards them
    to configured backends.
    
    Usage:
        sink = UnifiedEventSink(config)
        await sink.start()
        
        # Submit single event
        await sink.submit_event(event)
        
        # Submit batch
        await sink.batch_submit([event1, event2, ...])
        
        await sink.stop()
    """
    
    def __init__(self, config: SinkConfig):
        """
        Initialize Unified Event Sink
        
        Args:
            config: Sink configuration
        """
        self.config = config
        self.logger = logger
        
        # Event buffer
        self._buffer: List[EventSchema] = []
        self._buffer_lock = asyncio.Lock()
        
        # Backends
        self._backends: List[EventBackend] = []
        
        # Background tasks
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Statistics
        self._stats = {
            'total_events': 0,
            'events_buffered': 0,
            'events_flushed': 0,
            'events_failed': 0,
            'flush_count': 0,
            'last_flush': None,
        }
        self._stats_lock = asyncio.Lock()
        
        self.logger.info(f"Initialized UnifiedEventSink with buffer_size={config.buffer_size}")
    
    async def start(self):
        """Start the event sink and background tasks"""
        self.logger.info("Starting Unified Event Sink...")
        
        # Initialize backends
        await self._initialize_backends()
        
        # Start background flush task
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        
        self.logger.info(f"✅ Unified Event Sink started with {len(self._backends)} backends")
    
    async def stop(self):
        """Stop the event sink and flush remaining events"""
        if not self._running:
            return
        
        self.logger.info("Stopping Unified Event Sink...")
        self._running = False
        
        # Stop flush task
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self._flush_buffer()
        
        # Close backends
        for backend in self._backends:
            try:
                await backend.close()
            except Exception as e:
                self.logger.error(f"Error closing backend {backend.__class__.__name__}: {e}")
        
        self.logger.info("✅ Unified Event Sink stopped")
    
    async def submit_event(self, event: EventSchema):
        """
        Submit a single event to the sink
        
        Args:
            event: Event to submit
        """
        async with self._buffer_lock:
            self._buffer.append(event)
            
            async with self._stats_lock:
                self._stats['total_events'] += 1
                self._stats['events_buffered'] += 1
            
            # Check if buffer is full
            if len(self._buffer) >= self.config.buffer_size:
                # Trigger immediate flush
                asyncio.create_task(self._flush_buffer())
    
    async def batch_submit(self, events: List[EventSchema]):
        """
        Submit multiple events at once
        
        Args:
            events: List of events to submit
        """
        if not events:
            return
        
        async with self._buffer_lock:
            self._buffer.extend(events)
            
            async with self._stats_lock:
                self._stats['total_events'] += len(events)
                self._stats['events_buffered'] += len(events)
            
            # Check if buffer is full
            if len(self._buffer) >= self.config.buffer_size:
                asyncio.create_task(self._flush_buffer())
    
    async def _initialize_backends(self):
        """Initialize configured backends"""
        for backend_config in self.config.backends:
            backend_type = backend_config.get('type', 'file')
            
            try:
                if backend_type == 'file':
                    backend = FileBackend(backend_config)
                elif backend_type == 'database':
                    backend = DatabaseBackend(backend_config)
                elif backend_type == 'streaming':
                    backend = StreamingBackend(backend_config)
                else:
                    self.logger.warning(f"Unknown backend type: {backend_type}")
                    continue
                
                await backend.initialize()
                self._backends.append(backend)
                self.logger.info(f"✅ Initialized {backend_type} backend")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize {backend_type} backend: {e}")
    
    async def _flush_loop(self):
        """Background task to periodically flush buffer"""
        self.logger.info(f"Flush loop started (interval={self.config.flush_interval}s)")
        
        try:
            while self._running:
                await asyncio.sleep(self.config.flush_interval)
                await self._flush_buffer()
                
        except asyncio.CancelledError:
            self.logger.info("Flush loop cancelled")
        except Exception as e:
            self.logger.error(f"Error in flush loop: {e}", exc_info=True)
    
    async def _flush_buffer(self):
        """Flush buffered events to backends"""
        async with self._buffer_lock:
            if not self._buffer:
                return
            
            # Get events to flush
            events_to_flush = self._buffer.copy()
            self._buffer.clear()
        
        # Update stats
        async with self._stats_lock:
            self._stats['flush_count'] += 1
            self._stats['last_flush'] = datetime.utcnow()
        
        # Send to backends in batches
        batch_size = self.config.batch_size
        for i in range(0, len(events_to_flush), batch_size):
            batch = events_to_flush[i:i + batch_size]
            await self._send_to_backends(batch)
    
    async def _send_to_backends(self, events: List[EventSchema]):
        """
        Send events to all backends
        
        Args:
            events: Events to send
        """
        for backend in self._backends:
            for retry in range(self.config.max_retries):
                try:
                    await backend.write_batch(events)
                    
                    # Update stats
                    async with self._stats_lock:
                        self._stats['events_flushed'] += len(events)
                    
                    break  # Success
                    
                except Exception as e:
                    self.logger.error(
                        f"Error writing to {backend.__class__.__name__} "
                        f"(attempt {retry + 1}/{self.config.max_retries}): {e}"
                    )
                    
                    if retry < self.config.max_retries - 1:
                        await asyncio.sleep(self.config.retry_delay)
                    else:
                        # Final failure
                        async with self._stats_lock:
                            self._stats['events_failed'] += len(events)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get sink statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            **self._stats,
            'buffer_size': len(self._buffer),
            'backends_count': len(self._backends),
            'backends': [
                {
                    'type': backend.__class__.__name__,
                    'stats': backend.get_statistics()
                }
                for backend in self._backends
            ]
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on sink and backends
        
        Returns:
            Health status dictionary
        """
        status = {
            'sink_running': self._running,
            'buffer_size': len(self._buffer),
            'buffer_usage': len(self._buffer) / self.config.buffer_size,
            'backends': []
        }
        
        for backend in self._backends:
            try:
                backend_health = await backend.health_check()
                status['backends'].append({
                    'type': backend.__class__.__name__,
                    'healthy': backend_health.get('healthy', False),
                    **backend_health
                })
            except Exception as e:
                status['backends'].append({
                    'type': backend.__class__.__name__,
                    'healthy': False,
                    'error': str(e)
                })
        
        status['healthy'] = (
            status['sink_running'] and 
            status['buffer_usage'] < 0.9 and
            any(b['healthy'] for b in status['backends'])
        )
        
        return status


# ═══ Factory Function ═══

def create_unified_sink(config: Dict[str, Any]) -> UnifiedEventSink:
    """
    Factory function to create Unified Event Sink from config
    
    Args:
        config: Configuration dictionary
        
    Returns:
        UnifiedEventSink instance
    """
    sink_config = config.get('event_sink', {})
    
    # Default backend if none configured
    if not sink_config.get('backends'):
        sink_config['backends'] = [
            {
                'type': 'file',
                'output_dir': 'logs/events',
                'format': 'json',
                'rotation': 'daily'
            }
        ]
    
    return UnifiedEventSink(SinkConfig.from_dict(sink_config))
