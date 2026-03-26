#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Streaming Backend
═══════════════════════════════════════════════════════════════════

Streaming backend for real-time event processing.
Supports Kafka, Redis Streams, and other message brokers.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
import json
from typing import List, Dict, Any, Optional

try:
    from aiokafka import AIOKafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .base import EventBackend
from ..event_schema import EventSchema


logger = logging.getLogger(__name__)


class StreamingBackend(EventBackend):
    """
    Streaming backend for real-time event processing
    
    Supports:
    - Apache Kafka
    - Redis Streams
    - Custom message brokers
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize streaming backend
        
        Args:
            config: Configuration with:
                - stream_type: 'kafka', 'redis', etc.
                - connection_string: Connection details
                - topic/stream: Target topic/stream name
        """
        super().__init__(config)
        
        self.stream_type = config.get('stream_type', 'kafka').lower()
        self.connection_string = config.get('connection_string', 'localhost:9092')
        self.topic = config.get('topic', 'CyberNexus-events')
        
        self._producer = None
        self._redis = None
        
        # Validate availability
        if self.stream_type == 'kafka' and not KAFKA_AVAILABLE:
            logger.warning("Kafka not available. Install with: pip install aiokafka")
        if self.stream_type == 'redis' and not REDIS_AVAILABLE:
            logger.warning("Redis not available. Install with: pip install aioredis")
        
        logger.info(f"Streaming backend initialized: {self.stream_type}")
    
    async def initialize(self):
        """Initialize streaming connection"""
        try:
            if self.stream_type == 'kafka':
                await self._init_kafka()
            elif self.stream_type == 'redis':
                await self._init_redis()
            else:
                logger.warning(f"Streaming type {self.stream_type} not fully implemented")
            
            logger.info(f"✅ Streaming backend ready: {self.stream_type}")
        except Exception as e:
            logger.error(f"Failed to initialize streaming backend: {e}")
            # Don't raise - allow graceful degradation
    
    async def _init_kafka(self):
        """Initialize Kafka producer"""
        if not KAFKA_AVAILABLE:
            return
        
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.connection_string,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await self._producer.start()
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            return
        
        self._redis = await aioredis.create_redis_pool(
            self.connection_string,
            encoding='utf-8'
        )
    
    async def write_batch(self, events: List[EventSchema]):
        """Stream events to broker"""
        if not events:
            return
        
        try:
            if self.stream_type == 'kafka':
                await self._write_kafka(events)
            elif self.stream_type == 'redis':
                await self._write_redis(events)
            else:
                logger.warning(f"Streaming to {self.stream_type} not implemented")
                return
            
            self._update_stats(len(events), failed=False)
            
        except Exception as e:
            logger.error(f"Error streaming events: {e}")
            self._update_stats(len(events), failed=True)
            # Don't raise - allow other backends to continue
    
    async def _write_kafka(self, events: List[EventSchema]):
        """Write to Kafka"""
        if not self._producer:
            return
        
        for event in events:
            await self._producer.send_and_wait(
                self.topic,
                value=event.to_dict()
            )
    
    async def _write_redis(self, events: List[EventSchema]):
        """Write to Redis Streams"""
        if not self._redis:
            return
        
        for event in events:
            await self._redis.xadd(
                self.topic,
                {'data': event.to_json()}
            )
    
    async def close(self):
        """Close streaming connection"""
        if self._producer:
            await self._producer.stop()
        
        if self._redis:
            self._redis.close()
            await self._redis.wait_closed()
        
        logger.info("Streaming backend closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check streaming connection"""
        try:
            # Basic connectivity check
            is_healthy = False
            
            if self.stream_type == 'kafka' and self._producer:
                # Kafka producer is connected
                is_healthy = True
            elif self.stream_type == 'redis' and self._redis:
                # Try Redis ping
                pong = await self._redis.ping()
                is_healthy = (pong == b'PONG')
            
            return {
                'healthy': is_healthy,
                'stream_type': self.stream_type,
                'topic': self.topic
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }
