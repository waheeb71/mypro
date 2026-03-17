#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - Database Backend
═══════════════════════════════════════════════════════════════════

Database backend for event storage.
Supports PostgreSQL and SQLite.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

from .base import EventBackend
from ..event_schema import EventSchema


logger = logging.getLogger(__name__)


class DatabaseBackend(EventBackend):
    """
    Database backend for event storage
    
    Supports:
    - PostgreSQL (via asyncpg)
    - SQLite (via aiosqlite)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize database backend
        
        Args:
            config: Configuration with:
                - db_type: 'postgresql' or 'sqlite'
                - connection_string: Database connection string
                - table_name: Table name for events
                - auto_create_table: Create table if not exists
        """
        super().__init__(config)
        
        self.db_type = config.get('db_type', 'sqlite').lower()
        self.connection_string = config.get('connection_string', 'ngfw_events.db')
        self.table_name = config.get('table_name', 'events')
        self.auto_create_table = config.get('auto_create_table', True)
        
        self._pool = None
        self._conn = None  # For SQLite
        
        # Validate availability
        if self.db_type == 'postgresql' and not ASYNCPG_AVAILABLE:
            raise RuntimeError("asyncpg not available. Install with: pip install asyncpg")
        if self.db_type == 'sqlite' and not AIOSQLITE_AVAILABLE:
            raise RuntimeError("aiosqlite not available. Install with: pip install aiosqlite")
        
        logger.info(f"Database backend initialized: {self.db_type}")
    
    async def initialize(self):
        """Initialize database connection"""
        if self.db_type == 'postgresql':
            await self._init_postgresql()
        elif self.db_type == 'sqlite':
            await self._init_sqlite()
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
        
        # Create table if needed
        if self.auto_create_table:
            await self._create_table()
        
        logger.info(f"✅ Database backend ready: {self.db_type}")
    
    async def _init_postgresql(self):
        """Initialize PostgreSQL connection pool"""
        self._pool = await asyncpg.create_pool(self.connection_string)
    
    async def _init_sqlite(self):
        """Initialize SQLite connection"""
        self._conn = await aiosqlite.connect(self.connection_string)
    
    async def _create_table(self):
        """Create events table if not exists"""
        if self.db_type == 'postgresql':
            create_sql = f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                event_id VARCHAR(36) PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                flow_id VARCHAR(100) NOT NULL,
                src_ip VARCHAR(45) NOT NULL,
                dst_ip VARCHAR(45) NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol VARCHAR(10) NOT NULL,
                iface_in VARCHAR(50),
                iface_out VARCHAR(50),
                bytes BIGINT DEFAULT 0,
                packets BIGINT DEFAULT 0,
                direction VARCHAR(20),
                source_path VARCHAR(20),
                verdict VARCHAR(20),
                reason TEXT,
                policy_id VARCHAR(100),
                ml_score REAL,
                ml_label VARCHAR(50),
                confidence REAL,
                domain VARCHAR(255),
                url TEXT,
                application VARCHAR(100),
                user_id VARCHAR(100),
                session_id VARCHAR(100),
                metadata JSONB,
                ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_timestamp ON {self.table_name}(timestamp);
            CREATE INDEX IF NOT EXISTS idx_src_ip ON {self.table_name}(src_ip);
            CREATE INDEX IF NOT EXISTS idx_verdict ON {self.table_name}(verdict);
            CREATE INDEX IF NOT EXISTS idx_source_path ON {self.table_name}(source_path);
            """
            
            async with self._pool.acquire() as conn:
                await conn.execute(create_sql)
                
        elif self.db_type == 'sqlite':
            create_sql = f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                flow_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                iface_in TEXT,
                iface_out TEXT,
                bytes INTEGER DEFAULT 0,
                packets INTEGER DEFAULT 0,
                direction TEXT,
                source_path TEXT,
                verdict TEXT,
                reason TEXT,
                policy_id TEXT,
                ml_score REAL,
                ml_label TEXT,
                confidence REAL,
                domain TEXT,
                url TEXT,
                application TEXT,
                user_id TEXT,
                session_id TEXT,
                metadata TEXT,
                ingestion_time TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_timestamp ON {self.table_name}(timestamp);
            CREATE INDEX IF NOT EXISTS idx_src_ip ON {self.table_name}(src_ip);
            """
            
            await self._conn.execute(create_sql)
            await self._conn.commit()
    
    async def write_batch(self, events: List[EventSchema]):
        """Write events to database"""
        if not events:
            return
        
        try:
            if self.db_type == 'postgresql':
                await self._write_postgresql(events)
            elif self.db_type == 'sqlite':
                await self._write_sqlite(events)
            
            self._update_stats(len(events), failed=False)
            
        except Exception as e:
            logger.error(f"Error writing events to database: {e}")
            self._update_stats(len(events), failed=True)
            raise
    
    async def _write_postgresql(self, events: List[EventSchema]):
        """Write to PostgreSQL"""
        insert_sql = f"""
        INSERT INTO {self.table_name} (
            event_id, timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
            protocol, iface_in, iface_out, bytes, packets, direction, source_path,
            verdict, reason, policy_id, ml_score, ml_label, confidence,
            domain, url, application, user_id, session_id, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                 $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
        """
        
        rows = [
            (
                e.event_id, e.timestamp, e.flow_id, e.src_ip, e.dst_ip,
                e.src_port, e.dst_port, e.protocol, e.iface_in, e.iface_out,
                e.bytes, e.packets, e.direction.value, e.source_path.value,
                e.verdict.value, e.reason, e.policy_id, e.ml_score, e.ml_label,
                e.confidence, e.domain, e.url, e.application, e.user_id,
                e.session_id, e.metadata.to_dict()
            )
            for e in events
        ]
        
        async with self._pool.acquire() as conn:
            await conn.executemany(insert_sql, rows)
    
    async def _write_sqlite(self, events: List[EventSchema]):
        """Write to SQLite"""
        insert_sql = f"""
        INSERT INTO {self.table_name} (
            event_id, timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
            protocol, iface_in, iface_out, bytes, packets, direction, source_path,
            verdict, reason, policy_id, ml_score, ml_label, confidence,
            domain, url, application, user_id, session_id, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        import json
        rows = [
            (
                e.event_id, e.timestamp.isoformat(), e.flow_id, e.src_ip, e.dst_ip,
                e.src_port, e.dst_port, e.protocol, e.iface_in, e.iface_out,
                e.bytes, e.packets, e.direction.value, e.source_path.value,
                e.verdict.value, e.reason, e.policy_id, e.ml_score, e.ml_label,
                e.confidence, e.domain, e.url, e.application, e.user_id,
                e.session_id, json.dumps(e.metadata.to_dict())
            )
            for e in events
        ]
        
        await self._conn.executemany(insert_sql, rows)
        await self._conn.commit()
    
    async def close(self):
        """Close database connection"""
        if self.db_type == 'postgresql' and self._pool:
            await self._pool.close()
        elif self.db_type == 'sqlite' and self._conn:
            await self._conn.close()
        
        logger.info("Database backend closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check database connection"""
        try:
            if self.db_type == 'postgresql':
                async with self._pool.acquire() as conn:
                    await conn.fetchval('SELECT 1')
            elif self.db_type == 'sqlite':
                await self._conn.execute('SELECT 1')
            
            return {
                'healthy': True,
                'db_type': self.db_type,
                'table_name': self.table_name
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }
