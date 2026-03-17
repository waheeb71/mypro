#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - File Backend
═══════════════════════════════════════════════════════════════════

File-based event storage backend.
Supports JSON and CSV formats with rotation.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import aiofiles
import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import logging

from .base import EventBackend
from ..event_schema import EventSchema


logger = logging.getLogger(__name__)


class FileBackend(EventBackend):
    """
    File-based event storage
    
    Features:
    - JSON or CSV format
    - Daily/hourly/size-based rotation
    - Async I/O
    - Compression support (gzip)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize file backend
        
        Args:
            config: Configuration with:
                - output_dir: Directory for event files
                - format: 'json' or 'csv'
                - rotation: 'daily', 'hourly', 'size'
                - max_size: Max file size in MB (for size rotation)
                - compress: Enable gzip compression
        """
        super().__init__(config)
        
        self.output_dir = Path(config.get('output_dir', 'logs/events'))
        self.format = config.get('format', 'json').lower()
        self.rotation = config.get('rotation', 'daily')
        self.max_size = config.get('max_size', 100) * 1024 * 1024  # Convert MB to bytes
        self.compress = config.get('compress', False)
        
        self._current_file: Optional[Path] = None
        self._file_handle = None
        self._csv_writer = None
        self._lock = asyncio.Lock()
        
        logger.info(f"File backend initialized: {self.output_dir} ({self.format})")
    
    async def initialize(self):
        """Create output directory"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"✅ File backend ready: {self.output_dir}")
    
    async def write_batch(self, events: List[EventSchema]):
        """
        Write events to file
        
        Args:
            events: Events to write
        """
        if not events:
            return
        
        async with self._lock:
            try:
                # Check if we need to rotate
                await self._check_rotation()
                
                # Write based on format
                if self.format == 'json':
                    await self._write_json(events)
                elif self.format == 'csv':
                    await self._write_csv(events)
                else:
                    raise ValueError(f"Unsupported format: {self.format}")
                
                # Update stats
                total_bytes = sum(len(e.to_json()) for e in events)
                self._update_stats(len(events), total_bytes, failed=False)
                
            except Exception as e:
                logger.error(f"Error writing events to file: {e}")
                self._update_stats(len(events), failed=True)
                raise
    
    async def _check_rotation(self):
        """Check if file needs rotation"""
        current_file = self._get_current_filename()
        
        # Check if file changed (time-based rotation)
        if self._current_file != current_file:
            await self._rotate_file(current_file)
            return
        
        # Check size-based rotation
        if self.rotation == 'size' and self._current_file:
            if self._current_file.exists():
                size = self._current_file.stat().st_size
                if size >= self.max_size:
                    # Add timestamp to rotated file
                    rotated = self._current_file.with_suffix(
                        f'.{datetime.now().strftime("%Y%m%d_%H%M%S")}{self._current_file.suffix}'
                    )
                    await self._rotate_file(current_file)
    
    def _get_current_filename(self) -> Path:
        """Get current filename based on rotation policy"""
        now = datetime.now()
        
        if self.rotation == 'hourly':
            timestamp = now.strftime('%Y%m%d_%H')
        elif self.rotation == 'daily':
            timestamp = now.strftime('%Y%m%d')
        else:  # size-based, use date as base
            timestamp = now.strftime('%Y%m%d')
        
        extension = 'json' if self.format == 'json' else 'csv'
        filename = f"events_{timestamp}.{extension}"
        
        return self.output_dir / filename
    
    async def _rotate_file(self, new_file: Path):
        """Rotate to a new file"""
        # Close current file
        if self._file_handle:
            await self._file_handle.close()
            self._file_handle = None
            self._csv_writer = None
        
        self._current_file = new_file
        logger.info(f"Rotated to new file: {new_file}")
    
    async def _write_json(self, events: List[EventSchema]):
        """Write events in JSON format (one per line)"""
        # Open file in append mode
        async with aiofiles.open(self._current_file, 'a', encoding='utf-8') as f:
            for event in events:
                line = event.to_json() + '\n'
                await f.write(line)
    
    async def _write_csv(self, events: List[EventSchema]):
        """Write events in CSV format"""
        # For CSV, we need to handle headers
        file_exists = self._current_file.exists() and self._current_file.stat().st_size > 0
        
        # Convert events to dicts
        rows = [event.to_dict() for event in events]
        
        # Get all possible keys
        if not file_exists and rows:
            headers = rows[0].keys()
        else:
            headers = None
        
        async with aiofiles.open(self._current_file, 'a', encoding='utf-8', newline='') as f:
            # Write to string buffer first (csv module doesn't support async)
            import io
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=headers or rows[0].keys() if rows else [])
            
            if not file_exists and headers:
                writer.writeheader()
            
            for row in rows:
                writer.writerow(row)
            
            # Write buffer to file
            await f.write(buffer.getvalue())
    
    async def close(self):
        """Close file backend"""
        if self._file_handle:
            await self._file_handle.close()
        logger.info("File backend closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if output directory is writable"""
        try:
            # Try to write a test file
            test_file = self.output_dir / '.health_check'
            test_file.touch()
            test_file.unlink()
            
            return {
                'healthy': True,
                'output_dir': str(self.output_dir),
                'format': self.format,
                'current_file': str(self._current_file) if self._current_file else None
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }
