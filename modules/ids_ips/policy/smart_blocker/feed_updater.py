#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - Threat Feed Updater
═══════════════════════════════════════════════════════════════════

Automated threat intelligence feed updater with scheduling,
integrity verification, and audit logging.

Features:
- Scheduled automatic updates
- Checksum verification
- Feed format validation
- Audit logging
- Graceful error handling

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import hashlib
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import aiohttp
import json
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class FeedConfig:
    """Configuration for a threat feed"""
    name: str
    url: str
    update_interval: int  # seconds
    format: str  # json, csv, txt
    enabled: bool = True
    checksum_url: Optional[str] = None
    last_update: Optional[datetime] = None
    last_success: Optional[datetime] = None
    update_count: int = 0
    fail_count: int = 0


@dataclass
class FeedUpdateResult:
    """Result of feed update operation"""
    feed_name: str
    success: bool
    entries_added: int = 0
    entries_removed: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class ThreatFeedUpdater:
    """
    Automated threat intelligence feed updater
    
    Features:
    - Periodic feed updates
    - Integrity verification
    - Audit logging
    - Error handling with retries
    """
    
    def __init__(
        self,
        threat_intel,
        config: Dict,
        audit_log_path: Optional[Path] = None
    ):
        """
        Initialize feed updater
        
        Args:
            threat_intel: ThreatIntelligence instance
            config: Configuration dictionary
            audit_log_path: Path for audit logs
        """
        self.threat_intel = threat_intel
        self.config = config
        self.audit_log_path = audit_log_path or Path('/var/log/ngfw/feed_audit.log')
        
        # Feed configurations
        self.feeds: Dict[str, FeedConfig] = {}
        self._load_feed_configs()
        
        # Update tasks
        self._update_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        
        # Statistics
        self._stats = {
            'total_updates': 0,
            'successful_updates': 0,
            'failed_updates': 0,
            'total_entries_added': 0
        }
        
        self.logger = logger
    
    def _load_feed_configs(self):
        """Load feed configurations from config"""
        feeds_config = self.config.get('threat_intel', {}).get('feeds', [])
        
        for feed_cfg in feeds_config:
            feed = FeedConfig(
                name=feed_cfg.get('name', 'unknown'),
                url=feed_cfg.get('url', ''),
                update_interval=feed_cfg.get('update_interval', 3600),
                format=feed_cfg.get('format', 'json'),
                enabled=feed_cfg.get('enabled', True),
                checksum_url=feed_cfg.get('checksum_url')
            )
            self.feeds[feed.name] = feed
        
        self.logger.info(f"Loaded {len(self.feeds)} feed configurations")
    
    async def start(self):
        """Start feed updater and scheduling"""
        if self._running:
            self.logger.warning("Feed updater already running")
            return
        
        self.logger.info("Starting Threat Feed Updater...")
        self._running = True
        
        # Start update tasks for each enabled feed
        for feed_name, feed in self.feeds.items():
            if feed.enabled:
                task = asyncio.create_task(self._update_loop(feed))
                self._update_tasks[feed_name] = task
                self.logger.info(f"Started update task for feed: {feed_name}")
        
        self.logger.info("✅ Threat Feed Updater started")
    
    async def stop(self):
        """Stop feed updater gracefully"""
        if not self._running:
            return
        
        self.logger.info("Stopping Threat Feed Updater...")
        self._running = False
        
        # Cancel all update tasks
        for feed_name, task in self._update_tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self.logger.debug(f"Stopped update task for feed: {feed_name}")
        
        self._update_tasks.clear()
        self.logger.info("✅ Threat Feed Updater stopped")
    
    async def _update_loop(self, feed: FeedConfig):
        """
        Update loop for a single feed
        
        Args:
            feed: Feed configuration
        """
        self.logger.info(
            f"Update loop started for '{feed.name}' "
            f"(interval={feed.update_interval}s)"
        )
        
        try:
            while self._running:
                try:
                    # Perform update
                    result = await self.update_feed(feed)
                    
                    # Log result
                    await self._audit_log(result)
                    
                    # Update statistics
                    self._stats['total_updates'] += 1
                    if result.success:
                        self._stats['successful_updates'] += 1
                        self._stats['total_entries_added'] += result.entries_added
                        feed.last_success = datetime.utcnow()
                        feed.update_count += 1
                        feed.fail_count = 0  # Reset on success
                    else:
                        self._stats['failed_updates'] += 1
                        feed.fail_count += 1
                    
                    feed.last_update = datetime.utcnow()
                    
                except Exception as e:
                    self.logger.error(f"Error updating feed '{feed.name}': {e}", exc_info=True)
                    feed.fail_count += 1
                
                # Wait for next update
                await asyncio.sleep(feed.update_interval)
                
        except asyncio.CancelledError:
            self.logger.info(f"Update loop cancelled for '{feed.name}'")
    
    async def update_feed(self, feed: FeedConfig) -> FeedUpdateResult:
        """
        Update a single threat feed
        
        Args:
            feed: Feed configuration
            
        Returns:
            FeedUpdateResult with the outcome
        """
        self.logger.info(f"Updating feed: {feed.name} from {feed.url}")
        
        try:
            # Download feed data
            feed_data = await self._download_feed(feed.url)
            
            # Verify integrity if checksum URL provided
            if feed.checksum_url:
                is_valid = await self._verify_integrity(feed_data, feed.checksum_url)
                if not is_valid:
                    return FeedUpdateResult(
                        feed_name=feed.name,
                        success=False,
                        error="Integrity verification failed"
                    )
            
            # Validate feed format
            entries = await self._validate_feed_data(feed_data, feed.format)
            if not entries:
                return FeedUpdateResult(
                    feed_name=feed.name,
                    success=False,
                    error="No valid entries found in feed"
                )
            
            # Update threat intelligence
            entries_added = await self._apply_feed_updates(feed.name, entries)
            
            self.logger.info(
                f"✅ Successfully updated feed '{feed.name}': "
                f"{entries_added} entries added"
            )
            
            return FeedUpdateResult(
                feed_name=feed.name,
                success=True,
                entries_added=entries_added,
                metadata={
                    'total_entries': len(entries),
                    'format': feed.format
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update feed '{feed.name}': {e}", exc_info=True)
            return FeedUpdateResult(
                feed_name=feed.name,
                success=False,
                error=str(e)
            )
    
    async def _download_feed(self, url: str) -> bytes:
        """
        Download feed data from URL
        
        Args:
            url: Feed URL
            
        Returns:
            Feed data as bytes
        """
        timeout = aiohttp.ClientTimeout(total=60)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                response.raise_forstatus()
                data = await response.read()
                self.logger.debug(f"Downloaded {len(data)} bytes from {url}")
                return data
    
    async def _verify_integrity(self, data: bytes, checksum_url: str) -> bool:
        """
        Verify feed data integrity using checksum
        
        Args:
            data: Feed data
            checksum_url: URL to checksum file
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Download checksum
            checksum_data = await self._download_feed(checksum_url)
            expected_checksum = checksum_data.decode().strip().split()[0]
            
            # Calculate actual checksum
            actual_checksum = hashlib.sha256(data).hexdigest()
            
            if actual_checksum == expected_checksum:
                self.logger.debug("✅ Integrity check passed")
                return True
            else:
                self.logger.warning(
                    f"❌ Integrity check failed: expected={expected_checksum}, "
                    f"actual={actual_checksum}"
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error verifying integrity: {e}")
            return False
    
    async def _validate_feed_data(self, data: bytes, format: str) -> List[Dict]:
        """
        Validate and parse feed data
        
        Args:
            data: Feed data
            format: Feed format (json, csv, txt)
            
        Returns:
            List of validated entries
        """
        entries = []
        
        try:
            if format == 'json':
                feed_json = json.loads(data.decode())
                # Assume JSON has 'threats' or 'ips' list
                entries = feed_json.get('threats', feed_json.get('ips', []))
                
            elif format == 'txt':
                # Plain text, one IP per line
                lines = data.decode().strip().split('\n')
                entries = [
                    {'ip': line.strip(), 'type': 'malicious'}
                    for line in lines
                    if line.strip() and not line.startswith('#')
                ]
                
            elif format == 'csv':
                # Simple CSV parsing (ip,type,description)
                lines = data.decode().strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            entries.append({
                                'ip': parts[0].strip(),
                                'type': parts[1].strip(),
                                'description': parts[2].strip() if len(parts) > 2 else ''
                            })
            
            self.logger.debug(f"Parsed {len(entries)} entries from feed ({format})")
            return entries
            
        except Exception as e:
            self.logger.error(f"Error parsing feed data ({format}): {e}")
            return []
    
    async def _apply_feed_updates(self, feed_name: str, entries: List[Dict]) -> int:
        """
        Apply feed updates to threat intelligence
        
        Args:
            feed_name: Feed name
            entries: List of threat entries
            
        Returns:
            Number of entries added
        """
        added = 0
        
        for entry in entries:
            ip = entry.get('ip')
            threat_type = entry.get('type', 'malicious')
            
            if ip:
                # Add to threat intelligence
                self.threat_intel.add_threat(
                    ip=ip,
                    threat_type=threat_type,
                    source=feed_name,
                    metadata=entry
                )
                added += 1
        
        return added
    
    async def _audit_log(self, result: FeedUpdateResult):
        """
        Write audit log for feed update
        
        Args:
            result: Feed update result
        """
        try:
            # Ensure log directory exists
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            
            log_entry = {
                'timestamp': result.timestamp.isoformat(),
                'feed_name': result.feed_name,
                'success': result.success,
                'entries_added': result.entries_added,
                'entries_removed': result.entries_removed,
                'error': result.error,
                'metadata': result.metadata
            }
            
            # Append to audit log
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")
    
    async def manual_update(self, feed_name: str) -> FeedUpdateResult:
        """
        Manually trigger feed update
        
        Args:
            feed_name: Name of feed to update
            
        Returns:
            FeedUpdateResult
        """
        if feed_name not in self.feeds:
            return FeedUpdateResult(
                feed_name=feed_name,
                success=False,
                error="Feed not found"
            )
        
        feed = self.feeds[feed_name]
        return await self.update_feed(feed)
    
    def get_statistics(self) -> Dict:
        """
        Get feed updater statistics
        
        Returns:
            Statistics dictionary
        """
        feed_stats = {}
        for name, feed in self.feeds.items():
            feed_stats[name] = {
                'enabled': feed.enabled,
                'last_update': feed.last_update.isoformat() if feed.last_update else None,
                'last_success': feed.last_success.isoformat() if feed.last_success else None,
                'update_count': feed.update_count,
                'fail_count': feed.fail_count,
                'update_interval': feed.update_interval
            }
        
        return {
            **self._stats,
            'feeds': feed_stats
        }
