#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Flow Tracker - Connection State Management
═══════════════════════════════════════════════════════════════════

Tracks active connections and sessions:
- Connection state (NEW, ESTABLISHED, CLOSING, CLOSED)
- Bandwidth tracking per flow
- Connection duration
- Application identification
- User association (with authentication)

Author: Enterprise Security Team
"""

import asyncio
import logging
from typing import Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection state"""
    NEW = "new"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class FlowInfo:
    """Information about a network flow"""
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    state: ConnectionState
    
    # Timestamps
    start_time: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    # Traffic statistics
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    
    # Application info
    application: Optional[str] = None
    category: Optional[str] = None
    
    # User info (from authentication)
    username: Optional[str] = None
    user_groups: list = field(default_factory=list)
    
    # Policy info
    policy_id: Optional[str] = None
    policy_action: Optional[str] = None
    
    # Metadata
    metadata: dict = field(default_factory=dict)
    
    def update_traffic(self, sent: int = 0, received: int = 0):
        """Update traffic counters"""
        self.bytes_sent += sent
        self.bytes_received += received
        if sent > 0:
            self.packets_sent += 1
        if received > 0:
            self.packets_received += 1
        self.last_seen = datetime.now()
    
    def duration(self) -> float:
        """Get connection duration in seconds"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/export"""
        return {
            'flow_id': self.flow_id,
            'client': f"{self.client_ip}:{self.client_port}",
            'server': f"{self.server_ip}:{self.server_port}",
            'protocol': self.protocol,
            'state': self.state.value,
            'start_time': self.start_time.isoformat(),
            'duration': self.duration(),
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'application': self.application,
            'category': self.category,
            'username': self.username,
            'policy_id': self.policy_id,
        }


class FlowTracker:
    """
    Flow Tracker
    
    Tracks all active connections and maintains flow state.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.flow_config = config.get('flow_tracking', {})
        
        # Active flows
        self.flows: Dict[str, FlowInfo] = {}
        
        # Configuration
        self.max_flows = self.flow_config.get('max_flows', 100000)
        self.flow_timeout = self.flow_config.get('flow_timeout', 3600)
        
        # Statistics
        self.stats = {
            'total_flows': 0,
            'active_flows': 0,
            'closed_flows': 0,
        }
        
        # Cleanup task
        self.cleanup_task = None
        
        # AI Analytics (Layer 6)
        self.uba = None
        self.vulnerability_predictor = None
        
        # High Availability State Sync
        self.state_sync = None

        # XDP Engine for immediate AI-driven blocking
        self.xdp_engine = None
        # Read auto_block setting — default True (block immediately on AI anomaly)
        ai_cfg = config.get('ai_enforcement', {})
        self.auto_block_enabled = ai_cfg.get('auto_block', True)
        self.anomaly_block_threshold = ai_cfg.get('anomaly_threshold', 0.8)
        
        logger.info(
            f"Flow Tracker initialized (max_flows={self.max_flows}, "
            f"ai_auto_block={'ON' if self.auto_block_enabled else 'OFF'}, "
            f"threshold={self.anomaly_block_threshold})"
        )
        
    def set_sync_manager(self, state_sync):
        """Inject HA State Synchronizer"""
        self.state_sync = state_sync
        logger.info("🔄 HA State Sync linked to Flow Tracker")

    def set_xdp_engine(self, xdp_engine) -> None:
        """Inject XDP Engine for AI-driven kernel-level blocking"""
        self.xdp_engine = xdp_engine
        status = 'AUTO-BLOCK ON' if self.auto_block_enabled else 'monitor-only'
        logger.info(f"⚡ XDP Engine linked to Flow Tracker ({status})")
        
    def set_analytics(self, uba, vulnerability_predictor):
        """Inject AI analytics engines after initialization"""
        self.uba = uba
        self.vulnerability_predictor = vulnerability_predictor
        logger.info("🧠 AI Analytics (UBA & Vulnerability) wired into Flow Tracker")
    
    async def start(self):
        """Start flow tracker"""
        # Start periodic cleanup
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Flow Tracker started")
    
    async def stop(self):
        """Stop flow tracker"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Flow Tracker stopped")
    
    def create_flow(self,
                   client_ip: str,
                   client_port: int,
                   server_ip: str,
                   server_port: int,
                   protocol: str = "TCP") -> FlowInfo:
        """
        Create new flow
        
        Args:
            client_ip: Client IP address
            client_port: Client port
            server_ip: Server IP address
            server_port: Server port
            protocol: Protocol (TCP/UDP)
        
        Returns:
            FlowInfo object
        """
        # Generate flow ID
        flow_id = self._generate_flow_id(
            client_ip, client_port, server_ip, server_port, protocol
        )
        
        # Check if flow already exists
        if flow_id in self.flows:
            logger.debug(f"Flow {flow_id} already exists")
            return self.flows[flow_id]
        
        # Check flow limit
        if len(self.flows) >= self.max_flows:
            logger.warning(f"Flow limit reached ({self.max_flows}), cleaning up...")
            self._cleanup_old_flows(force=True)
        
        # Create flow
        flow = FlowInfo(
            flow_id=flow_id,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            protocol=protocol,
            state=ConnectionState.NEW,
        )
        
        self.flows[flow_id] = flow
        self.stats['total_flows'] += 1
        self.stats['active_flows'] += 1
        
        # 🧠 Predict vulnerabilities automatically when a new connection hits a target
        if self.vulnerability_predictor and server_ip and server_port:
            self.vulnerability_predictor.update_asset_profile(server_ip, open_ports=[server_port])
            # Pass a basic intensity score based on active connections
            score = self.vulnerability_predictor.predict_vulnerability(server_ip, scan_intensity=0.1)
            if score.risk_score > 70.0:
                logger.warning(f"🚨 Vulnerability Risk High for {server_ip}: {score.risk_score}%")
                
        # 🔄 HA Sync: Broadcast the new flow to the backup node (fire and forget)
        if self.state_sync and self.state_sync.is_master:
            asyncio.create_task(self.state_sync.broadcast_flow_state({
                'flow_id': flow.flow_id,
                'client_ip': flow.client_ip,
                'client_port': flow.client_port,
                'server_ip': flow.server_ip,
                'server_port': flow.server_port,
                'protocol': flow.protocol,
                'application': flow.application,
                'start_time': flow.start_time.isoformat(),
            }))
                
        logger.debug(f"Created flow: {flow_id}")
        
        return flow
    
    def get_flow(self, flow_id: str) -> Optional[FlowInfo]:
        """Get flow by ID"""
        return self.flows.get(flow_id)
    
    def update_flow_policy(self, flow_id: str, action: str):
        """Update policy action applied to flow"""
        flow = self.flows.get(flow_id)
        if flow:
            flow.policy_action = action
            from datetime import datetime
            flow.last_seen = datetime.utcnow()
            
    def handle_synced_flow(self, flow_data: dict):
        """Handle a flow synchronized from the HA Master node"""
        if flow_data['flow_id'] in self.flows:
            return  # Already tracked
            
        from datetime import datetime
        flow = FlowInfo( # Corrected: Should be FlowInfo, not ConnectionState
            flow_id=flow_data['flow_id'],
            client_ip=flow_data['client_ip'],
            client_port=flow_data['client_port'],
            server_ip=flow_data['server_ip'],
            server_port=flow_data['server_port'],
            protocol=flow_data['protocol'],
            application=flow_data.get('application'),
            state=ConnectionState.ESTABLISHED # Assuming synced flows are established
        )
        # Parse the timestamp safely
        try:
            flow.start_time = datetime.fromisoformat(flow_data['start_time'])
            flow.last_seen = flow.start_time
        except Exception:
            flow.start_time = datetime.utcnow()
            flow.last_seen = datetime.utcnow()
            
        self.flows[flow.flow_id] = flow
        self.stats['total_flows'] += 1
        self.stats['active_flows'] += 1
        logger.debug(f"🔄 Imported synced HA flow: {flow.flow_id}")
            
    def update_flow_state(self, flow_id: str, state: ConnectionState):
        """Update flow state"""
        flow = self.flows.get(flow_id)
        if flow:
            flow.state = state
            flow.last_seen = datetime.now()
            
            if state == ConnectionState.CLOSED:
                flow.end_time = datetime.now()
                self.stats['active_flows'] -= 1
                self.stats['closed_flows'] += 1
    
    def update_flow_traffic(self, flow_id: str, sent: int = 0, received: int = 0):
        """Update flow traffic statistics"""
        flow = self.flows.get(flow_id)
        if flow:
            flow.update_traffic(sent, received)
            
            # 🧠 Feed traffic data into User Behavior Analytics
            if self.uba and flow.username:
                anomaly_score = self.uba.analyze_activity(
                    username=flow.username,
                    source_ip=flow.client_ip,
                    target_service=str(flow.server_port),
                    bytes_transferred=sent + received
                )
                if anomaly_score > self.anomaly_block_threshold:
                    logger.warning(
                        f"🕵️ Anomalous behavior detected for user {flow.username} "
                        f"from {flow.client_ip} (Score: {anomaly_score:.2f})"
                    )
                    if self.auto_block_enabled and self.xdp_engine:
                        asyncio.create_task(
                            self.xdp_engine.add_blocked_ip(flow.client_ip)
                        )
                        logger.warning(
                            f"🚫 AI Auto-Block: {flow.client_ip} sent to XDP kernel blocklist"
                        )
                    elif not self.auto_block_enabled:
                        logger.info(
                            f"ℹ️ AI Auto-Block DISABLED — {flow.client_ip} flagged but not blocked "
                            f"(set ai_enforcement.auto_block: true to enable)"
                        )
    
    def update_flow_application(self, flow_id: str, app: str, category: str = None):
        """Update flow application identification"""
        flow = self.flows.get(flow_id)
        if flow:
            flow.application = app
            flow.category = category
            logger.debug(f"Flow {flow_id} identified as {app}")
    
    def update_flow_user(self, flow_id: str, username: str, groups: list = None):
        """Associate user with flow (from authentication)"""
        flow = self.flows.get(flow_id)
        if flow:
            flow.username = username
            flow.user_groups = groups or []
            logger.debug(f"Flow {flow_id} associated with user {username}")
    
    def close_flow(self, flow_id: str):
        """Close flow"""
        self.update_flow_state(flow_id, ConnectionState.CLOSED)
        
        # Optionally export flow to logging/SIEM
        flow = self.flows.get(flow_id)
        if flow:
            logger.info(f"Flow closed: {flow.to_dict()}")
    
    def _generate_flow_id(self,
                         client_ip: str,
                         client_port: int,
                         server_ip: str,
                         server_port: int,
                         protocol: str) -> str:
        """Generate unique flow ID"""
        # Use hash of 5-tuple
        flow_tuple = f"{client_ip}:{client_port}->{server_ip}:{server_port}/{protocol}"
        flow_hash = hashlib.sha256(flow_tuple.encode()).hexdigest()[:16]
        return flow_hash
    
    def _cleanup_old_flows(self, force: bool = False):
        """Cleanup old closed flows"""
        now = datetime.now()
        to_remove = []
        
        for flow_id, flow in self.flows.items():
            # Remove closed flows older than timeout
            if flow.state == ConnectionState.CLOSED:
                if flow.end_time:
                    age = (now - flow.end_time).total_seconds()
                    if age > self.flow_timeout or force:
                        to_remove.append(flow_id)
        
        # Remove flows
        for flow_id in to_remove:
            del self.flows[flow_id]
        
        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} old flows")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of old flows"""
        try:
            while True:
                await asyncio.sleep(60)  # Run every minute
                self._cleanup_old_flows()
        except asyncio.CancelledError:
            logger.debug("Cleanup loop cancelled")
    
    def get_statistics(self) -> dict:
        """Get flow statistics"""
        return {
            'total_flows': self.stats['total_flows'],
            'active_flows': self.stats['active_flows'],
            'closed_flows': self.stats['closed_flows'],
            'current_tracked': len(self.flows),
        }
    
    def get_active_flows(self, limit: int = 100) -> list:
        """Get list of active flows"""
        active = [
            flow.to_dict() 
            for flow in self.flows.values() 
            if flow.state in [ConnectionState.NEW, ConnectionState.ESTABLISHED]
        ]
        return active[:limit]
