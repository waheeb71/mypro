"""
Enterprise NGFW - HA Manager (Heartbeat & State Sync)

Provides Active-Passive High Availability clustering. Nodes exchange
UDP heartbeats. If the Master fails, the Backup takes over and 
applies the synchronized state.
"""

import json
import socket
import asyncio
import logging
import time
from enum import Enum
from typing import Optional, Callable
from dataclasses import dataclass, asdict

class NodeState(Enum):
    INIT = "init"
    MASTER = "master"
    BACKUP = "backup"
    FAULT = "fault"

@dataclass
class HeartbeatPayload:
    node_id: str
    state: str
    priority: int
    timestamp: float

class HAManager:
    """Manages High Availability state and heartbeats."""
    
    def __init__(self, node_id: str, priority: int = 100, bind_port: int = 54321, 
                 peer_ip: str = "127.0.0.1", logger: Optional[logging.Logger] = None):
        self.node_id = node_id
        self.priority = priority
        self.bind_port = bind_port
        self.peer_ip = peer_ip
        
        self.state: NodeState = NodeState.INIT
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.last_heartbeat_received: float = 0.0
        self.failover_timeout: float = 3.0  # seconds
        
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._on_state_change: Optional[Callable[[NodeState], None]] = None

    def set_state_change_callback(self, callback: Callable[[NodeState], None]):
        """Register a callback for when node state changes (e.g., Backup -> Master)."""
        self._on_state_change = callback

    def _change_state(self, new_state: NodeState):
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            self.logger.warning(f"🔄 HA State Transition: {old_state.value} -> {new_state.value}")
            if self._on_state_change:
                self._on_state_change(new_state)

    async def start(self):
        """Start the HA manager."""
        self._running = True
        
        # Setup UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.bind_port))
        self._sock.setblocking(False)
        
        # Initial state assumption based on priority (highest priority = init master)
        # Real VRRP would hold an election, this is simplified.
        if self.priority >= 100:
            self._change_state(NodeState.MASTER)
        else:
            self._change_state(NodeState.BACKUP)
            
        asyncio.create_task(self._send_heartbeats())
        asyncio.create_task(self._receive_heartbeats())
        asyncio.create_task(self._monitor_peer())
        
        self.logger.info(f"✅ HA Manager started (Node: {self.node_id}, Initial State: {self.state.value})")

    async def stop(self):
        """Stop the HA manager."""
        self._running = False
        if self._sock:
            self._sock.close()
        self.logger.info("🛑 HA Manager stopped")

    async def _send_heartbeats(self):
        """Periodically broadcast state to peer."""
        while self._running:
            if self.state == NodeState.MASTER:
                payload = HeartbeatPayload(
                    node_id=self.node_id,
                    state=self.state.value,
                    priority=self.priority,
                    timestamp=time.time()
                )
                data = json.dumps(asdict(payload)).encode('utf-8')
                try:
                    # UDP Send to peer
                    loop = asyncio.get_running_loop()
                    await loop.sock_sendto(self._sock, data, (self.peer_ip, self.bind_port))
                except Exception as e:
                    self.logger.debug(f"Failed to send heartbeat: {e}")
                    
            await asyncio.sleep(1.0) # 1 second heartbeats

    async def _receive_heartbeats(self):
        """Listen for peer heartbeats."""
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 1024)
                if addr[0] == self.peer_ip:
                    payload = json.loads(data.decode('utf-8'))
                    self.last_heartbeat_received = time.time()
                    
                    # If we are MASTER and see another MASTER with higher priority, step down
                    if payload['state'] == NodeState.MASTER.value and self.state == NodeState.MASTER:
                        if payload['priority'] > self.priority:
                            self.logger.warning("Peer is MASTER with higher priority. Stepping down.")
                            self._change_state(NodeState.BACKUP)
                            
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Error receiving heartbeat: {e}")
                await asyncio.sleep(1)

    async def _monitor_peer(self):
        """Monitor if the master peer has timed out."""
        while self._running:
            if self.state == NodeState.BACKUP:
                now = time.time()
                
                # If we haven't received a heartbeat in X seconds AND we've lived long enough to expect one
                if self.last_heartbeat_received > 0 and (now - self.last_heartbeat_received) > self.failover_timeout:
                    self.logger.critical(f"🚨 MASTER NODE DEAD (No heartbeat for {self.failover_timeout}s). Initiating Failover!")
                    self._change_state(NodeState.MASTER)
                    
            await asyncio.sleep(0.5)
