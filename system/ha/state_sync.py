"""
Enterprise NGFW - HA State Synchronizer

Mirrors state (like new active connections, updated database rules)
from the MASTER node to the BACKUP node to ensure a seamless failover.
"""

import json
import asyncio
import logging
from typing import Optional, Dict

class StateSynchronizer:
    """Synchronizes state data from MASTER to BACKUP nodes."""
    
    def __init__(self, port: int = 54322, peer_ip: str = "127.0.0.1", 
                 logger: Optional[logging.Logger] = None):
        self.port = port
        self.peer_ip = peer_ip
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.is_master = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        
        # Callbacks to update local state when receiving data
        self.flow_tracker_update_cb = None
        
    def set_flow_callback(self, cb):
        self.flow_tracker_update_cb = cb

    async def start(self, initial_is_master: bool):
        """Start the synchronization service."""
        self._running = True
        self.is_master = initial_is_master
        
        if not self.is_master:
            # If we are backup, listen for state updates
            await self._start_listener()
            
        self.logger.info(f"✅ HA State Synchronizer started (Is Master: {self.is_master})")

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.logger.info("🛑 HA State Synchronizer stopped")

    def on_state_change(self, is_master: bool):
        """Handle HA state change."""
        self.is_master = is_master
        if not self.is_master and not self._server:
            asyncio.create_task(self._start_listener())
        elif self.is_master and self._server:
            self._server.close()
            self._server = None

    async def _start_listener(self):
        """Listen for state updates from the MASTER."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client, '0.0.0.0', self.port
            )
            self.logger.info(f"HA Sync Listener bound to 0.0.0.0:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start HA Sync listener: {e}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming state data from MASTER."""
        try:
            while self._running and not self.is_master:
                data = await reader.read(4096)
                if not data:
                    break
                    
                payload = json.loads(data.decode('utf-8'))
                
                # Apply synchronized state
                if payload.get('type') == 'flow_update' and self.flow_tracker_update_cb:
                    self.flow_tracker_update_cb(payload.get('data'))
                    
        except Exception as e:
            self.logger.debug(f"Error handling sync client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def broadcast_flow_state(self, flow_data: Dict):
        """Called by MASTER to push flow changes to BACKUP."""
        if not self.is_master or not self._running:
            return
            
        payload = json.dumps({
            'type': 'flow_update',
            'data': flow_data
        }).encode('utf-8')
        
        try:
            reader, writer = await asyncio.open_connection(self.peer_ip, self.port)
            writer.write(payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            # It's expected to fail if peer is down or not ready
            pass
