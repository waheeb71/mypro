import asyncio
import logging
from typing import List, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class WAFEventDispatcher:
    """
    Manages active WebSocket connections for the WAF Live Dashboard.
    Broadcasts WAF inspection events (Blocks, Challenges, and high-risk Allows)
    to all connected clients in real-time.
    """
    
    def __init__(self):
        self._active_connections: List[WebSocket] = []
        logger.info("WAF Event Dispatcher initialized")

    async def connect(self, websocket: WebSocket):
        """Register an already-accepted WebSocket connection."""
        self._active_connections.append(websocket)
        logger.debug("Live Dashboard Client connected. Total: %d", len(self._active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)
            logger.debug("Live Dashboard Client disconnected. Total: %d", len(self._active_connections))

    async def broadcast(self, event: Dict[str, Any]):
        """Non-blocking broadcast to all connected WebSocket clients."""
        if not self._active_connections:
            return  # Nobody listening
            
        disconnected = []
        for connection in self._active_connections:
            try:
                await connection.send_json(event)
            except Exception as e:
                logger.debug("Failed sending WebSocket event: %s", e)
                disconnected.append(connection)
                
        # Clean up dead connections
        for dead in disconnected:
            self.disconnect(dead)

# Global singleton dispatcher used by the router and the inspector
waf_dispatcher = WAFEventDispatcher()
