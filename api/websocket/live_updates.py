#!/usr/bin/env python3
"""
Enterprise CyberNexus - WebSocket Real-time Updates
Live statistics, traffic monitoring, and alert notifications
"""

import asyncio
import logging
import json
from typing import Set, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

from fastapi import WebSocket, WebSocketDisconnect, Depends
from fastapi.websockets import WebSocketState
import jwt

# Import JWT config from REST API (single source of truth)
try:
    from api.rest.main import SECRET_KEY, ALGORITHM
except ImportError:
    # Fallback for standalone usage
    import os
    import secrets as _secrets
    SECRET_KEY = os.getenv("CyberNexus_SECRET_KEY", _secrets.token_hex(32))
    ALGORITHM = "HS256"

logger = logging.getLogger(__name__)


@dataclass
class LiveStats:
    """Real-time statistics"""
    timestamp: str
    packets_per_second: int
    bytes_per_second: int
    active_connections: int
    blocked_count: int
    anomaly_count: int
    top_sources: list
    top_destinations: list


@dataclass
class TrafficAlert:
    """Real-time alert"""
    timestamp: str
    severity: str  # info, warning, critical
    alert_type: str  # anomaly, attack, policy_violation
    source_ip: str
    destination_ip: str
    description: str
    confidence: float


@dataclass
class LiveTraffic:
    """Live traffic flow"""
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes: int
    packets: int
    action: str  # allow, block, throttle


class ConnectionManager:
    """
    Manage WebSocket connections and broadcasts
    
    Features:
    - Connection management
    - Room-based subscriptions
    - Broadcast to all/specific clients
    - Authentication via JWT
    """
    
    def __init__(self):
        # Active connections by client ID
        self.active_connections: Dict[str, WebSocket] = {}
        
        # Subscription rooms
        self.subscriptions: Dict[str, Set[str]] = {
            'stats': set(),       # Live statistics
            'alerts': set(),      # Alert notifications
            'traffic': set(),     # Live traffic flows
            'anomalies': set()    # Anomaly detections
        }
        
        # Client metadata
        self.client_metadata: Dict[str, Dict] = {}
        
        logger.info("ConnectionManager initialized")
    
    async def connect(
        self,
        websocket: WebSocket,
        client_id: str,
        token: Optional[str] = None
    ) -> bool:
        """
        Accept new WebSocket connection
        
        Args:
            websocket: WebSocket connection
            client_id: Unique client identifier
            token: JWT authentication token
        
        Returns:
            True if connection accepted, False otherwise
        """
        # Verify token if provided
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                role = payload.get("role", "guest")
            except jwt.JWTError as e:
                logger.warning(f"Invalid token for client {client_id}: {e}")
                return False
        else:
            username = "anonymous"
            role = "guest"
        
        await websocket.accept()
        
        self.active_connections[client_id] = websocket
        self.client_metadata[client_id] = {
            'username': username,
            'role': role,
            'connected_at': datetime.now().isoformat(),
            'subscriptions': set()
        }
        
        logger.info(f"Client {client_id} ({username}) connected")
        
        # Send welcome message
        await self.send_personal_message(
            {
                'type': 'connection',
                'status': 'connected',
                'client_id': client_id,
                'message': f'Welcome {username}!'
            },
            client_id
        )
        
        return True
    
    def disconnect(self, client_id: str):
        """Disconnect client and cleanup"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from all subscriptions
        for room in self.subscriptions.values():
            room.discard(client_id)
        
        if client_id in self.client_metadata:
            del self.client_metadata[client_id]
        
        logger.info(f"Client {client_id} disconnected")
    
    async def send_personal_message(self, message: Dict[str, Any], client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: Dict[str, Any], room: Optional[str] = None):
        """
        Broadcast message to all clients or specific room
        
        Args:
            message: Message to broadcast
            room: Optional room name (stats, alerts, traffic, anomalies)
        """
        if room and room in self.subscriptions:
            # Broadcast to room subscribers
            clients = self.subscriptions[room]
        else:
            # Broadcast to all
            clients = self.active_connections.keys()
        
        disconnected = []
        
        for client_id in clients:
            if client_id in self.active_connections:
                websocket = self.active_connections[client_id]
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
                    disconnected.append(client_id)
        
        # Cleanup disconnected clients
        for client_id in disconnected:
            self.disconnect(client_id)
    
    def subscribe(self, client_id: str, room: str) -> bool:
        """Subscribe client to a room"""
        if room not in self.subscriptions:
            logger.warning(f"Invalid room: {room}")
            return False
        
        self.subscriptions[room].add(client_id)
        
        if client_id in self.client_metadata:
            self.client_metadata[client_id]['subscriptions'].add(room)
        
        logger.info(f"Client {client_id} subscribed to {room}")
        return True
    
    def unsubscribe(self, client_id: str, room: str) -> bool:
        """Unsubscribe client from a room"""
        if room not in self.subscriptions:
            return False
        
        self.subscriptions[room].discard(client_id)
        
        if client_id in self.client_metadata:
            self.client_metadata[client_id]['subscriptions'].discard(room)
        
        logger.info(f"Client {client_id} unsubscribed from {room}")
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'total_connections': len(self.active_connections),
            'subscriptions': {
                room: len(clients)
                for room, clients in self.subscriptions.items()
            },
            'clients': [
                {
                    'client_id': client_id,
                    'username': meta['username'],
                    'role': meta['role'],
                    'subscriptions': list(meta['subscriptions'])
                }
                for client_id, meta in self.client_metadata.items()
            ]
        }


# Global connection manager
manager = ConnectionManager()


# ==================== WebSocket Handler ====================

async def handle_websocket(websocket: WebSocket, client_id: str):
    """
    Main WebSocket handler
    
    Message format:
    {
        "type": "subscribe|unsubscribe|ping|request",
        "room": "stats|alerts|traffic|anomalies",
        "data": {...}
    }
    """
    # Get token from query params
    token = websocket.query_params.get('token')
    
    # Connect client
    connected = await manager.connect(websocket, client_id, token)
    
    if not connected:
        await websocket.close(code=1008, reason="Authentication failed")
        return
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                msg_type = message.get('type')
                
                # Handle different message types
                if msg_type == 'subscribe':
                    room = message.get('room')
                    if room:
                        success = manager.subscribe(client_id, room)
                        await manager.send_personal_message(
                            {
                                'type': 'subscription',
                                'status': 'success' if success else 'failed',
                                'room': room
                            },
                            client_id
                        )
                
                elif msg_type == 'unsubscribe':
                    room = message.get('room')
                    if room:
                        success = manager.unsubscribe(client_id, room)
                        await manager.send_personal_message(
                            {
                                'type': 'unsubscription',
                                'status': 'success' if success else 'failed',
                                'room': room
                            },
                            client_id
                        )
                
                elif msg_type == 'ping':
                    await manager.send_personal_message(
                        {'type': 'pong', 'timestamp': datetime.now().isoformat()},
                        client_id
                    )
                
                elif msg_type == 'request':
                    # Handle specific data requests
                    request_type = message.get('request')
                    if request_type == 'stats':
                        await send_live_stats(client_id)
                    elif request_type == 'connections':
                        stats = manager.get_stats()
                        await manager.send_personal_message(
                            {'type': 'connections_stats', 'data': stats},
                            client_id
                        )
                
                else:
                    await manager.send_personal_message(
                        {'type': 'error', 'message': f'Unknown message type: {msg_type}'},
                        client_id
                    )
            
            except json.JSONDecodeError:
                await manager.send_personal_message(
                    {'type': 'error', 'message': 'Invalid JSON'},
                    client_id
                )
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected normally")
    
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}", exc_info=True)
        manager.disconnect(client_id)


# ==================== Broadcasting Functions ====================

async def send_live_stats(client_id: Optional[str] = None):
    """Send live statistics"""
    # Generate mock stats (replace with real data)
    stats = LiveStats(
        timestamp=datetime.now().isoformat(),
        packets_per_second=1500,
        bytes_per_second=750000,
        active_connections=250,
        blocked_count=15,
        anomaly_count=3,
        top_sources=["192.168.1.100", "192.168.1.105", "192.168.1.110"],
        top_destinations=["8.8.8.8", "1.1.1.1", "cloudflare.com"]
    )
    
    message = {
        'type': 'stats',
        'data': asdict(stats)
    }
    
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        await manager.broadcast(message, room='stats')


async def send_alert(alert: TrafficAlert):
    """Send traffic alert"""
    message = {
        'type': 'alert',
        'data': asdict(alert)
    }
    await manager.broadcast(message, room='alerts')


async def send_traffic_flow(flow: LiveTraffic):
    """Send live traffic flow"""
    message = {
        'type': 'traffic',
        'data': asdict(flow)
    }
    await manager.broadcast(message, room='traffic')


async def send_anomaly(anomaly: Dict[str, Any]):
    """Send anomaly detection"""
    message = {
        'type': 'anomaly',
        'data': anomaly
    }
    await manager.broadcast(message, room='anomalies')


# ==================== Background Tasks ====================

async def stats_broadcaster():
    """Periodically broadcast statistics"""
    while True:
        await asyncio.sleep(1)  # Update every 1 second
        
        if manager.subscriptions['stats']:
            await send_live_stats()


async def alert_monitor():
    """Monitor and broadcast alerts"""
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        
        # Check for new alerts (implement real monitoring)
        # For demo, send a test alert
        if manager.subscriptions['alerts']:
            alert = TrafficAlert(
                timestamp=datetime.now().isoformat(),
                severity='warning',
                alert_type='anomaly',
                source_ip='192.168.1.100',
                destination_ip='suspicious.example.com',
                description='Unusual traffic pattern detected',
                confidence=0.85
            )
            await send_alert(alert)


# ==================== Startup ====================

async def start_background_tasks():
    """Start background broadcasting tasks"""
    asyncio.create_task(stats_broadcaster())
    asyncio.create_task(alert_monitor())
    logger.info("Background tasks started")