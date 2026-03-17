#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Base Proxy - Abstract Base Class for Proxy Modes
═══════════════════════════════════════════════════════════════════

Defines common interface and functionality for all proxy modes.

Author: Enterprise Security Team
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from modules.qos.qos_manager import QoSManager

logger = logging.getLogger(__name__)


@dataclass
class ProxyConnection:
    """Represents a proxied connection"""
    connection_id: str
    client_ip: str
    client_port: int
    target_host: str
    target_port: int
    protocol: str = "UNKNOWN"
    
    # Stream objects
    client_reader: Optional[asyncio.StreamReader] = None
    client_writer: Optional[asyncio.StreamWriter] = None
    server_reader: Optional[asyncio.StreamReader] = None
    server_writer: Optional[asyncio.StreamWriter] = None
    
    # Statistics
    start_time: datetime = None
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()


class BaseProxy(ABC):
    """
    Abstract base class for proxy implementations
    
    All proxy modes must inherit from this class and implement
    the abstract methods.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.proxy_config = config.get('proxy', {})
        
        # QoS Integration
        self.qos_manager = QoSManager(config)
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
        }
        
        # Running state
        self.running = False
        self.servers = []
        
        logger.info(f"{self.__class__.__name__} initialized")
    
    @abstractmethod
    async def start(self):
        """Start the proxy server"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the proxy server"""
        pass
    
    @abstractmethod
    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection
        
        This is the main entry point for each connection.
        Must be implemented by subclasses.
        """
        pass
    
    async def relay_data(self,
                        reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        connection: ProxyConnection,
                        direction: str):
        """
        Relay data between two streams
        
        Args:
            reader: Source stream
            writer: Destination stream
            connection: ProxyConnection object
            direction: 'client->server' or 'server->client'
        """
        try:
            buffer_size = self.proxy_config.get('buffer_size', 65536)
            
            while True:
                data = await reader.read(buffer_size)
                
                if not data:
                    break
                    
                # Throttle data delivery based on QoS policies
                if self.qos_manager:
                    await self.qos_manager.throttle(connection.client_ip, len(data))
                    
                # Update statistics
                if direction == 'client->server':
                    connection.bytes_sent += len(data)
                    self.stats['bytes_sent'] += len(data)
                else:
                    connection.bytes_received += len(data)
                    self.stats['bytes_received'] += len(data)
                
                # Write data
                writer.write(data)
                await writer.drain()
                
        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            logger.debug(f"Connection reset ({direction})")
        except Exception as e:
            logger.debug(f"Relay error ({direction}): {e}")
        finally:
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
    
    async def connect_to_upstream(self,
                                  target_host: str,
                                  target_port: int,
                                  ssl_context=None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to upstream server
        
        Args:
            target_host: Target hostname
            target_port: Target port
            ssl_context: Optional SSL context for TLS
        
        Returns:
            (reader, writer) tuple
        """
        try:
            if ssl_context:
                reader, writer = await asyncio.open_connection(
                    target_host, target_port,
                    ssl=ssl_context,
                    server_hostname=target_host
                )
            else:
                reader, writer = await asyncio.open_connection(
                    target_host, target_port
                )
            
            logger.debug(f"Connected to upstream: {target_host}:{target_port}")
            return reader, writer
            
        except Exception as e:
            logger.error(f"Failed to connect to {target_host}:{target_port}: {e}")
            raise
    
    def get_statistics(self) -> dict:
        """Get proxy statistics"""
        return {
            'total_connections': self.stats['total_connections'],
            'active_connections': self.stats['active_connections'],
            'bytes_sent': self.stats['bytes_sent'],
            'bytes_received': self.stats['bytes_received'],
        }
    
    def _generate_connection_id(self, client_addr: tuple, target_host: str, target_port: int) -> str:
        """Generate unique connection ID"""
        return f"{client_addr[0]}:{client_addr[1]}->{target_host}:{target_port}"
