#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Forward Proxy - Explicit Proxy Mode
═══════════════════════════════════════════════════════════════════

Forward proxy mode where clients explicitly configure proxy settings.
Supports:
- HTTP CONNECT method
- SOCKS5 protocol (future)
- Proxy authentication
- PAC (Proxy Auto-Configuration) files

Author: Enterprise Security Team
"""
import asyncio
import logging
from typing import Optional, Tuple
from .base_proxy import BaseProxy, ProxyConnection

logger = logging.getLogger(__name__)
class ForwardProxy(BaseProxy):
    """
    Forward Proxy Implementation
    Clients explicitly configure proxy settings to use this proxy.
    """
    def __init__(self, config: dict, ca_manager, flow_tracker=None, event_sink=None):
        super().__init__(config)
        self.ca_manager = ca_manager
        self.flow_tracker = flow_tracker
        self.event_sink = event_sink
        
        self.listen_host = self.proxy_config.get('forward_listen_host', '0.0.0.0')
        self.listen_port = self.proxy_config.get('forward_listen_port', 8080)
        
        logger.info(f"Forward Proxy configured on {self.listen_host}:{self.listen_port}")
    
    async def start(self):
        """Start forward proxy server"""
        logger.info("Starting Forward Proxy...")
        self.running = True
        
        server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port
        )
        self.servers.append(server)
        
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"📡 Forward Proxy listening on {addrs}")
        async with server:
            await server.serve_forever()
    
    async def stop(self):
        """Stop forward proxy server"""
        logger.info("Stopping Forward Proxy...")
        self.running = False
        
        for server in self.servers:
            server.close()
            await server.wait_closed()
        
        logger.info("Forward Proxy stopped")
    
    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection
        
        Expects HTTP CONNECT or regular HTTP request
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"Forward proxy connection from {client_addr}")
        
        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1
        
        try:
            # Read first line to determine request type
            first_line = await asyncio.wait_for(
                client_reader.readline(),
                timeout=10.0
            )
            
            if not first_line:
                return
            
            # Parse request
            line = first_line.decode('latin-1').strip()
            parts = line.split()
            
            if len(parts) < 2:
                logger.warning(f"Invalid request from {client_addr}")
                return
            
            method = parts[0]
            target = parts[1]
            
            # Handle CONNECT method (for HTTPS)
            if method == 'CONNECT':
                await self._handle_connect(
                    client_reader, client_writer,
                    target, client_addr
                )
            else:
                # Handle regular HTTP request
                await self._handle_http(
                    client_reader, client_writer,
                    first_line, method, target, client_addr
                )
                
        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout from {client_addr}")
        except Exception as e:
            logger.error(f"Error handling forward proxy connection: {e}", exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def _handle_connect(self,
                             client_reader: asyncio.StreamReader,
                             client_writer: asyncio.StreamWriter,
                             target: str,
                             client_addr: tuple):
        """
        Handle HTTP CONNECT method
        
        This creates a tunnel for HTTPS traffic
        """
        try:
            # Parse target (host:port)
            target_parts = target.split(':')
            target_host = target_parts[0]
            target_port = int(target_parts[1]) if len(target_parts) > 1 else 443
            
            logger.info(f"🔐 CONNECT {target_host}:{target_port} from {client_addr[0]}")
            
            # Read and discard remaining headers
            while True:
                line = await client_reader.readline()
                if line == b'\r\n' or line == b'\n' or not line:
                    break
            
            # Send 200 Connection Established
            response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            client_writer.write(response)
            await client_writer.drain()
            
            # Now we can perform SSL interception or just relay
            # For now, let's just relay without inspection
            # (SSL inspection will be added later)
            await self._relay_tunnel(
                client_reader, client_writer,
                target_host, target_port, client_addr
            )
            
        except Exception as e:
            logger.error(f"Error in CONNECT handler: {e}", exc_info=True)
    
    async def _handle_http(self,
                          client_reader: asyncio.StreamReader,
                          client_writer: asyncio.StreamWriter,
                          first_line: bytes,
                          method: str,
                          url: str,
                          client_addr: tuple):
        """
        Handle regular HTTP request (non-CONNECT)
        """
        try:
            # Parse URL to extract host
            if url.startswith('http://'):
                url = url[7:]
            
            # Extract host and path
            if '/' in url:
                host_part, path = url.split('/', 1)
                path = '/' + path
            else:
                host_part = url
                path = '/'
            
            # Extract host and port
            if ':' in host_part:
                target_host, port_str = host_part.split(':', 1)
                target_port = int(port_str)
            else:
                target_host = host_part
                target_port = 80
            
            logger.info(f"📄 HTTP {method} {target_host}{path} from {client_addr[0]}")
            
            # Connect to upstream
            server_reader, server_writer = await self.connect_to_upstream(
                target_host, target_port
            )
            
            # Forward request
            # Reconstruct request without full URL
            new_first_line = f"{method} {path} HTTP/1.1\r\n".encode()
            server_writer.write(new_first_line)
            
            # Forward remaining headers
            while True:
                line = await client_reader.readline()
                server_writer.write(line)
                if line == b'\r\n' or line == b'\n' or not line:
                    break
            
            await server_writer.drain()
            
            # Create connection object for tracking
            conn_id = self._generate_connection_id(client_addr, target_host, target_port)
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port,
                protocol="HTTP",
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer
            )
            
            # Relay data bidirectionally
            await asyncio.gather(
                self.relay_data(client_reader, server_writer, connection, 'client->server'),
                self.relay_data(server_reader, client_writer, connection, 'server->client'),
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"Error in HTTP handler: {e}", exc_info=True)
    
    async def _relay_tunnel(self,
                           client_reader: asyncio.StreamReader,
                           client_writer: asyncio.StreamWriter,
                           target_host: str,
                           target_port: int,
                           client_addr: tuple):
        """
        Relay data through tunnel without inspection
        """
        server_reader = None
        server_writer = None
        
        try:
            # Connect to upstream
            server_reader, server_writer = await self.connect_to_upstream(
                target_host, target_port
            )
            
            # Create connection object
            conn_id = self._generate_connection_id(client_addr, target_host, target_port)
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port,
                protocol="HTTPS",
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer
            )
            
            # Relay data bidirectionally
            logger.info(f"🔄 Tunneling: {client_addr[0]} ↔ {target_host}:{target_port}")
            
            await asyncio.gather(
                self.relay_data(client_reader, server_writer, connection, 'client->server'),
                self.relay_data(server_reader, client_writer, connection, 'server->client'),
                return_exceptions=True
            )
            
            logger.info(f"✅ Tunnel closed: {target_host} (↑{connection.bytes_sent}B ↓{connection.bytes_received}B)")
            
        except Exception as e:
            logger.error(f"Error in tunnel relay: {e}", exc_info=True)
        finally:
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()
