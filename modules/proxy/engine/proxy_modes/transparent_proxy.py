# Migrated from original MITM Proxy implementation
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise NGFW - Transparent Proxy Mode
═══════════════════════════════════════════════════════════════════

High-performance asyncio-based MITM proxy with TLS interception,
eBPF acceleration, and enterprise-grade security features.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
import ssl
import socket
import struct
from typing import Optional, Tuple, Dict
from dataclasses import dataclass
from datetime import datetime
import re
from modules.ssl_inspection.engine.ca_pool import CAPoolManager
# Inspection
from system.inspection_core.framework.pipeline import InspectionPipeline, InspectionContext, InspectionAction
logger = logging.getLogger(__name__)
@dataclass
class ConnectionStats:
    """Connection statistics"""
    client_ip: str
    client_port: int
    target_host: str
    target_port: int
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: datetime = None
    end_time: Optional[datetime] = None
    
    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()


class TLSInterceptor:
    """
    TLS/HTTPS Interceptor
    
    Handles SSL/TLS handshake interception, certificate generation,
    and bidirectional encrypted data relay.
    """
    
    def __init__(self, ca_manager: CAPoolManager, config: dict):
        self.ca_manager = ca_manager
        self.config = config
        self.tls_config = config.get('tls', {})
        
        # Create SSL context for upstream connections
        self.upstream_ssl_context = self._create_upstream_ssl_context()
    
    def _create_upstream_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for connecting to real servers"""
        context = ssl.create_default_context()
        
        # Configure TLS version
        min_version = self.tls_config.get('min_tls_version', 'TLSv1.2')
        max_version = self.tls_config.get('max_tls_version', 'TLSv1.3')
        
        if min_version == 'TLSv1.2':
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif min_version == 'TLSv1.3':
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        if max_version == 'TLSv1.3':
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        elif max_version == 'TLSv1.2':
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        
        # Set cipher suites
        cipher_suites = self.tls_config.get('cipher_suites', [])
        if cipher_suites:
            context.set_ciphers(':'.join(cipher_suites))
        
        # ALPN protocols
        alpn_protocols = self.tls_config.get('alpn_protocols', ['h2', 'http/1.1'])
        context.set_alpn_protocols(alpn_protocols)
        
        # Certificate validation
        if self.config.get('security', {}).get('strict_cert_validation', True):
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    def create_client_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """
        Create SSL context for client connection with dynamically generated certificate
        
        Args:
            hostname: Target hostname for certificate generation
        
        Returns:
            SSL context with MITM certificate
        """
        if self.config["proxy"].get("mode") == "reverse_proxy":
            logger.info(f"Reverse proxy mode active - using server cert for {hostname}")
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # Load server certificate (not CA)
            context.load_cert_chain(
                certfile=self.tls_config.get("server_cert"),
                keyfile=self.tls_config.get("server_key")
            )
            # Optionally load chain for clients / OCSP stapling
            if self.tls_config.get("cert_chain"):
                context.load_verify_locations(self.tls_config.get("cert_chain"))
            # ALPN / protocol versions same as before
            context.set_alpn_protocols(self.tls_config.get('alpn_protocols', ['h2', 'http/1.1']))
            if self.tls_config.get('min_tls_version', 'TLSv1.2') == 'TLSv1.2':
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            return context
        # Generate certificate for this hostname
        cert_pem, key_pem = self.ca_manager.generate_server_certificate(hostname)
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load generated certificate
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
            cert_file.write(cert_pem)
            cert_file.write(key_pem)
            cert_file.flush()
            
            context.load_cert_chain(cert_file.name)
        
        # Configure TLS version
        min_version = self.tls_config.get('min_tls_version', 'TLSv1.2')
        if min_version == 'TLSv1.2':
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif min_version == 'TLSv1.3':
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Set cipher suites
        cipher_suites = self.tls_config.get('cipher_suites', [])
        if cipher_suites:
            context.set_ciphers(':'.join(cipher_suites))
        
        # ALPN protocols
        alpn_protocols = self.tls_config.get('alpn_protocols', ['h2', 'http/1.1'])
        context.set_alpn_protocols(alpn_protocols)
        
        return context


class MITMProxy:
    """
    Main MITM Proxy Server
    
    Handles incoming connections, performs TLS interception,
    and relays traffic between client and upstream server.
    """
    
    def __init__(self, config: dict, ca_manager: CAPoolManager, ebpf_manager=None, event_sink=None, inspection_pipeline: Optional[InspectionPipeline] = None):
        self.config = config
        self.ca_manager = ca_manager
        self.ebpf_manager = ebpf_manager
        self.event_sink = event_sink
        self.inspection_pipeline = inspection_pipeline
        
        self.proxy_config = config.get('proxy', {})
        self.security_config = config.get('security', {})
        
        self.listen_host = self.proxy_config.get('listen_host', '0.0.0.0')
        self.listen_port = self.proxy_config.get('listen_port', 8443)
        self.http_port = self.proxy_config.get('http_port', 8080)
        
        self.tls_interceptor = TLSInterceptor(ca_manager, config)
        self.server_ssl_context = None
        if self.config.get('proxy', {}).get('mode') == 'reverse_proxy':
            # Use server cert to terminate TLS at proxy
            self.server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls = self.config.get('tls', {})
            self.server_ssl_context.load_cert_chain(tls.get('server_cert'), tls.get('server_key'))
            if tls.get('cert_chain'):
                self.server_ssl_context.load_verify_locations(tls.get('cert_chain'))
            self.server_ssl_context.set_alpn_protocols(tls.get('alpn_protocols', ['h2', 'http/1.1']))

        # Statistics
        self.stats: Dict[str, ConnectionStats] = {}
        self.total_connections = 0
        self.active_connections = 0
        
        # Running state
        self.running = False
        self.servers = []
    
    async def start(self):
        """Start proxy servers"""
        logger.info("Starting Enterprise MITM Proxy...")
        self.running = True
        
        # Start HTTPS proxy
        https_server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
            ssl=self.server_ssl_context 
        )
        self.servers.append(https_server)
        
        addrs = ', '.join(str(sock.getsockname()) for sock in https_server.sockets)
        logger.info(f"🔒 HTTPS Proxy listening on {addrs}")
        
        # Start HTTP proxy
        http_server = await asyncio.start_server(
            self.handle_http_connection,
            self.listen_host,
            self.http_port
        )
        self.servers.append(http_server)
        
        addrs = ', '.join(str(sock.getsockname()) for sock in http_server.sockets)
        logger.info(f" HTTP Proxy listening on {addrs}")
        
        logger.info("✅ Enterprise MITM Proxy started successfully")
        logger.info(f" Max connections: {self.proxy_config.get('max_connections', 10000)}")
        
        # Serve forever
        async with https_server, http_server:
            await asyncio.gather(
                https_server.serve_forever(),
                http_server.serve_forever()
            )
    
    async def stop(self):
        """Stop proxy servers"""
        logger.info("Stopping proxy servers...")
        self.running = False
        
        for server in self.servers:
            server.close()
            await server.wait_closed()
        
        logger.info("Proxy servers stopped")
    
    # Linux kernel constant for retrieving original destination from iptables REDIRECT
    SO_ORIGINAL_DST = 80
    
    def _get_original_dst(self, sock_wrapper) -> Tuple[Optional[str], int]:
        """
        Get the original destination IP:port from iptables REDIRECT.
        
        When iptables PREROUTING redirects traffic (e.g., port 443 → 8443),
        the original destination is stored in the socket and can be retrieved
        via getsockopt(SOL_IP, SO_ORIGINAL_DST).
        
        This is the standard technique used by transparent proxies
        (mitmproxy, squid, etc.) on Linux.
        """
        try:
            # Returns struct sockaddr_in (16 bytes):
            # family(2) + port(2, network order) + addr(4) + zero(8)
            dst = sock_wrapper.getsockopt(socket.SOL_IP, self.SO_ORIGINAL_DST, 16)
            port = struct.unpack('!H', dst[2:4])[0]
            addr = socket.inet_ntoa(dst[4:8])
            
            # Avoid looping back to ourselves
            if addr in ('127.0.0.1', '0.0.0.0'):
                return None, 0
                
            logger.debug(f"SO_ORIGINAL_DST: {addr}:{port}")
            return addr, port
        except Exception as e:
            logger.debug(f"SO_ORIGINAL_DST failed: {e}")
            return None, 0
    
    async def handle_connection(self, client_reader: asyncio.StreamReader,
                                 client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection (HTTPS)
        
        Target extraction strategy (in order):
        1. SNI peek (MSG_PEEK) — for domain-based HTTPS (e.g., https://example.com)
        2. SO_ORIGINAL_DST — for IP-based HTTPS via iptables REDIRECT (e.g., https://192.168.20.2)
        3. Stream read fallback — for HTTP CONNECT tunnels
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"New connection from {client_addr}")
        
        self.total_connections += 1
        self.active_connections += 1
        
        try:
            # ===== CRITICAL: Pause transport BEFORE any await =====
            # This prevents asyncio from consuming the TLS ClientHello
            # from the OS socket buffer. start_tls() needs it intact.
            transport = client_writer.transport
            transport.pause_reading()
            
            target_host = None
            target_port = 443
            
            sock_wrapper = transport.get_extra_info('socket')
            
            # --- Strategy 1: SNI Peek (for domain-based connections) ---
            if sock_wrapper is not None:
                try:
                    fd = sock_wrapper.fileno()
                    dup_sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        peek_data = dup_sock.recv(4096, socket.MSG_PEEK)
                        if peek_data and len(peek_data) > 5 and peek_data[0] == 0x16:
                            target_host = self._parse_sni_from_client_hello(peek_data)
                            if target_host:
                                logger.info(f"🔍 SNI: {target_host}")
                    finally:
                        dup_sock.close()
                except Exception as e:
                    logger.debug(f"SNI peek failed: {e}")
            
            # --- Strategy 2: SO_ORIGINAL_DST (for iptables REDIRECT) ---
            if not target_host and sock_wrapper is not None:
                orig_addr, orig_port = self._get_original_dst(sock_wrapper)
                if orig_addr:
                    target_host = orig_addr
                    target_port = orig_port
                    logger.info(f"🔍 Original destination (iptables): {target_host}:{target_port}")
            
            # --- Strategy 3: Stream read fallback (CONNECT method) ---
            if not target_host:
                transport.resume_reading()
                target_host, target_port = await self._extract_target(client_reader)
            
            if not target_host:
                transport.resume_reading()
                logger.warning(f"Could not extract target from {client_addr}")
                return
            
            logger.info(f"🎯 {client_addr[0]} → {target_host}:{target_port}")
            
            # Check security policies
            if not self._check_security_policy(client_addr[0], target_host):
                logger.warning(f"🚫 Blocked by security policy: {client_addr[0]} → {target_host}")
                transport.resume_reading()
                client_writer.close()
                await client_writer.wait_closed()
                return
            
            # Perform MITM interception
            await self._perform_mitm(
                client_reader, client_writer,
                target_host, target_port,
                client_addr
            )
            
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}", exc_info=True)
        finally:
            self.active_connections -= 1
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def handle_http_connection(self, client_reader: asyncio.StreamReader,
                                      client_writer: asyncio.StreamWriter):
        """Handle HTTP (non-TLS) connections"""
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"New HTTP connection from {client_addr}")
        
        try:
            # Read HTTP request
            request_line = await client_reader.readline()
            if not request_line:
                return
            
            # Parse HTTP request
            parts = request_line.decode('latin-1').strip().split()
            if len(parts) < 2:
                return
            
            method = parts[0]
            url = parts[1]
            
            # Handle CONNECT method (for HTTPS tunneling)
            if method == 'CONNECT':
                # Extract host:port
                target = url.split(':')
                target_host = target[0]
                target_port = int(target[1]) if len(target) > 1 else 443
                
                logger.info(f"🔐 CONNECT {target_host}:{target_port} from {client_addr[0]}")
                
                # Send 200 Connection Established
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
                
                # Now perform MITM on this connection
                await self._perform_mitm(
                    client_reader, client_writer,
                    target_host, target_port,
                    client_addr
                )
            else:
                # Regular HTTP request (not CONNECT)
                logger.info(f"📄 HTTP {method} {url} from {client_addr[0]}")
                
                # For now, just relay without interception
                # (Content inspection can be added here later)
                await self._relay_http(client_reader, client_writer, request_line)
        
        except Exception as e:
            logger.error(f"Error handling HTTP connection: {e}", exc_info=True)
        finally:
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def _perform_reverse_proxy(self, client_reader, client_writer, target_host, target_port):
        """
        Relay between client and backend in reverse proxy mode.
        TLS already terminated at server side. Backend connection may use TLS.
        """
        upstream_reader = upstream_writer = None
        try:
            backend = self.config.get('backend', {})
            use_tls = backend.get('use_tls', True)
            backend_host = backend.get('target_host', target_host)
            backend_port = backend.get('target_port', target_port)

            if use_tls:
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    backend_host, backend_port,
                    ssl=self.tls_interceptor.upstream_ssl_context,
                    server_hostname=backend_host
                )
            else:
                upstream_reader, upstream_writer = await asyncio.open_connection(backend_host, backend_port)

            # Relay bidirectionally
            stats = ConnectionStats(
                client_ip=client_writer.get_extra_info('peername')[0],
                client_port=client_writer.get_extra_info('peername')[1],
                target_host=backend_host,
                target_port=backend_port
            )
            conn_id = f"{stats.client_ip}:{stats.client_port}->{backend_host}:{backend_port}"
            self.stats[conn_id] = stats

            await asyncio.gather(
                self._relay_data(client_reader, upstream_writer, stats, 'client->server'),
                self._relay_data(upstream_reader, client_writer, stats, 'server->client'),
                return_exceptions=True
            )

        except Exception as e:
            logger.error(f"Reverse proxy error: {e}", exc_info=True)
        finally:
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _extract_target(self, client_reader: asyncio.StreamReader) -> Tuple[Optional[str], int]:
        """
        Extract target hostname and port from connection
        
        Returns:
            (hostname, port) or (None, 0) if extraction fails
        """
        try:
            # Peek at first bytes to determine connection type
            data = await asyncio.wait_for(client_reader.read(1024), timeout=5.0)
            
            if not data:
                return None, 0
            
            # Check if it's a TLS ClientHello
            if data[0] == 0x16 and len(data) > 5:
                # Parse SNI from ClientHello
                hostname = self._parse_sni_from_client_hello(data)
                if hostname:
                    return hostname, 443
            
            # Check if it's HTTP CONNECT
            if data.startswith(b'CONNECT'):
                line = data.split(b'\r\n')[0].decode('latin-1')
                parts = line.split()
                if len(parts) >= 2:
                    target = parts[1].split(':')
                    hostname = target[0]
                    port = int(target[1]) if len(target) > 1 else 443
                    return hostname, port
            
            return None, 0
            
        except asyncio.TimeoutError:
            logger.warning("Timeout reading target information")
            return None, 0
        except Exception as e:
            logger.error(f"Error extracting target: {e}")
            return None, 0
    
    def _parse_sni_from_client_hello(self, data: bytes) -> Optional[str]:
        """
        Parse Server Name Indication (SNI) from TLS ClientHello
        
        Args:
            data: Raw TLS ClientHello data
        
        Returns:
            Hostname or None if not found
        """
        try:
            # TLS record header: type(1) + version(2) + length(2)
            if len(data) < 5:
                return None
            
            # Skip record header
            pos = 5
            
            # Handshake header: type(1) + length(3)
            if len(data) < pos + 4:
                return None
            
            pos += 4
            
            # Client version (2 bytes)
            pos += 2
            
            # Random (32 bytes)
            pos += 32
            
            # Session ID length (1 byte)
            if len(data) < pos + 1:
                return None
            
            session_id_length = data[pos]
            pos += 1 + session_id_length
            
            # Cipher suites length (2 bytes)
            if len(data) < pos + 2:
                return None
            
            cipher_suites_length = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_length
            
            # Compression methods length (1 byte)
            if len(data) < pos + 1:
                return None
            
            compression_length = data[pos]
            pos += 1 + compression_length
            
            # Extensions length (2 bytes)
            if len(data) < pos + 2:
                return None
            
            extensions_length = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            
            # Parse extensions
            extensions_end = pos + extensions_length
            while pos < extensions_end and pos < len(data):
                if len(data) < pos + 4:
                    break
                
                ext_type = struct.unpack('>H', data[pos:pos+2])[0]
                ext_length = struct.unpack('>H', data[pos+2:pos+4])[0]
                pos += 4
                
                # SNI extension (type 0)
                if ext_type == 0:
                    if len(data) < pos + ext_length:
                        break
                    
                    sni_data = data[pos:pos+ext_length]
                    
                    # Parse SNI
                    if len(sni_data) >= 5:
                        # Skip list length (2 bytes)
                        sni_pos = 2
                        # Name type (1 byte) - should be 0 for hostname
                        if sni_data[sni_pos] == 0:
                            sni_pos += 1
                            # Name length (2 bytes)
                            name_length = struct.unpack('>H', sni_data[sni_pos:sni_pos+2])[0]
                            sni_pos += 2
                            # Hostname
                            hostname = sni_data[sni_pos:sni_pos+name_length].decode('ascii')
                            return hostname
                
                pos += ext_length
            
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing SNI: {e}")
            return None
    
    def _check_security_policy(self, client_ip: str, target_host: str) -> bool:
        """
        Check if connection is allowed by security policies
        
        Args:
            client_ip: Client IP address
            target_host: Target hostname
        
        Returns:
            True if allowed, False if blocked
        """
        # Check IP blacklist
        blacklist_ips = self.security_config.get('blacklist_ips', [])
        if client_ip in blacklist_ips:
            logger.warning(f"Blocked blacklisted IP: {client_ip}")
            return False
        
        # Check domain blacklist
        blacklist_domains = self.security_config.get('blacklist_domains', [])
        for pattern in blacklist_domains:
            if self._match_domain_pattern(target_host, pattern):
                logger.warning(f"Blocked blacklisted domain: {target_host}")
                if self.ebpf_manager:
                    # Add to eBPF blocklist for future fast blocking
                    asyncio.create_task(self.ebpf_manager.add_blocked_domain(target_host))
                return False
        
        return True
    
    def _match_domain_pattern(self, domain: str, pattern: str) -> bool:
        """Match domain against pattern (supports wildcards)"""
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
        return bool(re.match(f'^{regex_pattern}$', domain))
    
    async def _perform_mitm(self, client_reader: asyncio.StreamReader,
                           client_writer: asyncio.StreamWriter,
                           target_host: str, target_port: int,
                           client_addr: tuple):
        """
        Perform MITM interception
        
        1. Establish TLS with client using generated certificate
        2. Connect to upstream server with real TLS
        3. Relay data bidirectionally
        """
        mode = self.config.get('proxy', {}).get('mode', 'mitm_proxy')
        if mode == 'reverse_proxy':
            # TLS already terminated by server_ssl_context; simply connect to backend
            await self._perform_reverse_proxy(client_reader, client_writer, target_host, target_port)
            return

        upstream_reader = None
        upstream_writer = None
        
        try:
            # Step 1: Create SSL context for client with generated certificate
            logger.debug(f"Generating certificate for {target_host}")
            client_ssl_context = self.tls_interceptor.create_client_ssl_context(target_host)
            
            # Wrap client connection with SSL
            logger.debug(f"Wrapping client connection with SSL")
            client_ssl_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(client_ssl_reader)
            
            transport = client_writer.transport
            ssl_transport = await asyncio.get_event_loop().start_tls(
                transport,
                protocol,
                client_ssl_context,
                server_side=True
            )
            
            client_ssl_writer = asyncio.StreamWriter(
                ssl_transport,
                protocol,
                client_ssl_reader,
                asyncio.get_event_loop()
            )
            
            logger.debug(f"✅ SSL handshake completed with client")
            
            # Step 2: Connect to upstream server
            logger.debug(f"Connecting to upstream {target_host}:{target_port}")
            
            upstream_reader, upstream_writer = await asyncio.open_connection(
                target_host, target_port,
                ssl=self.tls_interceptor.upstream_ssl_context,
                server_hostname=target_host
            )
            
            logger.debug(f"✅ Connected to upstream server")
            
            # Create statistics
            conn_id = f"{client_addr[0]}:{client_addr[1]}->{target_host}:{target_port}"
            stats = ConnectionStats(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port
            )
            self.stats[conn_id] = stats
            
            # Step 3: Relay data bidirectionally
            logger.info(f"🔄 Relaying: {client_addr[0]} ↔ {target_host}:{target_port}")
            
            await asyncio.gather(
                self._relay_data(client_ssl_reader, upstream_writer, stats, 'client->server'),
                self._relay_data(upstream_reader, client_ssl_writer, stats, 'server->client'),
                return_exceptions=True
            )
            
            stats.end_time = datetime.now()
            duration = (stats.end_time - stats.start_time).total_seconds()
            logger.info(
                f"✅ Connection closed: {target_host} "
                f"(↑{stats.bytes_sent}B ↓{stats.bytes_received}B {duration:.2f}s)"
            )
            
        except ssl.SSLError as e:
            logger.error(f"SSL error during MITM: {e}")
        except Exception as e:
            logger.error(f"Error during MITM: {e}", exc_info=True)
        finally:
            # Clean up connections
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()
    
    async def _relay_data(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter,
                         stats: ConnectionStats,
                         direction: str):
        """
        Relay data between two streams
        
        Args:
            reader: Source stream reader
            writer: Destination stream writer
            stats: Connection statistics
            direction: Direction label for logging
        """
        try:
            buffer_size = self.proxy_config.get('buffer_size', 65536)
            
            while True:
                data = await reader.read(buffer_size)
                
                if not data:
                    break
                
                # Update statistics
                if direction == 'client->server':
                    stats.bytes_sent += len(data)
                else:
                    stats.bytes_received += len(data)
                
                # Inspect content
                if self.inspection_pipeline:
                    try:
                        # Create context
                        context = InspectionContext(
                            src_ip=stats.client_ip,
                            dst_ip=stats.target_host,
                            src_port=stats.client_port,
                            dst_port=stats.target_port,
                            protocol='TCP',
                            direction='outbound' if direction == 'client->server' else 'inbound',
                            flow_id=f"{stats.client_ip}:{stats.client_port}-{stats.target_host}:{stats.target_port}",
                            timestamp=datetime.now().timestamp(),
                            metadata={}
                        )
                        
                        result = self.inspection_pipeline.inspect(context, data)
                        
                        if result.is_blocked:
                            logger.warning(f"🚫 Blocked by inspection: {direction} (Action: {result.action.name})")
                            for finding in result.findings:
                                logger.info(f"  - {finding.description}")
                            
                            # Terminate connection
                            raise ConnectionAbortedError("Blocked by inspection")
                            
                    except ConnectionAbortedError:
                        raise
                    except Exception as e:
                        logger.error(f"Inspection error: {e}")
                        
                writer.write(data)
                await writer.drain()
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Relay ended ({direction}): {e}")
        finally:
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
    
    async def _relay_http(self, client_reader: asyncio.StreamReader,
                         client_writer: asyncio.StreamWriter,
                         first_line: bytes):
        """
        Relay plain HTTP connection to the destination server.
        
        Extracts the Host header from the request, connects to the
        target server, forwards the full request, and relays the response.
        """
        upstream_writer = None
        try:
            # Read remaining headers
            headers_raw = b''
            while True:
                line = await asyncio.wait_for(client_reader.readline(), timeout=10.0)
                headers_raw += line
                if line == b'\r\n' or line == b'\n' or not line:
                    break
            
            # Extract Host header to determine target
            target_host = None
            target_port = 80
            for hdr_line in headers_raw.decode('latin-1', errors='replace').split('\r\n'):
                if hdr_line.lower().startswith('host:'):
                    host_val = hdr_line.split(':', 1)[1].strip()
                    if ':' in host_val:
                        target_host, port_str = host_val.rsplit(':', 1)
                        try:
                            target_port = int(port_str)
                        except ValueError:
                            target_host = host_val
                    else:
                        target_host = host_val
                    break
            
            if not target_host:
                # Try to extract from the URL in the request line
                req_parts = first_line.decode('latin-1').strip().split()
                if len(req_parts) >= 2 and req_parts[1].startswith('http://'):
                    from urllib.parse import urlparse
                    parsed = urlparse(req_parts[1])
                    target_host = parsed.hostname
                    target_port = parsed.port or 80
            
            if not target_host:
                logger.warning("HTTP relay: could not determine target host")
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return
            
            # Check security policy
            client_addr = client_writer.get_extra_info('peername')
            if not self._check_security_policy(client_addr[0], target_host):
                logger.warning(f"🚫 HTTP blocked: {client_addr[0]} → {target_host}")
                client_writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\nBlocked by NGFW policy")
                await client_writer.drain()
                return
            
            logger.info(f"🔄 HTTP relay: {client_addr[0]} → {target_host}:{target_port}")
            
            # Connect to upstream
            upstream_reader, upstream_writer = await asyncio.open_connection(
                target_host, target_port
            )
            
            # Forward the original request
            upstream_writer.write(first_line)
            upstream_writer.write(headers_raw)
            await upstream_writer.drain()
            
            # Create stats
            stats = ConnectionStats(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port
            )
            
            # Relay bidirectionally
            await asyncio.gather(
                self._relay_data(client_reader, upstream_writer, stats, 'client->server'),
                self._relay_data(upstream_reader, client_writer, stats, 'server->client'),
                return_exceptions=True
            )
            
            logger.info(f"✅ HTTP closed: {target_host} (↑{stats.bytes_sent}B ↓{stats.bytes_received}B)")
            
        except asyncio.TimeoutError:
            logger.warning("HTTP relay: timeout reading headers")
        except Exception as e:
            logger.error(f"HTTP relay error: {e}", exc_info=True)
        finally:
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()
    
    def get_statistics(self) -> dict:
        """Get proxy statistics"""
        return {
            'total_connections': self.total_connections,
            'active_connections': self.active_connections,
            'cached_certificates': len(self.ca_manager.cert_cache.cache),
        }