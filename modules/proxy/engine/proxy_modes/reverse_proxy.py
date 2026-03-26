#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Reverse Proxy - Web Application Protection Mode
═══════════════════════════════════════════════════════════════════

Reverse proxy mode for protecting web servers/applications.
Features:
- SSL termination at proxy
- Load balancing (future)
- Web Application Firewall (WAF) integration
- DDoS protection

Author: Enterprise Security Team
"""

import asyncio
import logging
import ssl
import ipaddress
from typing import Optional, List
from .base_proxy import BaseProxy, ProxyConnection

logger = logging.getLogger(__name__)


class ReverseProxy(BaseProxy):
    """
    Reverse Proxy Implementation
    
    Terminates SSL at proxy and forwards to backend servers.
    """
    
    def __init__(self, config: dict, ca_manager, flow_tracker=None, event_sink=None):
        super().__init__(config)
        self.ca_manager = ca_manager
        self.flow_tracker = flow_tracker
        self.event_sink = event_sink
        
        self.listen_host = self.proxy_config.get('reverse_listen_host', '0.0.0.0')
        self.listen_port = self.proxy_config.get('reverse_listen_port', 443)
        self.http_port = self.proxy_config.get('reverse_http_port', 80)
        self.http_enabled = self.proxy_config.get('reverse_http_enabled', False)
        
        # Backend servers
        self.backends = self.proxy_config.get('backends', [
            {'host': 'localhost', 'port': 8000}
        ])
        self.current_backend = 0
        
        # SSL context for client connections
        self.ssl_context = self._create_ssl_context()
        
        logger.info(f"Reverse Proxy configured on {self.listen_host}:{self.listen_port}")
        logger.info(f"Backend servers: {self.backends}")
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for accepting client connections"""
        tls_config = self.config.get('tls', {})
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate
        cert_file = tls_config.get('server_cert', '/etc/CyberNexus/certs/server.crt')
        key_file = tls_config.get('server_key', '/etc/CyberNexus/certs/server.key')
        
        try:
            context.load_cert_chain(cert_file, key_file)
            logger.info(f"Loaded SSL certificate: {cert_file}")
        except (FileNotFoundError, ssl.SSLError) as e:
            logger.warning(f"SSL certificate not found or invalid: {e}")
            logger.warning("Auto-generating self-signed certificate for testing...")
            self._generate_self_signed_cert(cert_file, key_file)
            try:
                context.load_cert_chain(cert_file, key_file)
                logger.info("✅ Self-signed certificate loaded")
            except Exception as e2:
                logger.error(f"Failed to load generated cert: {e2}")
        
        # Configure TLS versions
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # ALPN: only http/1.1 — we relay raw TCP, not HTTP/2 frames
        context.set_alpn_protocols(['http/1.1'])
        
        return context
    
    def _generate_self_signed_cert(self, cert_file: str, key_file: str):
        """Generate a self-signed certificate for testing"""
        import os
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Create directories if needed
        os.makedirs(os.path.dirname(cert_file), exist_ok=True)
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        
        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generate cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CyberNexus Reverse Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise CyberNexus"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("192.168.10.1")),
                    x509.IPAddress(ipaddress.IPv4Address("192.168.20.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        
        # Write key
        with open(key_file, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write cert
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Generated self-signed cert: {cert_file}")
    
    async def start(self):
        """Start reverse proxy server"""
        logger.info("Starting Reverse Proxy...")
        self.running = True
        
        # Start HTTPS server
        server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
            ssl=self.ssl_context
        )
        self.servers.append(server)
        
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"🔒 Reverse Proxy (HTTPS) listening on {addrs} (SSL)")
        
        # Start HTTP server if enabled
        if self.http_enabled:
            http_server = await asyncio.start_server(
                self.handle_http_connection,
                self.listen_host,
                self.http_port
            )
            self.servers.append(http_server)
            addrs_http = ', '.join(str(sock.getsockname()) for sock in http_server.sockets)
            logger.info(f" Reverse Proxy (HTTP) listening on {addrs_http}")
        
        # Serve forever
        async with server:
            if self.http_enabled:
                async with http_server:
                    await asyncio.gather(
                        server.serve_forever(),
                        http_server.serve_forever()
                    )
            else:
                await server.serve_forever()
    
    async def stop(self):
        """Stop reverse proxy server"""
        logger.info("Stopping Reverse Proxy...")
        self.running = False
        
        for server in self.servers:
            server.close()
            await server.wait_closed()
        
        logger.info("Reverse Proxy stopped")
    
    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection
        
        SSL is already terminated by the server.
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"Reverse proxy connection from {client_addr}")
        
        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1
        
        server_reader = None
        server_writer = None
        
        try:
            # Select backend server (simple round-robin)
            backend = self._select_backend()
            
            logger.info(f"🔄 Reverse proxying {client_addr[0]} → {backend['host']}:{backend['port']}")
            
            # Connect to backend
            # Check if backend uses SSL
            # Check if backend uses SSL
            use_ssl = backend.get('ssl', False)
            # Handle string boolean values just in case
            if isinstance(use_ssl, str):
                use_ssl = use_ssl.lower() in ('true', '1', 'yes', 'on')
            
            # Safeguard: Force SSL off for port 80 unless explicitly overridden
            # This handles cases where config.yaml overrides base.yaml with bad defaults
            if backend['port'] == 80 and use_ssl:
                logger.warning(f"⚠️ Disabling SSL for port 80 backend {backend['host']} (config says SSL=True)")
                use_ssl = False
            
            logger.info(f"Connecting to backend {backend['host']}:{backend['port']} (SSL={use_ssl})")
            
            if use_ssl:
                backend_ssl = ssl.create_default_context()
                backend_ssl.check_hostname = False
                backend_ssl.verify_mode = ssl.CERT_NONE
                
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'],
                    backend['port'],
                    ssl=backend_ssl
                )
            else:
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'],
                    backend['port']
                )
            
            # Create connection object
            conn_id = self._generate_connection_id(
                client_addr,
                backend['host'],
                backend['port']
            )
            
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=backend['host'],
                target_port=backend['port'],
                protocol="HTTPS",
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
            
            logger.info(f"✅ Connection closed: {backend['host']} (↑{connection.bytes_sent}B ↓{connection.bytes_received}B)")
            
        except Exception as e:
            logger.error(f"Error in reverse proxy: {e}", exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()
            
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def handle_http_connection(self,
                                    client_reader: asyncio.StreamReader,
                                    client_writer: asyncio.StreamWriter):
        """
        Handle incoming HTTP client connection (non-SSL)
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"Reverse proxy HTTP connection from {client_addr}")
        
        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1
        
        server_reader = None
        server_writer = None
        
        try:
            # Select backend server
            backend = self._select_backend()
            
            logger.info(f"🔄 Reverse proxying (HTTP) {client_addr[0]} → {backend['host']}:{backend['port']}")
            
            # Connect to backend (usually HTTP plain text)
            # If backend requires SSL, we can use ssl context here too
            use_ssl = backend.get('ssl', False)
            if isinstance(use_ssl, str):
                use_ssl = use_ssl.lower() in ('true', '1', 'yes', 'on')
            
            if backend['port'] == 80 and use_ssl:
                use_ssl = False
            
            logger.info(f"Connecting (HTTP) to backend {backend['host']}:{backend['port']} (SSL={use_ssl})")
            
            if use_ssl:
                backend_ssl = ssl.create_default_context()
                backend_ssl.check_hostname = False
                backend_ssl.verify_mode = ssl.CERT_NONE
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'],
                    backend['port'],
                    ssl=backend_ssl
                )
            else:
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'],
                    backend['port']
                )
            
            # Create connection object
            conn_id = self._generate_connection_id(
                client_addr,
                backend['host'],
                backend['port']
            )
            
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=backend['host'],
                target_port=backend['port'],
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
            
            logger.info(f"✅ Connection closed: {backend['host']} (↑{connection.bytes_sent}B ↓{connection.bytes_received}B)")
            
        except Exception as e:
            logger.error(f"Error in reverse proxy HTTP: {e}", exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()
            
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()

    def _select_backend(self) -> dict:
        """
        Select backend server
        
        Simple round-robin load balancing.
        In production, use more sophisticated algorithms:
        - Least connections
        - Response time based
        - Health check based
        """
        if not self.backends:
            raise ValueError("No backend servers configured")
        
        backend = self.backends[self.current_backend]
        self.current_backend = (self.current_backend + 1) % len(self.backends)
        
        return backend
