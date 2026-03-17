#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SSL Inspector - Advanced SSL/TLS Interception Engine
═══════════════════════════════════════════════════════════════════

Handles SSL/TLS interception with advanced features:
- Dynamic certificate generation
- Certificate pinning detection
- Protocol version negotiation
- Cipher suite management

Author: Enterprise Security Team
"""

import asyncio
import logging
import ssl
import tempfile
from typing import Optional, Tuple
from .ca_pool import CAPoolManager

logger = logging.getLogger(__name__)


class SSLInspector:
    """
    SSL/TLS Inspection Engine
    
    Performs man-in-the-middle SSL inspection.
    """
    
    def __init__(self, ca_manager: CAPoolManager, config: dict):
        self.ca_manager = ca_manager
        self.config = config
        self.tls_config = config.get('tls', {})
        
        # Create SSL context for upstream connections
        self.upstream_ssl_context = self._create_upstream_ssl_context()
        
        logger.info("SSL Inspector initialized")
    
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
        # Generate certificate for this hostname
        cert_pem, key_pem = self.ca_manager.generate_server_certificate(hostname)
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load generated certificate into a temporary file
        # (ssl.SSLContext requires file paths, not bytes directly)
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
    
    async def wrap_client_connection(self,
                                     reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter,
                                     hostname: str) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Wrap client connection with SSL
        
        Args:
            reader: Client StreamReader
            writer: Client StreamWriter
            hostname: Target hostname
        
        Returns:
            (ssl_reader, ssl_writer) tuple
        """
        try:
            # Create SSL context
            ssl_context = self.create_client_ssl_context(hostname)
            
            # Wrap connection
            ssl_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(ssl_reader)
            
            transport = writer.transport
            ssl_transport = await asyncio.get_event_loop().start_tls(
                transport,
                protocol,
                ssl_context,
                server_side=True
            )
            
            ssl_writer = asyncio.StreamWriter(
                ssl_transport,
                protocol,
                ssl_reader,
                asyncio.get_event_loop()
            )
            
            logger.debug(f"✅ SSL handshake completed for {hostname}")
            
            return ssl_reader, ssl_writer
            
        except ssl.SSLError as e:
            logger.error(f"SSL error during handshake for {hostname}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error wrapping client connection: {e}")
            raise
    
    async def connect_to_upstream(self,
                                  hostname: str,
                                  port: int = 443) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to upstream server with SSL
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            (reader, writer) tuple
        """
        try:
            reader, writer = await asyncio.open_connection(
                hostname, port,
                ssl=self.upstream_ssl_context,
                server_hostname=hostname
            )
            
            logger.debug(f"✅ Connected to upstream: {hostname}:{port}")
            
            return reader, writer
            
        except Exception as e:
            logger.error(f"Failed to connect to {hostname}:{port}: {e}")
            raise
