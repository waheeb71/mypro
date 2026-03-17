#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SNI Router - Server Name Indication Parser
═══════════════════════════════════════════════════════════════════

Extracts SNI (Server Name Indication) from TLS ClientHello packets.

Author: Enterprise Security Team
"""

import struct
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def extract_sni(data: bytes) -> Optional[str]:
    """
    Extract Server Name Indication (SNI) from TLS ClientHello
    
    Args:
        data: Raw TLS ClientHello data
    
    Returns:
        Hostname or None if not found
    """
    try:
        # TLS record header: type(1) + version(2) + length(2)
        if len(data) < 5:
            return None
        
        # Check if it's a handshake record (type 0x16)
        if data[0] != 0x16:
            return None
        
        # Skip record header
        pos = 5
        
        # Handshake header: type(1) + length(3)
        if len(data) < pos + 4:
            return None
        
        # Check if it's ClientHello (type 0x01)
        if data[pos] != 0x01:
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
                        if len(sni_data) >= sni_pos + name_length:
                            hostname = sni_data[sni_pos:sni_pos+name_length].decode('ascii')
                            return hostname
            
            pos += ext_length
        
        return None
        
    except Exception as e:
        logger.debug(f"Error parsing SNI: {e}")
        return None


class SNIRouter:
    """
    SNI-based routing
    
    Routes connections based on SNI to different backends or policies.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.routing_rules = config.get('sni_routing', {})
        
        logger.info("SNI Router initialized")
    
    def get_backend_for_sni(self, sni: str) -> Optional[dict]:
        """
        Get backend configuration for given SNI
        
        Args:
            sni: Server Name Indication (hostname)
        
        Returns:
            Backend configuration dict or None
        """
        # Check exact match
        if sni in self.routing_rules:
            return self.routing_rules[sni]
        
        # Check wildcard match
        parts = sni.split('.')
        for i in range(len(parts)):
            wildcard = '*.' + '.'.join(parts[i+1:])
            if wildcard in self.routing_rules:
                return self.routing_rules[wildcard]
        
        return None
