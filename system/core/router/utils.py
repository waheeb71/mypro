"""
Router Utilities
Helper functions for traffic analysis and extraction.
"""

import logging
from typing import Tuple, Optional, Any
from .types import ProxyMode

logger = logging.getLogger(__name__)

async def extract_target(data: bytes, mode: ProxyMode) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract target host/port from initial connection data
    
    Handles:
    - HTTP CONNECT requests
    - TLS SNI
    """
    # Check for HTTP CONNECT
    if data.startswith(b'CONNECT'):
        try:
            line = data.split(b'\r\n')[0].decode('latin-1')
            parts = line.split()
            if len(parts) >= 2:
                target = parts[1].split(':')
                host = target[0]
                port = int(target[1]) if len(target) > 1 else 443
                return host, port
        except Exception as e:
            logger.debug(f"Error parsing CONNECT: {e}")
    
    # Check for TLS ClientHello (SNI)
    if len(data) > 5 and data[0] == 0x16:
        # Avoid circular import by importing inside function if strictly needed, 
        # or better: rely on a dedicated SNI parser utility if available.
        # For now, we reuse the existing one from modules.ssl_inspection.engine
        try:
            from modules.ssl_inspection.engine.sni_router import extract_sni
            sni = extract_sni(data)
            if sni:
                return sni, 443
        except ImportError:
            logger.warning("SNI Router module not found")
    
    return None, None

def match_domain(domain: str, pattern: str) -> bool:
    """Match domain against pattern (supports wildcards)"""
    import re
    regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
    return bool(re.match(f'^{regex_pattern}$', domain, re.IGNORECASE))
