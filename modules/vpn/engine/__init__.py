"""
Enterprise NGFW - VPN Integration

Provides VPN connection capabilities.
"""

from .wireguard import WireGuardManager, PeerConfig

__all__ = [
    'WireGuardManager',
    'PeerConfig'
]
