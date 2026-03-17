"""
Proxy Dispatcher
Logic for selecting the appropriate Proxy Mode.
"""

import logging
from typing import Dict
from .types import ProxyMode

logger = logging.getLogger(__name__)

class ProxyDispatcher:
    """Determines Proxy Mode based on port and config"""
    
    def __init__(self, config: dict):
        self.config = config
        self.routing_config = config.get('routing', {})
        
        self.default_mode = ProxyMode(
            self.routing_config.get('default_mode', 'transparent')
        )
        self.port_mode_map = self._build_port_map()
        
    def _build_port_map(self) -> Dict[int, ProxyMode]:
        """Build port to mode mapping"""
        defaults = {
            8080: ProxyMode.FORWARD,
            8443: ProxyMode.FORWARD,
            443: ProxyMode.TRANSPARENT,
            80: ProxyMode.TRANSPARENT,
        }
        
        custom_mappings = self.routing_config.get('port_mappings', {})
        for port, mode_str in custom_mappings.items():
            try:
                defaults[int(port)] = ProxyMode(mode_str)
            except (ValueError, KeyError) as e:
                logger.warning(f"Invalid port mapping: {port}={mode_str}: {e}")
                
        return defaults

    def get_mode(self, local_port: int) -> ProxyMode:
        """Get proxy mode for a destination port"""
        return self.port_mode_map.get(local_port, self.default_mode)
