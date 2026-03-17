"""
Zone Management
Maps interfaces to logical zones (LAN, WAN, DMZ)
"""

from typing import Dict, Optional

class ZoneManager:
    """Manages Network Zones"""
    
    def __init__(self, interface_map: Optional[Dict[str, str]] = None):
        # Maps interface name -> zone name
        # e.g., {'eth0': 'wan', 'eth1': 'lan'}
        self.interface_map = interface_map or {}
        
    def get_zone(self, interface_name: str) -> str:
        """Get zone for interface"""
        return self.interface_map.get(interface_name, "unknown")

    def add_zone_mapping(self, interface: str, zone: str):
        self.interface_map[interface] = zone
