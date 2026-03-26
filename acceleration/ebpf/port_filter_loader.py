"""
Enterprise CyberNexus v2.0 - eBPF Port Filter Loader

Python wrapper for loading and managing the XDP port filter program.
Provides high-level API for port filtering configuration.

Author: Enterprise CyberNexus Team
License: Proprietary
"""

import logging
import struct
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logging.warning("BCC not available - eBPF port filtering disabled")


class FilterMode(IntEnum):
    """Port filtering modes"""
    DISABLED = 0
    WHITELIST = 1  # Only listed ports allowed
    BLACKLIST = 2  # Listed ports blocked


@dataclass
class PortStats:
    """Statistics for a specific port"""
    port: int
    packets: int = 0
    bytes: int = 0
    drops: int = 0
    last_seen: float = 0.0
    
    @property
    def drop_rate(self) -> float:
        """Calculate drop rate percentage"""
        if self.packets == 0:
            return 0.0
        return (self.drops / self.packets) * 100


@dataclass
class FilterConfig:
    """Port filter configuration"""
    mode: FilterMode = FilterMode.DISABLED
    filter_tcp: bool = True
    filter_udp: bool = True
    log_drops: bool = False
    default_action: int = 2  # XDP_PASS


class PortFilterLoader:
    """
    Loads and manages eBPF XDP port filter program.
    
    Provides APIs for:
    - Loading/unloading XDP program
    - Managing whitelist/blacklist
    - Retrieving per-port statistics
    - Dynamic configuration updates
    """
    
    def __init__(
        self,
        interface: str,
        program_path: Optional[Path] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.interface = interface
        self.program_path = program_path or self._default_program_path()
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.bpf: Optional[BPF] = None
        self.loaded = False
        
        # Local caches
        self._whitelist: Set[int] = set()
        self._blacklist: Set[int] = set()
        self._config = FilterConfig()
        
    def _default_program_path(self) -> Path:
        """Get default path to port_filter.c"""
        current_dir = Path(__file__).parent
        return current_dir / "port_filter.c"
        
    def load(self) -> bool:
        """
        Load XDP program onto interface.
        
        Returns:
            True if loaded successfully
        """
        if not BCC_AVAILABLE:
            self.logger.error("BCC not available - cannot load eBPF program")
            return False
            
        if self.loaded:
            self.logger.warning("Program already loaded")
            return True
            
        if not self.program_path.exists():
            self.logger.error(f"Program not found: {self.program_path}")
            return False
            
        try:
            # Load BPF program
            self.logger.info(f"Loading port filter on {self.interface}...")
            
            with open(self.program_path, 'r') as f:
                bpf_code = f.read()
                
            self.bpf = BPF(text=bpf_code)
            
            # Attach to interface
            fn = self.bpf.load_func("xdp_port_filter", BPF.XDP)
            self.bpf.attach_xdp(self.interface, fn, 0)
            
            self.loaded = True
            self.logger.info("Port filter loaded successfully")
            
            # Initialize with default config
            self._update_config()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load port filter: {e}")
            return False
            
    def unload(self) -> bool:
        """
        Unload XDP program from interface.
        
        Returns:
            True if unloaded successfully
        """
        if not self.loaded:
            self.logger.warning("Program not loaded")
            return True
            
        try:
            if self.bpf:
                self.bpf.remove_xdp(self.interface, 0)
                self.bpf = None
                
            self.loaded = False
            self.logger.info("Port filter unloaded")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload port filter: {e}")
            return False
            
    def set_mode(self, mode: FilterMode) -> bool:
        """Set filtering mode (disabled/whitelist/blacklist)"""
        self._config.mode = mode
        return self._update_config()
        
    def enable_protocol(self, tcp: bool = True, udp: bool = True) -> bool:
        """Enable/disable TCP and UDP filtering"""
        self._config.filter_tcp = tcp
        self._config.filter_udp = udp
        return self._update_config()
        
    def _update_config(self) -> bool:
        """Push configuration to eBPF map"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            config_map = self.bpf["config_map"]
            
            # Pack configuration
            config_data = struct.pack(
                'BBBI',
                self._config.mode.value,
                int(self._config.filter_tcp),
                int(self._config.filter_udp),
                int(self._config.log_drops),
                self._config.default_action
            )
            
            config_map[0] = config_data
            self.logger.debug(f"Updated config: mode={self._config.mode.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update config: {e}")
            return False
            
    def add_to_whitelist(self, ports: List[int]) -> bool:
        """Add ports to whitelist"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            whitelist_map = self.bpf["port_whitelist"]
            
            for port in ports:
                if 0 <= port <= 65535:
                    whitelist_map[port] = 1
                    self._whitelist.add(port)
                    
            self.logger.info(f"Added {len(ports)} ports to whitelist")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update whitelist: {e}")
            return False
            
    def remove_from_whitelist(self, ports: List[int]) -> bool:
        """Remove ports from whitelist"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            whitelist_map = self.bpf["port_whitelist"]
            
            for port in ports:
                if port in self._whitelist:
                    del whitelist_map[port]
                    self._whitelist.discard(port)
                    
            self.logger.info(f"Removed {len(ports)} ports from whitelist")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update whitelist: {e}")
            return False
            
    def add_to_blacklist(self, ports: List[int]) -> bool:
        """Add ports to blacklist"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            blacklist_map = self.bpf["port_blacklist"]
            
            for port in ports:
                if 0 <= port <= 65535:
                    blacklist_map[port] = 1
                    self._blacklist.add(port)
                    
            self.logger.info(f"Added {len(ports)} ports to blacklist")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update blacklist: {e}")
            return False
            
    def remove_from_blacklist(self, ports: List[int]) -> bool:
        """Remove ports from blacklist"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            blacklist_map = self.bpf["port_blacklist"]
            
            for port in ports:
                if port in self._blacklist:
                    del blacklist_map[port]
                    self._blacklist.discard(port)
                    
            self.logger.info(f"Removed {len(ports)} ports from blacklist")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update blacklist: {e}")
            return False
            
    def get_port_statistics(self, port: Optional[int] = None) -> Dict[int, PortStats]:
        """
        Get statistics for port(s).
        
        Args:
            port: Specific port number, or None for all ports
            
        Returns:
            Dictionary mapping port -> PortStats
        """
        if not self.loaded or not self.bpf:
            return {}
            
        try:
            stats_map = self.bpf["port_statistics"]
            result = {}
            
            if port is not None:
                # Get specific port
                if port in stats_map:
                    data = stats_map[port]
                    packets, bytes_count, drops, last_seen = struct.unpack('QQQQ', data)
                    result[port] = PortStats(
                        port=port,
                        packets=packets,
                        bytes=bytes_count,
                        drops=drops,
                        last_seen=last_seen / 1e9  # ns to seconds
                    )
            else:
                # Get all ports
                for port_key, data in stats_map.items():
                    port_num = port_key.value
                    packets, bytes_count, drops, last_seen = struct.unpack('QQQQ', data)
                    result[port_num] = PortStats(
                        port=port_num,
                        packets=packets,
                        bytes=bytes_count,
                        drops=drops,
                        last_seen=last_seen / 1e9
                    )
                    
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
            
    def get_top_ports(self, n: int = 10, by: str = 'packets') -> List[PortStats]:
        """
        Get top N ports by traffic.
        
        Args:
            n: Number of ports to return
            by: Sort metric ('packets', 'bytes', 'drops')
            
        Returns:
            List of PortStats sorted by metric
        """
        all_stats = self.get_port_statistics()
        
        if not all_stats:
            return []
            
        sorted_stats = sorted(
            all_stats.values(),
            key=lambda s: getattr(s, by),
            reverse=True
        )
        
        return sorted_stats[:n]
        
    def clear_statistics(self) -> bool:
        """Clear all port statistics"""
        if not self.loaded or not self.bpf:
            return False
            
        try:
            stats_map = self.bpf["port_statistics"]
            stats_map.clear()
            self.logger.info("Cleared port statistics")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to clear statistics: {e}")
            return False
            
    def get_status(self) -> Dict:
        """Get current filter status"""
        return {
            'loaded': self.loaded,
            'interface': self.interface,
            'mode': self._config.mode.name,
            'filter_tcp': self._config.filter_tcp,
            'filter_udp': self._config.filter_udp,
            'whitelist_count': len(self._whitelist),
            'blacklist_count': len(self._blacklist),
            'total_ports_tracked': len(self.get_port_statistics())
        }
        
    def __enter__(self):
        """Context manager entry"""
        self.load()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.unload()