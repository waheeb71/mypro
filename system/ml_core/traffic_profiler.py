#!/usr/bin/env python3
"""
Enterprise NGFW - Traffic Profiler
Real-time traffic pattern classification and behavioral profiling
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import numpy as np
from threading import RLock

logger = logging.getLogger(__name__)


class TrafficPattern(Enum):
    """Traffic pattern classifications"""
    NORMAL = "normal"
    SCANNING = "scanning"          # Port/network scanning
    DDOS = "ddos"                  # DDoS attack pattern
    BRUTE_FORCE = "brute_force"    # Login attempts
    DATA_EXFIL = "data_exfiltration"  # Large data transfers
    C2_COMMUNICATION = "c2_comm"   # Command & Control
    SUSPICIOUS = "suspicious"      # Anomalous but not classified
    UNKNOWN = "unknown"


@dataclass
class ConnectionProfile:
    """Individual connection profile"""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: datetime
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    duration: float = 0.0
    flags: Set[str] = field(default_factory=set)


@dataclass
class IPProfile:
    """Behavioral profile for an IP address"""
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_connections: int = 0
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    unique_dst_ips: Set[str] = field(default_factory=set)
    unique_dst_ports: Set[int] = field(default_factory=set)
    protocols_used: Dict[str, int] = field(default_factory=dict)
    patterns_detected: Dict[TrafficPattern, int] = field(default_factory=dict)
    reputation_score: float = 100.0  # 0-100, lower is worse
    
    def update_reputation(self, pattern: TrafficPattern):
        """Update reputation based on detected pattern"""
        penalties = {
            TrafficPattern.NORMAL: 0,
            TrafficPattern.SUSPICIOUS: -2,
            TrafficPattern.SCANNING: -10,
            TrafficPattern.BRUTE_FORCE: -15,
            TrafficPattern.DDOS: -20,
            TrafficPattern.C2_COMMUNICATION: -25,
            TrafficPattern.DATA_EXFIL: -20,
        }
        
        penalty = penalties.get(pattern, -5)
        self.reputation_score = max(0.0, min(100.0, self.reputation_score + penalty))


@dataclass
class ProfilerStatistics:
    """Traffic profiler statistics"""
    total_profiles: int = 0
    patterns_detected: Dict[TrafficPattern, int] = field(default_factory=dict)
    low_reputation_ips: int = 0
    scanning_detected: int = 0
    ddos_detected: int = 0
    c2_detected: int = 0


class TrafficProfiler:
    """
    Real-time traffic profiling and pattern classification
    
    Features:
    - Behavioral profiling per IP
    - Pattern detection (scanning, DDoS, C2, etc.)
    - Reputation scoring
    - Temporal analysis
    - Anomaly correlation
    """
    
    def __init__(
        self,
        time_window: int = 300,  # 5 minutes
        max_profiles: int = 10000,
        low_reputation_threshold: float = 40.0
    ):
        self.time_window = time_window
        self.max_profiles = max_profiles
        self.low_reputation_threshold = low_reputation_threshold
        
        # Profile storage
        self.ip_profiles: Dict[str, IPProfile] = {}
        self.recent_connections: deque = deque(maxlen=10000)
        
        # Pattern detection thresholds
        self.scanning_threshold = {
            'unique_ports': 50,       # > 50 unique ports
            'time_window': 60,        # in 60 seconds
            'connection_rate': 10     # > 10 conn/sec
        }
        
        self.ddos_threshold = {
            'connection_rate': 1000,  # > 1000 conn/sec to same target
            'time_window': 10,
            'packet_rate': 10000      # > 10K packets/sec
        }
        
        self.brute_force_threshold = {
            'failed_attempts': 10,    # > 10 failed logins
            'time_window': 60,
            'ports': {22, 23, 3389, 21, 445}  # SSH, Telnet, RDP, FTP, SMB
        }
        
        self.data_exfil_threshold = {
            'bytes_rate': 100 * 1024 * 1024,  # > 100 MB/sec
            'duration': 60,
            'single_connection': 1024 * 1024 * 1024  # > 1 GB in one connection
        }
        
        # Statistics
        self.stats = ProfilerStatistics()
        self._lock = RLock()
        
        logger.info(f"TrafficProfiler initialized (window={time_window}s, max_profiles={max_profiles})")
    
    def profile_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        packets_sent: int = 0,
        packets_recv: int = 0,
        duration: float = 0.0,
        flags: Optional[Set[str]] = None
    ) -> Tuple[TrafficPattern, float]:
        """
        Profile a connection and classify its pattern
        
        Returns:
            (pattern, confidence) - Pattern classification and confidence score
        """
        with self._lock:
            # Create connection profile
            conn = ConnectionProfile(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                timestamp=datetime.now(),
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                packets_sent=packets_sent,
                packets_recv=packets_recv,
                duration=duration,
                flags=flags or set()
            )
            
            self.recent_connections.append(conn)
            
            # Update IP profile
            profile = self._get_or_create_profile(src_ip)
            self._update_profile(profile, conn)
            
            # Detect pattern
            pattern, confidence = self._detect_pattern(profile, conn)
            
            # Update reputation
            profile.patterns_detected[pattern] = profile.patterns_detected.get(pattern, 0) + 1
            profile.update_reputation(pattern)
            
            # Update statistics
            self.stats.patterns_detected[pattern] = self.stats.patterns_detected.get(pattern, 0) + 1
            if profile.reputation_score < self.low_reputation_threshold:
                self.stats.low_reputation_ips += 1
            
            # Cleanup old profiles
            self._cleanup_old_profiles()
            
            return pattern, confidence
    
    def get_ip_profile(self, ip: str) -> Optional[IPProfile]:
        """Get profile for specific IP"""
        with self._lock:
            return self.ip_profiles.get(ip)
    
    def get_low_reputation_ips(self, threshold: Optional[float] = None) -> List[Tuple[str, float]]:
        """Get IPs with low reputation scores"""
        threshold = threshold or self.low_reputation_threshold
        with self._lock:
            return [
                (ip, profile.reputation_score)
                for ip, profile in self.ip_profiles.items()
                if profile.reputation_score < threshold
            ]
    
    def get_active_patterns(self) -> Dict[TrafficPattern, int]:
        """Get currently active patterns"""
        with self._lock:
            # Count patterns in recent time window
            cutoff = datetime.now() - timedelta(seconds=self.time_window)
            pattern_counts = defaultdict(int)
            
            for conn in self.recent_connections:
                if conn.timestamp > cutoff:
                    profile = self.ip_profiles.get(conn.src_ip)
                    if profile:
                        for pattern, count in profile.patterns_detected.items():
                            pattern_counts[pattern] += 1
            
            return dict(pattern_counts)
    
    def get_statistics(self) -> ProfilerStatistics:
        """Get profiler statistics"""
        with self._lock:
            self.stats.total_profiles = len(self.ip_profiles)
            return self.stats
    
    def _get_or_create_profile(self, ip: str) -> IPProfile:
        """Get existing profile or create new one"""
        if ip not in self.ip_profiles:
            if len(self.ip_profiles) >= self.max_profiles:
                # Remove oldest profile
                oldest_ip = min(
                    self.ip_profiles.keys(),
                    key=lambda x: self.ip_profiles[x].last_seen
                )
                del self.ip_profiles[oldest_ip]
            
            self.ip_profiles[ip] = IPProfile(
                ip=ip,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        
        return self.ip_profiles[ip]
    
    def _update_profile(self, profile: IPProfile, conn: ConnectionProfile):
        """Update profile with connection data"""
        profile.last_seen = conn.timestamp
        profile.total_connections += 1
        profile.total_bytes_sent += conn.bytes_sent
        profile.total_bytes_recv += conn.bytes_recv
        profile.unique_dst_ips.add(conn.dst_ip)
        profile.unique_dst_ports.add(conn.dst_port)
        
        protocol = conn.protocol.upper()
        profile.protocols_used[protocol] = profile.protocols_used.get(protocol, 0) + 1
    
    def _detect_pattern(self, profile: IPProfile, conn: ConnectionProfile) -> Tuple[TrafficPattern, float]:
        """Detect traffic pattern with confidence score"""
        
        # Check for port scanning
        if self._is_scanning(profile):
            self.stats.scanning_detected += 1
            return TrafficPattern.SCANNING, 0.9
        
        # Check for DDoS
        if self._is_ddos(profile, conn):
            self.stats.ddos_detected += 1
            return TrafficPattern.DDOS, 0.85
        
        # Check for brute force
        if self._is_brute_force(profile, conn):
            return TrafficPattern.BRUTE_FORCE, 0.8
        
        # Check for data exfiltration
        if self._is_data_exfiltration(conn):
            return TrafficPattern.DATA_EXFIL, 0.75
        
        # Check for C2 communication
        if self._is_c2_communication(profile, conn):
            self.stats.c2_detected += 1
            return TrafficPattern.C2_COMMUNICATION, 0.7
        
        # Check reputation for suspicious
        if profile.reputation_score < self.low_reputation_threshold:
            return TrafficPattern.SUSPICIOUS, 0.6
        
        # Default to normal
        return TrafficPattern.NORMAL, 0.95
    
    def _is_scanning(self, profile: IPProfile) -> bool:
        """Detect port/network scanning behavior"""
        time_active = (profile.last_seen - profile.first_seen).total_seconds()
        
        if time_active < self.scanning_threshold['time_window']:
            return False
        
        connection_rate = profile.total_connections / max(time_active, 1)
        unique_ports = len(profile.unique_dst_ports)
        
        return (
            unique_ports > self.scanning_threshold['unique_ports'] and
            connection_rate > self.scanning_threshold['connection_rate']
        )
    
    def _is_ddos(self, profile: IPProfile, conn: ConnectionProfile) -> bool:
        """Detect DDoS attack pattern"""
        # Count recent connections to same target
        cutoff = datetime.now() - timedelta(seconds=self.ddos_threshold['time_window'])
        recent_to_target = sum(
            1 for c in self.recent_connections
            if c.src_ip == profile.ip and
               c.dst_ip == conn.dst_ip and
               c.timestamp > cutoff
        )
        
        rate = recent_to_target / self.ddos_threshold['time_window']
        return rate > self.ddos_threshold['connection_rate']
    
    def _is_brute_force(self, profile: IPProfile, conn: ConnectionProfile) -> bool:
        """Detect brute force login attempts"""
        if conn.dst_port not in self.brute_force_threshold['ports']:
            return False
        
        # Count failed connection attempts (RST, FIN flags)
        cutoff = datetime.now() - timedelta(seconds=self.brute_force_threshold['time_window'])
        failed_attempts = sum(
            1 for c in self.recent_connections
            if c.src_ip == profile.ip and
               c.dst_port == conn.dst_port and
               c.timestamp > cutoff and
               ('RST' in c.flags or 'FIN' in c.flags)
        )
        
        return failed_attempts > self.brute_force_threshold['failed_attempts']
    
    def _is_data_exfiltration(self, conn: ConnectionProfile) -> bool:
        """Detect potential data exfiltration"""
        # Check for large single connection
        if conn.bytes_sent > self.data_exfil_threshold['single_connection']:
            return True
        
        # Check for high sustained rate
        if conn.duration > 0:
            rate = conn.bytes_sent / conn.duration
            return rate > self.data_exfil_threshold['bytes_rate']
        
        return False
    
    def _is_c2_communication(self, profile: IPProfile, conn: ConnectionProfile) -> bool:
        """Detect command & control communication patterns"""
        # C2 characteristics:
        # - Regular beaconing intervals
        # - Small packet sizes
        # - Unusual ports
        # - Low data volume
        
        # Check for regular intervals (beaconing)
        recent_conns = [
            c for c in self.recent_connections
            if c.src_ip == profile.ip and c.dst_ip == conn.dst_ip
        ]
        
        if len(recent_conns) < 5:
            return False
        
        # Calculate time intervals
        intervals = []
        for i in range(1, len(recent_conns)):
            delta = (recent_conns[i].timestamp - recent_conns[i-1].timestamp).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return False
        
        # Check for regular intervals (low variance)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        # Regular beaconing: low variance relative to mean
        is_regular = (std_interval / max(mean_interval, 1)) < 0.2
        
        # Small packets
        avg_packet_size = (conn.bytes_sent + conn.bytes_recv) / max(conn.packets_sent + conn.packets_recv, 1)
        is_small_packets = avg_packet_size < 500  # < 500 bytes
        
        # Unusual port (not in common ports)
        common_ports = {80, 443, 53, 22, 21, 25, 110, 143, 587}
        is_unusual_port = conn.dst_port not in common_ports
        
        return is_regular and is_small_packets and is_unusual_port
    
    def _cleanup_old_profiles(self):
        """Remove profiles outside time window"""
        cutoff = datetime.now() - timedelta(seconds=self.time_window * 2)
        
        old_ips = [
            ip for ip, profile in self.ip_profiles.items()
            if profile.last_seen < cutoff
        ]
        
        for ip in old_ips:
            del self.ip_profiles[ip]