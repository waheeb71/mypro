#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - eBPF XDP Engine
═══════════════════════════════════════════════════════════════════

Manages eBPF XDP/TC programs for high-speed packet filtering at
kernel level. Implements feedback loop with user-space proxy.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
import socket
import struct
import ipaddress
from typing import Optional, Set, TYPE_CHECKING
from pathlib import Path
from datetime import datetime

if TYPE_CHECKING:
    from system.telemetry.events import UnifiedEventSink
    from system.telemetry.events.event_schema import EventVerdict

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logging.warning("BCC not available. eBPF features will be disabled.")

logger = logging.getLogger(__name__)


class XDPEngine:
    """
    eBPF Manager for kernel-level packet filtering
    
    Implements XDP (eXpress Data Path) for ultra-fast packet filtering
    and TC (Traffic Control) for additional processing.
    """
    
    def __init__(self, config: dict, event_sink: Optional['UnifiedEventSink'] = None):
        self.config = config
        self.ebpf_config = config.get('ebpf', {})
        
        self.enabled = self.ebpf_config.get('enabled', True) and BCC_AVAILABLE
        
        # Event sink for unified logging
        self.event_sink = event_sink
        
        if not self.enabled:
            logger.warning("eBPF is disabled or BCC not available")
            return
        
        self.interface = self.ebpf_config.get('interface', 'eth0')
        self.xdp_mode = self.ebpf_config.get('xdp_mode', 'native')
        
        # eBPF program
        self.bpf: Optional[BPF] = None
        
        # Maps for blocked IPs and rate limiting
        self.blocked_ips: Set[str] = set()
        self.rate_limited_ips: Set[str] = set()
        
        # Feedback loop
        self.feedback_interval = self.ebpf_config.get('feedback_interval', 5)
        self.feedback_task = None
        
        # ML Anomaly Integration
        self.ml_config = self.ebpf_config.get('ml_integration', {})
        self.ml_enabled = self.ml_config.get('enabled', True)
        self.ml_threshold = self.ml_config.get('confidence_threshold', 0.85)

        model_path = config.get('ml', {}).get('anomaly_detection', {}).get('model_path')
        from system.ml_core.anomaly_detector import AnomalyDetector
        self.anomaly_detector = AnomalyDetector(model_path=model_path)
        
        logger.info(f"eBPF Manager initialized for interface {self.interface} (ML Enabled: {self.ml_enabled})")
    
    async def start(self):
        """Start eBPF programs and attach to interface"""
        if not self.enabled:
            logger.info("eBPF not enabled, skipping")
            return
        
        try:
            logger.info("Loading eBPF programs...")
            
            # Load eBPF program
            self.bpf = BPF(text=self._get_xdp_program())
            
            # Get function
            fn = self.bpf.load_func("xdp_filter", BPF.XDP)
            
            # Attach to interface
            flags = self._get_xdp_flags()
            self.bpf.attach_xdp(self.interface, fn, flags)
            
            logger.info(f"✅ eBPF XDP program attached to {self.interface}")
            
            # Start feedback loop
            self.feedback_task = asyncio.create_task(self._feedback_loop())
            
            logger.info("✅ eBPF Manager started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start eBPF: {e}", exc_info=True)
            self.enabled = False
    
    async def stop(self):
        """Stop eBPF programs and detach from interface"""
        if not self.enabled or not self.bpf:
            return
        
        try:
            logger.info("Stopping eBPF Manager...")
            
            # Stop feedback loop
            if self.feedback_task:
                self.feedback_task.cancel()
                try:
                    await self.feedback_task
                except asyncio.CancelledError:
                    pass
            
            # Detach XDP
            self.bpf.remove_xdp(self.interface)
            
            logger.info("eBPF Manager stopped")
            
        except Exception as e:
            logger.error(f"Error stopping eBPF: {e}")
    
    def _get_xdp_flags(self) -> int:
        """Get XDP attachment flags based on mode"""
        if self.xdp_mode == 'native':
            return 0  # XDP_FLAGS_DRV_MODE
        elif self.xdp_mode == 'offload':
            return 1 << 2  # XDP_FLAGS_HW_MODE
        else:  # generic
            return 1 << 1  # XDP_FLAGS_SKB_MODE
    
    def _get_xdp_program(self) -> str:
        """
        Get eBPF XDP program source code
        
        This program runs in the kernel for every packet at the NIC driver level.
        """
        return """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// ═══ BPF Maps ═══

// Blocked IP addresses (key: IP, value: 1 = blocked)
BPF_HASH(blocked_ips, u32, u32, 100000);

// Rate limiting (key: IP, value: packet count)
BPF_HASH(rate_limit, u32, u64, 50000);

// Statistics (key: 0 = total_packets, 1 = blocked_packets, 2 = rate_limited)
BPF_ARRAY(stats, u64, 10);

// Configuration (key: 0 = rate_limit_pps, 1 = rate_limit_burst)
BPF_ARRAY(config, u64, 10);

// ═══ Helper Functions ═══

static inline int check_ip_blocked(u32 ip) {
    u32 *blocked = blocked_ips.lookup(&ip);
    return (blocked != NULL && *blocked == 1);
}

static inline int check_rate_limit(u32 ip) {
    u64 *count = rate_limit.lookup(&ip);
    u64 now = bpf_ktime_get_ns() / 1000000000;  // Convert to seconds
    
    if (count == NULL) {
        // First packet from this IP
        u64 new_count = 1;
        rate_limit.update(&ip, &new_count);
        return 0;
    }
    
    // Get rate limit config
    u32 key = 0;
    u64 *pps_limit = config.lookup(&key);
    u64 rate_limit_pps = (pps_limit != NULL) ? *pps_limit : 1000;
    
    key = 1;
    u64 *burst_limit = config.lookup(&key);
    u64 rate_limit_burst = (burst_limit != NULL) ? *burst_limit : 5000;
    
    // Simple rate limiting logic
    if (*count >= rate_limit_pps) {
        // Rate limit exceeded
        return 1;
    }
    
    // Increment counter
    __sync_fetch_and_add(count, 1);
    return 0;
}

static inline void update_stats(int stat_type) {
    u32 key = stat_type;
    u64 *value = stats.lookup(&key);
    
    if (value != NULL) {
        __sync_fetch_and_add(value, 1);
    } else {
        u64 initial = 1;
        stats.update(&key, &initial);
    }
}

// ═══ Main XDP Program ═══

int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    u32 src_ip = ip->saddr;
    
    // Update total packets stats
    update_stats(0);
    
    // Check if IP is blocked
    if (check_ip_blocked(src_ip)) {
        update_stats(1);  // Blocked packets
        return XDP_DROP;
    }
    
    // Check rate limiting
    if (check_rate_limit(src_ip)) {
        update_stats(2);  // Rate limited packets
        return XDP_DROP;
    }
    
    // Only process TCP traffic to proxy ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        
        u16 dest_port = ntohs(tcp->dest);
        
        // Allow traffic to proxy ports (8080, 8443)
        if (dest_port == 8080 || dest_port == 8443 || dest_port == 443) {
            return XDP_PASS;
        }
    }
    
    // Pass all other packets
    return XDP_PASS;
}
"""
    
    async def add_blocked_ip(self, ip: str):
        """
        Add IP address to kernel-level blocklist
        
        Args:
            ip: IP address to block
        """
        if not self.enabled or not self.bpf:
            return
        
        try:
            # Convert IP to integer
            ip_int = int(ipaddress.IPv4Address(ip))
            
            # Update eBPF map
            blocked_ips = self.bpf.get_table("blocked_ips")
            blocked_ips[blocked_ips.Key(ip_int)] = blocked_ips.Leaf(1)
            
            self.blocked_ips.add(ip)
            logger.info(f"🚫 Added {ip} to eBPF blocklist")
            
        except Exception as e:
            logger.error(f"Failed to add IP to blocklist: {e}")
    
    async def remove_blocked_ip(self, ip: str):
        """Remove IP address from blocklist"""
        if not self.enabled or not self.bpf:
            return
        
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            
            blocked_ips = self.bpf.get_table("blocked_ips")
            blocked_ips.pop(blocked_ips.Key(ip_int))
            
            self.blocked_ips.discard(ip)
            logger.info(f"✅ Removed {ip} from eBPF blocklist")
            
        except Exception as e:
            logger.error(f"Failed to remove IP from blocklist: {e}")
    
    async def add_blocked_domain(self, domain: str):
        """
        Add domain to blocklist (requires DNS resolution)
        
        This is called from the feedback loop when suspicious domains are detected.
        """
        try:
            # Resolve domain to IP
            loop = asyncio.get_event_loop()
            addrinfo = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            
            for info in addrinfo:
                ip = info[4][0]
                await self.add_blocked_ip(ip)
                logger.info(f"🚫 Blocked domain {domain} -> {ip}")
                
        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")
    
    async def set_rate_limit(self, pps: int, burst: int):
        """
        Set rate limiting parameters
        
        Args:
            pps: Packets per second limit
            burst: Burst limit
        """
        if not self.enabled or not self.bpf:
            return
        
        try:
            config = self.bpf.get_table("config")
            config[config.Key(0)] = config.Leaf(pps)
            config[config.Key(1)] = config.Leaf(burst)
            
            logger.info(f"⚙️  Set rate limit: {pps} pps, burst {burst}")
            
        except Exception as e:
            logger.error(f"Failed to set rate limit: {e}")
    
    def get_statistics(self) -> dict:
        """Get eBPF statistics"""
        if not self.enabled or not self.bpf:
            return {}
        
        try:
            stats = self.bpf.get_table("stats")
            
            return {
                'total_packets': stats[stats.Key(0)].value if stats.Key(0) in stats else 0,
                'blocked_packets': stats[stats.Key(1)].value if stats.Key(1) in stats else 0,
                'rate_limited_packets': stats[stats.Key(2)].value if stats.Key(2) in stats else 0,
                'blocked_ips_count': len(self.blocked_ips),
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    async def _feedback_loop(self):
        """
        Feedback loop between eBPF and user-space proxy
        
        Periodically checks for suspicious patterns and updates eBPF maps.
        Sends events to UnifiedEventSink.
        """
        logger.info("Starting eBPF feedback loop...")
        
        try:
            while True:
                await asyncio.sleep(self.feedback_interval)
                
                # Get statistics
                stats = self.get_statistics()
                
                if stats:
                    logger.debug(
                        f"eBPF Stats: "
                        f"Total={stats.get('total_packets', 0)} "
                        f"Blocked={stats.get('blocked_packets', 0)} "
                        f"RateLimited={stats.get('rate_limited_packets', 0)} "
                        f"BlockedIPs={stats.get('blocked_ips_count', 0)}"
                    )
                    
                    # Send aggregate stats to event sink
                    if self.event_sink and stats.get('blocked_packets', 0) > 0:
                        await self._send_xdp_summary_event(stats)
                
                # Here we can implement more sophisticated feedback logic:
                # 1. Analyze traffic patterns
                # 2. Detect anomalies
                # 3. Update eBPF maps based on ML predictions
                # 4. Adjust rate limits dynamically
                
                # AI/ML integration
                if self.ml_enabled:
                    await self._analyze_and_update()
                
        except asyncio.CancelledError:
            logger.info("eBPF feedback loop cancelled")
        except Exception as e:
            logger.error(f"Error in feedback loop: {e}", exc_info=True)
    
    async def _send_xdp_summary_event(self, stats: dict):
        """
        Send XDP summary event to Unified Sink
        
        Args:
            stats: XDP statistics dictionary
        """
        try:
            from system.telemetry.events.event_schema import create_event_from_xdp, EventVerdict
            
            # Create aggregate event for XDP activity
            event = create_event_from_xdp(
                src_ip="0.0.0.0",  # Aggregate event
                dst_ip="0.0.0.0",
                src_port=0,
                dst_port=0,
                protocol="aggregate",
                interface=self.interface,
                bytes_count=0,
                packets_count=stats.get('blocked_packets', 0),
                verdict=EventVerdict.DROP,
                reason=f"XDP blocked {stats.get('blocked_packets', 0)} packets, "
                       f"rate-limited {stats.get('rate_limited_packets', 0)}",
                flow_id=f"xdp-summary-{datetime.now().timestamp()}",
            )
            
            await self.event_sink.submit_event(event)
            
        except Exception as e:
            logger.error(f"Error sending XDP event to sink: {e}")
    
    async def _analyze_and_update(self):
        """
        Analyze traffic patterns using ML models and update eBPF maps instantly.
        """
        if not self.ml_enabled or not self.bpf:
            return

        try:
            from system.ml_core.anomaly_detector import TrafficFeatures
            
            # Since true per-IP feature extraction requires deep kernel flow tracking,
            # we securely sample active IPs and their packet counts from the BPF rate limit map.
            rate_limit_map = self.bpf.get_table("rate_limit")
            
            suspect_ips = []
            for k, v in rate_limit_map.items():
                # Analyze streams with moderate activity
                if v.value > 50: 
                    ip_str = str(ipaddress.IPv4Address(k.value))
                    if ip_str not in self.blocked_ips:
                        suspect_ips.append((k, ip_str, v.value))
            
            for key, ip_str, pkt_count in suspect_ips:
                # Structure synthetic TrafficFeatures derived from kernel observations
                features = TrafficFeatures(
                    packets_per_second=pkt_count / self.feedback_interval,
                    bytes_per_second=(pkt_count * 1500) / self.feedback_interval,
                    avg_packet_size=1500,
                    packet_size_variance=200,
                    tcp_ratio=0.9,
                    udp_ratio=0.1,
                    syn_ratio=0.2, # Suspect elevated SYN requests
                    unique_dst_ports=2,
                    unique_src_ports=int(pkt_count/2),
                    inter_arrival_time_mean=0.01,
                    inter_arrival_time_variance=0.05,
                    failed_connections=int(pkt_count * 0.15),
                    connection_attempts=pkt_count,
                    reputation_score=50.0 
                )
                
                # ML Inference Execution
                result = self.anomaly_detector.detect(features)
                
                if result.is_anomaly and result.confidence >= self.ml_threshold:
                    logger.warning(f"🚨 ML Pipeline detected anomaly from {ip_str} (Conf: {result.confidence:.2f}). Dropping via zero-millisecond eBPF!")
                    await self.add_blocked_ip(ip_str)
                    
                    # Log event
                    if self.event_sink:
                        from system.telemetry.events.event_schema import create_event_from_xdp, EventVerdict
                        event = create_event_from_xdp(
                            src_ip=ip_str,
                            dst_ip="0.0.0.0",
                            src_port=0,
                            dst_port=0,
                            protocol="tcp",
                            interface=self.interface,
                            bytes_count=pkt_count * 1500,
                            packets_count=pkt_count,
                            verdict=EventVerdict.DROP,
                            reason=f"ML Anomaly Detected (Confidence: {result.confidence:.2f})",
                            flow_id=f"ml-block-{ip_str}-{datetime.now().timestamp()}",
                        )
                        await self.event_sink.submit_event(event)

        except Exception as e:
            logger.error(f"Error in eBPF ML analysis loop: {e}")


class XDPEngineMock:
    """
    Mock eBPF Manager for systems without BCC/eBPF support
    
    Provides same interface but no actual functionality.
    """
    
    def __init__(self, config: dict, event_sink: Optional['UnifiedEventSink'] = None):
        self.config = config
        self.event_sink = event_sink
        self.enabled = False
        logger.info("Using mock eBPF Manager (BCC not available)")
    
    async def start(self):
        logger.info("Mock eBPF Manager: start() called (no-op)")
    
    async def stop(self):
        logger.info("Mock eBPF Manager: stop() called (no-op)")
    
    async def add_blocked_ip(self, ip: str):
        logger.debug(f"Mock eBPF: would block IP {ip}")
    
    async def remove_blocked_ip(self, ip: str):
        logger.debug(f"Mock eBPF: would unblock IP {ip}")
    
    async def add_blocked_domain(self, domain: str):
        logger.debug(f"Mock eBPF: would block domain {domain}")
    
    async def set_rate_limit(self, pps: int, burst: int):
        logger.debug(f"Mock eBPF: would set rate limit {pps} pps, burst {burst}")
    
    def get_statistics(self) -> dict:
        return {
            'total_packets': 0,
            'blocked_packets': 0,
            'rate_limited_packets': 0,
            'blocked_ips_count': 0,
        }


def create_xdp_engine(config: dict, event_sink: Optional['UnifiedEventSink'] = None):
    """
    Factory function to create appropriate eBPF manager
    
    Args:
        config: Configuration dictionary
        event_sink: Optional unified event sink
    
    Returns:
        XDPEngine or XDPEngineMock
    """
    if BCC_AVAILABLE and config.get('ebpf', {}).get('enabled', True):
        return XDPEngine(config, event_sink)
    else:
        return XDPEngineMock(config, event_sink)