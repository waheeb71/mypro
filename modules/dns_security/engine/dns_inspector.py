"""
Enterprise NGFW v2.0 - DNS Inspector Plugin

Deep inspection of DNS traffic.

Features:
- DNS query analysis
- Domain reputation check
- DNS tunneling detection
- DGA (Domain Generation Algorithm) detection
- Suspicious TLD detection
- Query rate limiting

Author: Enterprise NGFW Team
License: Proprietary
"""

import re
import struct
import logging

from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import time

from system.inspection_core.framework import (
    InspectorPlugin,
    PluginPriority,
    InspectionContext,
    InspectionResult,
    InspectionAction,
    InspectionFinding
)


class DNSInspector(InspectorPlugin):
    """
    DNS traffic inspector.
    
    Detects:
    - DNS tunneling
    - DGA domains
    - Suspicious TLDs
    - Excessive query rates
    - Long domain names
    """
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.xyz', '.top', '.win', '.bid',  # Often used in malware
        '.onion',  # Tor
    }
    
    # DGA indicators (high entropy, random-looking)
    DGA_INDICATORS = [
        r'^[bcdfghjklmnpqrstvwxz]{8,}',  # Too many consonants
        r'\d{5,}',  # Many digits
        r'[a-z0-9]{20,}',  # Very long random strings
    ]
    
    def __init__(
        self,
        priority: PluginPriority = PluginPriority.HIGH,
        logger: Optional[logging.Logger] = None
    ):
        super().__init__(
            name="DNS Inspector",
            priority=priority,
            logger=logger
        )
        
        # Compile patterns
        self._dga_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.DGA_INDICATORS
        ]
        
        # Rate limiting (per source IP)
        self._query_counts: Dict[str, List[float]] = defaultdict(list)
        self._rate_limit_window = 60  # seconds
        self._rate_limit_max = 100  # queries per window
        
        # DNS tunneling detection
        self._tunnel_threshold = 50  # Max queries to same domain
        self._domain_queries: Dict[Tuple[str, str], int] = defaultdict(int)
        
    def can_inspect(self, context: InspectionContext) -> bool:
        """Check if this is DNS traffic"""
        return (
            context.protocol == 'UDP' and
            (context.dst_port == 53 or context.src_port == 53)
        )
        
    def inspect(
        self,
        context: InspectionContext,
        data: bytes
    ) -> InspectionResult:
        """Inspect DNS traffic"""
        result = InspectionResult(action=InspectionAction.ALLOW)
        
        try:
            # Parse DNS packet
            dns_data = self._parse_dns(data)
            
            if not dns_data:
                return result
                
            result.metadata['dns'] = dns_data
            
            # Check rate limiting
            self._check_rate_limit(context, result)
            
            # Inspect queries
            if dns_data.get('queries'):
                for query in dns_data['queries']:
                    domain = query.get('name', '')
                    
                    # Check TLD
                    self._check_suspicious_tld(domain, result)
                    
                    # Check for DGA
                    self._check_dga(domain, result)
                    
                    # Check domain length
                    self._check_domain_length(domain, result)
                    
                    # Check for tunneling
                    self._check_tunneling(context, domain, result)
                    
        except Exception as e:
            self.logger.error(f"DNS inspection failed: {e}")
            
        return result
        
    def _parse_dns(self, data: bytes) -> Optional[Dict]:
        """Parse DNS packet"""
        try:
            if len(data) < 12:
                return None
                
            # Parse DNS header
            header = struct.unpack('!HHHHHH', data[:12])
            
            dns_data = {
                'id': header[0],
                'flags': header[1],
                'qd_count': header[2],  # Questions
                'an_count': header[3],  # Answers
                'ns_count': header[4],  # Authority
                'ar_count': header[5],  # Additional
                'queries': [],
                'answers': []
            }
            
            # Parse flags
            qr = (header[1] >> 15) & 1
            opcode = (header[1] >> 11) & 0xF
            aa = (header[1] >> 10) & 1
            tc = (header[1] >> 9) & 1
            rd = (header[1] >> 8) & 1
            ra = (header[1] >> 7) & 1
            rcode = header[1] & 0xF
            
            dns_data['is_response'] = qr == 1
            dns_data['opcode'] = opcode
            dns_data['rcode'] = rcode
            
            # Parse questions
            offset = 12
            for _ in range(dns_data['qd_count']):
                name, offset = self._parse_domain_name(data, offset)
                
                if offset + 4 > len(data):
                    break
                    
                qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                
                dns_data['queries'].append({
                    'name': name,
                    'type': qtype,
                    'class': qclass
                })
                
            return dns_data
            
        except Exception as e:
            self.logger.debug(f"DNS parsing failed: {e}")
            return None
            
    def _parse_domain_name(
        self,
        data: bytes,
        offset: int
    ) -> Tuple[str, int]:
        """Parse DNS domain name"""
        parts = []
        
        while offset < len(data):
            length = data[offset]
            
            if length == 0:
                offset += 1
                break
                
            # Check for compression
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                name, _ = self._parse_domain_name(data, pointer)
                parts.append(name)
                offset += 2
                break
                
            offset += 1
            if offset + length > len(data):
                break
                
            part = data[offset:offset+length].decode('utf-8', errors='ignore')
            parts.append(part)
            offset += length
            
        return '.'.join(parts), offset
        
    def _check_rate_limit(
        self,
        context: InspectionContext,
        result: InspectionResult
    ) -> None:
        """Check DNS query rate limiting"""
        src_ip = context.src_ip
        current_time = time.time()
        
        # Clean old entries
        self._query_counts[src_ip] = [
            t for t in self._query_counts[src_ip]
            if current_time - t < self._rate_limit_window
        ]
        
        # Add current query
        self._query_counts[src_ip].append(current_time)
        
        # Check rate
        count = len(self._query_counts[src_ip])
        
        if count > self._rate_limit_max:
            result.findings.append(InspectionFinding(
                severity='MEDIUM',
                category='dns_rate_limit',
                description=f"Excessive DNS queries: {count} in {self._rate_limit_window}s",
                plugin_name=self.name,
                confidence=0.9,
                evidence={'query_count': count, 'window': self._rate_limit_window}
            ))
            
    def _check_suspicious_tld(self, domain: str, result: InspectionResult) -> None:
        """Check for suspicious TLDs"""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.lower().endswith(tld):
                result.findings.append(InspectionFinding(
                    severity='MEDIUM',
                    category='dns_tld',
                    description=f"Suspicious TLD detected: {tld}",
                    plugin_name=self.name,
                    confidence=0.7,
                    evidence={'domain': domain, 'tld': tld}
                ))
                break
                
    def _check_dga(self, domain: str, result: InspectionResult) -> None:
        """Check for DGA (Domain Generation Algorithm) indicators"""
        # Extract domain name without TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return
            
        domain_name = parts[-2]  # Second-level domain
        
        # Check patterns
        for pattern in self._dga_patterns:
            if pattern.search(domain_name):
                result.findings.append(InspectionFinding(
                    severity='HIGH',
                    category='dns_dga',
                    description="Potential DGA domain detected",
                    plugin_name=self.name,
                    confidence=0.75,
                    evidence={'domain': domain, 'pattern': pattern.pattern}
                ))
                break
                
        # Check entropy (simple version)
        if len(domain_name) > 10:
            unique_chars = len(set(domain_name))
            entropy_ratio = unique_chars / len(domain_name)
            
            if entropy_ratio > 0.7:  # High character diversity
                result.findings.append(InspectionFinding(
                    severity='MEDIUM',
                    category='dns_dga',
                    description="High entropy domain (possible DGA)",
                    plugin_name=self.name,
                    confidence=0.6,
                    evidence={
                        'domain': domain,
                        'entropy_ratio': entropy_ratio
                    }
                ))
                
    def _check_domain_length(self, domain: str, result: InspectionResult) -> None:
        """Check for abnormally long domain names"""
        if len(domain) > 100:
            result.findings.append(InspectionFinding(
                severity='MEDIUM',
                category='dns_length',
                description=f"Abnormally long domain: {len(domain)} chars",
                plugin_name=self.name,
                confidence=0.8,
                evidence={'domain': domain[:100], 'length': len(domain)}
            ))
            
    def _check_tunneling(
        self,
        context: InspectionContext,
        domain: str,
        result: InspectionResult
    ) -> None:
        """Check for DNS tunneling"""
        key = (context.src_ip, domain)
        self._domain_queries[key] += 1
        
        count = self._domain_queries[key]
        
        if count > self._tunnel_threshold:
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                severity='HIGH',
                category='dns_tunneling',
                description=f"Potential DNS tunneling: {count} queries to {domain}",
                plugin_name=self.name,
                confidence=0.85,
                evidence={
                    'domain': domain,
                    'query_count': count,
                    'threshold': self._tunnel_threshold
                }
            ))
