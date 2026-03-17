"""
DNS Filter
Blackholing of malicious domains at DNS level.
"""

from typing import Set

class DNSFilter:
    """DNS Sinkhole"""
    
    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.sinkhole_ip = "0.0.0.0"

    def add_domain(self, domain: str):
        self.blocked_domains.add(domain)

    def check_query(self, domain: str) -> bool:
        """Return True if blocked"""
        return domain in self.blocked_domains

    def get_response(self) -> str:
        return self.sinkhole_ip
