"""
DNS Security Policy Evaluator
Provides final action decisions integrating filter rules and security findings.
"""

from enum import Enum
from typing import List
from modules.dns_security.models import ActionEnum


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    LOG_ONLY = "LOG_ONLY"


class DNSPolicyEvaluator:
    """
    Evaluates combined DNS findings and returns a single policy decision.
    Allows for future expansion of policy logic (e.g., trusted zones, split-horizon DNS).
    """

    def __init__(self, block_on_match: bool = True):
        self.block_on_match = block_on_match
        self._trusted_domains: List[str] = []

    def add_trusted_domain(self, domain: str):
        """Add a domain to the trusted zone (always allowed)."""
        self._trusted_domains.append(domain.lower())

    def evaluate(self, domain: str, findings: list, explicit_action: str = None) -> PolicyDecision:
        """
        Given the domain and inspection findings, return the final policy decision.
        
        - explicit_action: If a filter rule already provided an explicit ALLOW/BLOCK.
        - findings: List of InspectionFinding from the plugin.
        """
        # Trusted domain override — always allow
        for trusted in self._trusted_domains:
            if domain.lower().endswith(trusted) or domain.lower() == trusted:
                return PolicyDecision.ALLOW

        # Explicit rule match from filter DB
        if explicit_action == ActionEnum.ALLOW.value:
            return PolicyDecision.ALLOW
        if explicit_action == ActionEnum.BLOCK.value:
            return PolicyDecision.BLOCK

        # Findings-based decision
        if findings and self.block_on_match:
            return PolicyDecision.BLOCK

        return PolicyDecision.ALLOW
