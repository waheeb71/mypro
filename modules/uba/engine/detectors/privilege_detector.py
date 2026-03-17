"""
Enterprise NGFW — UBA Privilege Escalation / Sensitive Service Detector

Detects access to high-privilege or previously never-used services.
Combines unknown-service detection with a known privileged-service list.

Score: 0.0 – 0.35
"""

import logging

logger = logging.getLogger(__name__)

# Default privileged service keywords / port strings
DEFAULT_PRIVILEGED = frozenset([
    "ssh", "rdp", "winrm", "sudo", "root", "admin", "administrator",
    "22", "23", "3389", "5985", "5986", "445", "139",
    "ldap", "389", "636",  # directory services
    "snmp", "161", "162",  # network management
])


class PrivilegeDetector:
    """
    Detect access to sensitive / privileged services that the user
    has not previously accessed.

    Two signal levels:
    - Unknown + privileged → high score
    - Unknown + normal → lower score (new service discovery)
    """

    MAX_SCORE = 0.35

    def __init__(self, privileged_services: list | None = None):
        self._privileged = DEFAULT_PRIVILEGED | frozenset(
            s.lower() for s in (privileged_services or [])
        )

    def _is_privileged(self, service: str) -> bool:
        svc = service.lower()
        return svc in self._privileged or any(p in svc for p in self._privileged)

    def analyze(
        self,
        profile,
        target_service: str,
    ) -> tuple[float, list[str]]:
        """
        Returns (score, flags).
        """
        flags: list[str] = []
        score = 0.0

        if not target_service:
            return 0.0, []

        known_services: list = profile.known_services or []
        is_new = target_service not in known_services

        if not is_new:
            return 0.0, []   # normal

        privileged = self._is_privileged(target_service)

        if privileged:
            score = self.MAX_SCORE
            flags.append(f"privilege:new_privileged_service:{target_service}")
        elif profile.baseline_locked:
            # Known baseline, truly unexpected service
            score = self.MAX_SCORE * 0.4
            flags.append(f"privilege:new_service:{target_service}")

        return score, flags

    def update_known_services(
        self,
        known_services: list,
        target_service: str,
        max_services: int = 100,
    ) -> list:
        if not target_service:
            return known_services
        known_services = list(known_services or [])
        if target_service not in known_services:
            known_services.append(target_service)
        if len(known_services) > max_services:
            known_services = known_services[-max_services:]
        return known_services
