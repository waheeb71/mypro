"""
CyberNexus NGFW — Threat Intelligence Manager
===============================================
Fetches, normalizes, and stores external threat intelligence feeds.

Controlled by features.yaml:
  features.threat_intel.enabled: true
  features.threat_intel.providers.abuseipdb.enabled: true

Usage:
    intel = ThreatIntelManager.instance()
    result = await intel.lookup_ip("1.2.3.4")
    if result.is_malicious:
        return InspectionResult(action="BLOCK", reason=result.reason)
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Result contract
# ──────────────────────────────────────────────────────────────────────

@dataclass
class IntelResult:
    ip: str = ""
    score: float = 0.0              # 0.0 = clean, 1.0 = definitely malicious
    is_malicious: bool = False
    source: str = ""
    reason: str = ""
    last_seen: float = 0.0


# ──────────────────────────────────────────────────────────────────────
# In-memory reputation store (Redis-ready interface)
# ──────────────────────────────────────────────────────────────────────

class IPReputationStore:
    """
    O(1) in-memory IP reputation cache.
    Interface compatible with a Redis HSET backend for production.
    """

    def __init__(self):
        self._store: Dict[str, IntelResult] = {}
        self._ttl_s: int = 3600      # Entries expire after 1 hour

    def set(self, ip: str, result: IntelResult) -> None:
        self._store[ip] = result

    def get(self, ip: str) -> Optional[IntelResult]:
        result = self._store.get(ip)
        if result and (time.time() - result.last_seen) > self._ttl_s:
            del self._store[ip]
            return None
        return result

    def is_blocked(self, ip: str, threshold: float = 0.85) -> bool:
        result = self.get(ip)
        return result is not None and result.score >= threshold

    def size(self) -> int:
        return len(self._store)

    def clear(self) -> None:
        self._store.clear()


# ──────────────────────────────────────────────────────────────────────
# Threat Intel Manager
# ──────────────────────────────────────────────────────────────────────

class ThreatIntelManager:
    """
    Orchestrates threat intel feeds and provides O(1) IP/domain reputation lookups.

    When threat_intel.enabled = false → all lookups return clean result.
    Feed refresh runs as background task every N minutes (configurable).
    """

    _instance: Optional["ThreatIntelManager"] = None

    def __init__(self):
        self._store = IPReputationStore()
        self._refresh_task: Optional[asyncio.Task] = None
        self._flags = None
        self._last_refresh: float = 0.0

    @classmethod
    def instance(cls) -> "ThreatIntelManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start(self) -> None:
        """Start background refresh loop."""
        from system.config.feature_flags import FeatureFlagManager
        self._flags = FeatureFlagManager.instance()

        if not self._flags.current.threat_intel.enabled:
            logger.info("[ThreatIntel] Disabled via feature flag")
            return

        self._refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info("[ThreatIntel] Started ✓")

    async def lookup_ip(self, ip: str) -> IntelResult:
        """
        O(1) IP reputation lookup.
        Returns clean result when threat_intel is disabled.
        """
        if self._flags and not self._flags.current.threat_intel.enabled:
            return IntelResult(ip=ip, score=0.0, is_malicious=False, source="disabled")

        cached = self._store.get(ip)
        if cached:
            return cached

        # Not in cache — return clean (will be populated on next refresh)
        return IntelResult(ip=ip, score=0.0, reason="Not in intel store")

    def is_ip_blocked(self, ip: str) -> bool:
        """Fast check for firewall ACL integration."""
        if not self._flags or not self._flags.current.threat_intel.enabled:
            return False
        threshold = self._flags.current.threat_intel.block_threshold
        return self._store.is_blocked(ip, threshold)

    def get_stats(self) -> dict:
        return {
            "enabled": self._flags.current.threat_intel.enabled if self._flags else False,
            "cached_ips": self._store.size(),
            "last_refresh": self._last_refresh,
        }

    # ── Internal ───────────────────────────────────────────────────

    async def _refresh_loop(self) -> None:
        """Background task: fetch feeds every N minutes."""
        while True:
            try:
                await self._do_refresh()
            except Exception as exc:
                logger.error(f"[ThreatIntel] Refresh error: {exc}")

            interval = self._flags.current.threat_intel.refresh_interval_minutes * 60
            await asyncio.sleep(interval)

    async def _do_refresh(self) -> None:
        """Fetch all enabled providers and populate the store."""
        logger.info("[ThreatIntel] Refreshing feeds...")
        fetched = 0

        providers = self._flags.current.threat_intel
        # Provider configs are read from features.yaml
        # Actual fetch calls go to provider-specific modules (Phase 7F expansion)
        try:
            entries = await self._fetch_abuseipdb()
            for entry in entries:
                entry.last_seen = time.time()
                self._store.set(entry.ip, entry)
                fetched += 1
        except Exception as exc:
            logger.warning(f"[ThreatIntel] AbuseIPDB fetch failed: {exc}")

        self._last_refresh = time.time()
        logger.info(f"[ThreatIntel] Refresh complete — {fetched} entries cached")

    async def _fetch_abuseipdb(self) -> list:
        """
        Fetch from AbuseIPDB blacklist API.
        Requires: ABUSEIPDB_API_KEY environment variable.
        """
        import os
        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not api_key:
            logger.debug("[ThreatIntel:AbuseIPDB] No API key — skipping")
            return []

        try:
            import aiohttp
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"confidenceMinimum": 90, "limit": 10000}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        logger.warning(f"[ThreatIntel:AbuseIPDB] HTTP {resp.status}")
                        return []
                    data = await resp.json()
                    results = []
                    for item in data.get("data", []):
                        score = item.get("abuseConfidenceScore", 0) / 100.0
                        results.append(IntelResult(
                            ip=item["ipAddress"],
                            score=score,
                            is_malicious=score >= 0.85,
                            source="abuseipdb",
                            reason=f"AbuseIPDB confidence: {item.get('abuseConfidenceScore')}%",
                            last_seen=time.time(),
                        ))
                    return results
        except ImportError:
            logger.warning("[ThreatIntel:AbuseIPDB] aiohttp not installed")
            return []
