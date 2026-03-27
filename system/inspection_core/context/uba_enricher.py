import logging
import time
from typing import Optional, Dict

from system.inspection_core.framework.plugin_base import AbstractEnricher, InspectionContext
from system.inspection_core.context.identity import IdentityContext
from system.inspection_core.context.risk import RiskContext
from system.database.database import UBAUserProfile

class UBAContextEnricher(AbstractEnricher):
    """
    Queries UBA Profiles to attach Identity and Risk context to every incoming packet.
    Implements Zero Trust Identity Verification layer before any Inspection Plugin runs.
    """
    
    def __init__(self, db_manager, logger: Optional[logging.Logger] = None):
        super().__init__(name="UBA_Context_Enricher", logger=logger)
        self.db = db_manager
        
        # High-speed in-memory cache to prevent DB lookups on every packet
        # Maps IP Address -> dict(username, user_id, risk_score, risk_level, peer_group)
        self._ip_cache: Dict[str, dict] = {}
        self._last_cache_update = 0
        self._cache_ttl = 60 # Refresh every 60 seconds

    def _sync_cache(self):
        """Pre-load UBA Profiles into memory mapped by known IPs."""
        now = time.time()
        if now - self._last_cache_update < self._cache_ttl and self._ip_cache:
            return
            
        try:
            with self.db.session() as session:
                profiles = session.query(UBAUserProfile).all()
                new_cache = {}
                for p in profiles:
                    for ip in (p.known_ips or []):
                        new_cache[ip] = {
                            "username": p.username,
                            "user_id": p.user_id,
                            "risk_score": p.risk_score,
                            "risk_level": p.risk_level,
                            "peer_group": p.peer_group
                        }
                self._ip_cache = new_cache
                self._last_cache_update = now
                self.logger.debug(f"UBA Enricher Cache Synced. Loaded {len(self._ip_cache)} IPs.")
        except Exception as e:
            self.logger.error(f"Failed to sync UBA Cache: {e}")

    def enrich(self, context: InspectionContext) -> None:
        """Stamp the identity and risk onto the packet."""
        self._sync_cache()
        
        user_info = self._ip_cache.get(context.src_ip)
        
        if user_info:
            # Stamp Identity
            context.identity.type = "user"
            context.identity.source = "ip_mapping"
            context.identity.confidence = 0.8  # Trusted internal map
            
            context.identity.username = user_info["username"]
            context.identity.user_id = user_info["user_id"]
            context.identity.department = user_info["peer_group"]
            context.identity.roles = [user_info["peer_group"]] if user_info["peer_group"] else []
            context.identity.is_authenticated = True
            context.identity.auth_method = "UBA_Heuristics"
            
            # Stamp Risk
            # Convert 0-100 UBA score to 0.0-1.0 standard risk continuum
            context.risk.uba_score = float(user_info["risk_score"]) / 100.0
            context.risk.is_compromised = user_info["risk_level"] in ("high", "critical")
            
        else:
            # Anonymous / Unrecognized IP
            # Don't overwrite if another enricher (like JWT) already identified them
            if context.identity.type == "anonymous":
                context.identity.type = "device"  # Fallback to device type until identified
                context.identity.source = "ip_fallback"
                context.identity.confidence = 0.5
                context.identity.username = "anonymous"
                context.identity.is_authenticated = False
            
            context.risk.uba_score = 0.5 # Default medium risk for unknown entities
            context.risk.is_compromised = False
            
    async def enrich_async(self, context: InspectionContext) -> None:
        """Asynchronously enrich the context."""
        import asyncio
        await asyncio.to_thread(self.enrich, context)
