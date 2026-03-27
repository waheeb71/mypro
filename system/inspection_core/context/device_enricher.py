import logging
import hashlib
from typing import Optional
from system.inspection_core.framework.plugin_base import AbstractEnricher, InspectionContext

class DeviceContextEnricher(AbstractEnricher):
    """
    Generates a unique Device ID fingerprint when no explicit user login is found.
    Implements Device-Based Identity fallback mechanisms.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(name="Device_Context_Enricher", logger=logger)

    def enrich(self, context: InspectionContext) -> None:
        """Fingerprint the device attempting to connect."""
        
        # If user identity is already resolved (e.g. JWT), we don't strictly need this as primary,
        # but we ALWAYS generate device_id to correlate sessions.
        
        fingerprint_data = f"{context.src_ip}"
        
        # Extract OS/Browser User-Agent if HTTP parsed data is available
        if context.parsed_http and "User-Agent" in context.parsed_http.get("headers", {}):
            fingerprint_data += context.parsed_http["headers"]["User-Agent"]
            
        # Hash to create a deterministic Device ID
        device_id = hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()[:16]
        
        context.identity.device_id = device_id
        
        # If no other identity source claimed this, set fallback
        if context.identity.type == "anonymous":
            context.identity.type = "device"
            context.identity.source = "device_fingerprint"
            context.identity.confidence = 0.6  # Medium confidence for pure IP/UA tracking
            
    async def enrich_async(self, context: InspectionContext) -> None:
        import asyncio
        await asyncio.to_thread(self.enrich, context)
