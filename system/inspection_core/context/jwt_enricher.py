import logging
import base64
import json
from typing import Optional

from system.inspection_core.framework.plugin_base import AbstractEnricher, InspectionContext

class JWTContextEnricher(AbstractEnricher):
    """
    Extracts identity from JWT Tokens for Cloud/API traffic.
    Reads Authorization headers to stamp IdentityContext with Token-based users.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(name="JWT_Context_Enricher", logger=logger)

    def enrich(self, context: InspectionContext) -> None:
        """Parse JWT from request and elevate identity context."""
        
        # If no raw data is available yet, skip.
        if not context.raw_data:
            return

        try:
            payload = context.raw_data.decode('utf-8', errors='ignore')
            auth_header_idx = payload.find("Authorization: Bearer ")
            
            if auth_header_idx != -1:
                start_idx = auth_header_idx + len("Authorization: Bearer ")
                end_idx = payload.find("\r\n", start_idx)
                token = payload[start_idx:end_idx].strip()
                
                parts = token.split('.')
                if len(parts) == 3:
                    # Parse the payload part (middle)
                    padded_payload = parts[1] + '=' * (-len(parts[1]) % 4)
                    decoded_bytes = base64.urlsafe_b64decode(padded_payload)
                    jwt_data = json.loads(decoded_bytes.decode('utf-8'))
                    
                    # Stamp the Context
                    context.identity.type = "user"
                    context.identity.source = "jwt_token"
                    context.identity.username = jwt_data.get("sub") or jwt_data.get("username")
                    context.identity.is_authenticated = True
                    context.identity.auth_method = "JWT"
                    context.identity.confidence = 0.9  # High confidence for valid tokens
                    
                    self.logger.debug(f"[JWT Enricher] Extracted identity: {context.identity.username}")
                    
        except Exception as e:
            self.logger.debug(f"Failed to parse JWT: {e}")

    async def enrich_async(self, context: InspectionContext) -> None:
        import asyncio
        await asyncio.to_thread(self.enrich, context)
