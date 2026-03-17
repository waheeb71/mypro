import logging
import json
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class APIValidationResult:
    is_valid: bool
    violation_reason: Optional[str] = None
    violation_score: float = 0.0

class APISchemaValidator:
    """
    Advanced API Security Validator.
    Protects against:
    - Mass Assignment
    - JSON Injections
    - Unexpected Payload Types
    - Schema Violations
    """

    def __init__(self, mode: str = "enforce", max_payload_size: int = 1024 * 512):
        self.mode = mode
        self.max_payload_size = max_payload_size
        self.schemas: Dict[str, Dict[str, Any]] = {}
        logger.info("APISchemaValidator initialized | mode=%s", mode)

    def load_schema(self, endpoint: str, schema: Dict[str, Any]) -> None:
        """Register an OpenAPI/Swagger-like JSON schema for an endpoint."""
        self.schemas[endpoint] = schema
        logger.debug("Loaded schema for endpoint: %s", endpoint)

    def validate(self, endpoint: str, payload_bytes: bytes, content_type: str = "application/json") -> APIValidationResult:
        """
        Validate incoming API request against schemas or generic JSON constraints.
        Returns validation result.
        """
        if not payload_bytes:
            return APIValidationResult(is_valid=True)
            
        if len(payload_bytes) > self.max_payload_size:
            return APIValidationResult(
                is_valid=False, 
                violation_reason="Payload size exceeded API maximum limits",
                violation_score=0.8
            )

        if "application/json" in content_type.lower():
            return self._validate_json(endpoint, payload_bytes)
        elif "application/graphql" in content_type.lower():
             return self._validate_graphql(payload_bytes)

        return APIValidationResult(is_valid=True)

    def _validate_json(self, endpoint: str, payload_bytes: bytes) -> APIValidationResult:
        """Parse and validate JSON payload."""
        try:
            # Detect JSON injection/parsing errors
            payload_str = payload_bytes.decode('utf-8')
            data = json.loads(payload_str)
        except UnicodeDecodeError:
            return APIValidationResult(
                is_valid=False, 
                violation_reason="Malformed Unicode in JSON payload",
                violation_score=0.8
            )
        except json.JSONDecodeError as e:
            return APIValidationResult(
                is_valid=False, 
                violation_reason=f"JSON Parse Error: {str(e)}",
                violation_score=0.6
            )

        # Generic heuristics (Mass assignment prevention)
        if isinstance(data, dict):
            if len(data.keys()) > 100:
                return APIValidationResult(
                    is_valid=False,
                    violation_reason="Exorbitant number of keys in JSON (possible Mass Assignment or DoS)",
                    violation_score=0.7
                )
                
            depth = self._get_dict_depth(data)
            if depth > 10:
                return APIValidationResult(
                    is_valid=False,
                    violation_reason=f"Extreme JSON nesting depth ({depth}) detected",
                    violation_score=0.9
                )

        # Strict Schema Validation (if endpoint schema exists)
        schema = self.schemas.get(endpoint)
        if schema and isinstance(data, dict):
            # Very basic schema check example
            expected_keys = schema.get("properties", {}).keys()
            for key in data.keys():
                if key not in expected_keys and not schema.get("additionalProperties", True):
                    return APIValidationResult(
                        is_valid=False,
                        violation_reason=f"Unexpected parameter '{key}' in strict API endpoint",
                        violation_score=0.5
                    )

        return APIValidationResult(is_valid=True)
        
    def _validate_graphql(self, payload_bytes: bytes) -> APIValidationResult:
        """Basic GraphQL inspection (Introspection blocks, extreme nesting)."""
        try:
            query = payload_bytes.decode('utf-8')
            
            # Block Introspection if pattern is found (often used for recon)
            if "__schema" in query or "__type" in query:
                 return APIValidationResult(
                    is_valid=False,
                    violation_reason="GraphQL Introspection query detected",
                    violation_score=0.6
                )
            
            # Query Depth/Alias DOS detection
            depth = query.count('{')
            if depth > 15:
                return APIValidationResult(
                    is_valid=False,
                    violation_reason=f"Extreme GraphQL query depth ({depth}) detected",
                    violation_score=0.8
                )
                
            return APIValidationResult(is_valid=True)
            
        except Exception as e:
            return APIValidationResult(
                is_valid=False,
                violation_reason=f"Malformed GraphQL query: {str(e)}",
                violation_score=0.6
            )

    @staticmethod
    def _get_dict_depth(d: Any, level: int = 1) -> int:
        if not isinstance(d, dict) or not d:
            return level
        return max(APISchemaValidator._get_dict_depth(v, level + 1) for v in d.values())
