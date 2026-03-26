"""
Enterprise CyberNexus — WAF GraphQL Inspector

Protects against deep nested queries (Denial of Service) and query batching
exhaustion attacks common in modern GraphQL APIs.
"""
import json
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class GraphQLValidationResult:
    def __init__(self, is_valid: bool, violation_score: float = 0.0, reason: str = ""):
        self.is_valid = is_valid
        self.violation_score = violation_score
        self.violation_reason = reason

class GraphQLInspector:
    """
    Analyzes GraphQL payloads for common attack vectors.
    """
    def __init__(self, max_depth: int = 5, max_batched_queries: int = 10, detect_introspection: bool = True):
        self.max_depth = max_depth
        self.max_batched_queries = max_batched_queries
        self.detect_introspection = detect_introspection

    def inspect(self, decoded_payload: str, content_type: str = "") -> Tuple[bool, GraphQLValidationResult]:
        """
        Returns (is_graphql, result)
        """
        # Quick heuristic to see if this might be GraphQL
        if "graphql" not in content_type.lower() and "query" not in decoded_payload and "mutation" not in decoded_payload:
            return False, GraphQLValidationResult(True)

        try:
            # Most GraphQL requests are sent as JSON: {"query": "{ ... }"}
            payload_json = json.loads(decoded_payload)
        except json.JSONDecodeError:
            # If it's not JSON, it could be raw application/graphql
            if "graphql" in content_type:
                payload_json = {"query": decoded_payload}
            else:
                return False, GraphQLValidationResult(True)

        # Handle Query Batching (Array of queries)
        if isinstance(payload_json, list):
            if len(payload_json) > self.max_batched_queries:
                return True, GraphQLValidationResult(
                    is_valid=False, 
                    violation_score=0.85, 
                    reason=f"GraphQL Query Batching limit exceeded. Found {len(payload_json)} queries (max {self.max_batched_queries})."
                )
            
            # Inspect first query deeply for simplicity in batch
            if len(payload_json) > 0 and "query" in payload_json[0]:
                query_str = payload_json[0].get("query", "")
            else:
                return True, GraphQLValidationResult(True)
        else:
            query_str = payload_json.get("query", "")

        if not isinstance(query_str, str) or not query_str.strip():
            return True, GraphQLValidationResult(True)

        # 1. Introspection Attack Check
        if self.detect_introspection and "__schema" in query_str or "__type" in query_str:
            return True, GraphQLValidationResult(
                is_valid=False,
                violation_score=0.75,
                reason="GraphQL Introspection Query Probing Detected."
            )

        # 2. Maximum Depth Parsing (Prevent Nested DoS)
        depth = self._calculate_depth(query_str)
        if depth > self.max_depth:
            return True, GraphQLValidationResult(
                is_valid=False,
                violation_score=0.90,
                reason=f"GraphQL Deep Nested Query Detected. Depth {depth} exceeds max {self.max_depth}."
            )

        # 3. Alias Batching (Multiple top-level queries in one string)
        # simplistic check counting top-level brackets/fragments
        alias_count = query_str.count(":")
        if alias_count > (self.max_batched_queries * 3): # Rough heuristic
             return True, GraphQLValidationResult(
                is_valid=False,
                violation_score=0.70,
                reason=f"Suspiciously high number of GraphQL aliases ({alias_count}), potential batching evasion."
            )           

        return True, GraphQLValidationResult(True)

    def _calculate_depth(self, query: str) -> int:
        """
        Calculate the maximum brace nesting level of a GraphQL query.
        """
        max_d = 0
        current_d = 0
        in_string = False
        
        for char in query:
            if char == '"':
                in_string = not in_string
            if not in_string:
                if char == '{':
                    current_d += 1
                    if current_d > max_d:
                        max_d = current_d
                elif char == '}':
                    current_d -= 1
                    
        return max_d

