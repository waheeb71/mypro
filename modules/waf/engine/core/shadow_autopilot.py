"""
Enterprise NGFW — WAF Shadow Autopilot (Zero-Trust Schema Generator)

When enabled, it silently observes HTTP traffic to build a structural profile
of the backend application. It learns what headers, parameters, methods, and
payload lengths are "normal". After the learning period is over, it synthesizes
a JSON Schema (OpenAPI style) that can be enforced rigidly by the APISchemaValidator.
"""

import json
import logging
import time
from typing import Dict, Any, List
from threading import Lock

logger = logging.getLogger(__name__)

class ShadowAutopilot:
    """
    Profiles incoming API requests to auto-generate a Zero-Trust Schema.
    """
    def __init__(self, observation_window_hours: int = 72):
        self.learning_enabled = False
        self.learning_end_time = 0.0
        self.observation_window_seconds = observation_window_hours * 3600
        
        # lock for thread-safe mutation of the shared profiles dictionary
        self._lock = Lock()
        
        # Profile structure: path -> { method -> { headers: set, params: set, max_length: int, content_types: set } }
        # Example:
        # {
        #    "/api/login": {
        #        "POST": {
        #             "headers": {"content-type", "authorization"},
        #             "params": set(),
        #             "max_payload": 2048,
        #             "content_types": {"application/json"}
        #        }
        #    }
        # }
        self.profiles: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def start_learning(self, hours: int = 72) -> None:
        """Start or restart the learning phase."""
        with self._lock:
            self.learning_enabled = True
            self.learning_end_time = time.time() + (hours * 3600)
            self.observation_window_seconds = hours * 3600
            # Reset existing profiles for a clean slate
            self.profiles.clear()
        
        logger.info("WAF Shadow Autopilot started for %s hours.", hours)

    def is_learning(self) -> bool:
        """Check if autopilot is actively learning."""
        if not self.learning_enabled:
            return False
        if time.time() > self.learning_end_time:
            self.learning_enabled = False
            return False
        return True

    def get_progress(self) -> Dict[str, Any]:
        """Get learning progress metrics."""
        if not self.learning_enabled:
            return {
                "status": "idle_or_finished",
                "endpoints_learned": len(self.profiles)
            }
        
        remaining_sec = max(0, self.learning_end_time - time.time())
        pct = 100 - ((remaining_sec / self.observation_window_seconds) * 100)
        return {
            "status": "learning",
            "endpoints_learned": len(self.profiles),
            "hours_remaining": round(remaining_sec / 3600, 2),
            "progress_percent": round(pct, 1)
        }

    def observe(self, path: str, method: str, headers: Dict[str, str], payload_size: int) -> None:
        """
        Record a request structure if learning is enabled.
        This must be exceptionally fast (O(1) amortized) to not block inspection.
        """
        if not self.is_learning():
            return
            
        # Fast normalize path (strip trailing slashes, keep queries separate, wait, queries are usually parsed upstream)
        base_path = path.split('?')[0].rstrip('/') or '/'
        method = method.upper()
        
        # Fast header extraction (keys only, lowercased)
        header_keys = {k.lower() for k in headers.keys()}
        content_type = headers.get('content-type', '').lower().split(';')[0]
        
        # Minimal locking specifically around the dict update
        with self._lock:
            if base_path not in self.profiles:
                self.profiles[base_path] = {}
                
            if method not in self.profiles[base_path]:
                self.profiles[base_path][method] = {
                    "headers": set(),
                    "max_payload_bytes": 0,
                    "content_types": set(),
                }
                
            node = self.profiles[base_path][method]
            node["headers"].update(header_keys)
            if content_type:
                node["content_types"].add(content_type)
                
            # Keep track of the absolute maximum payload size seen + 20% tolerance ceiling
            # If payload is large, limit to an absolute sane maximum of 10MB just for safety
            ceiling = min(int(payload_size * 1.2), 10 * 1024 * 1024)
            if ceiling > node["max_payload_bytes"]:
                node["max_payload_bytes"] = ceiling

    def generate_schema(self) -> Dict[str, Any]:
        """
        Synthesize the collected profile into an OpenAPI-like JSON structure.
        Ready to be written to disk and enforced by APISchemaValidator.
        """
        schema = {
            "openapi": "3.0.0",
            "info": {
                "title": "WAF Auto-Generated Zero-Trust Schema",
                "description": "Synthesized by Shadow Autopilot.",
                "version": "1.0.0"
            },
            "paths": {}
        }
        
        with self._lock:
            for path, methods in self.profiles.items():
                schema["paths"][path] = {}
                for method, data in methods.items():
                    schema["paths"][path][method.lower()] = {
                        "x-waf-max-payload": data["max_payload_bytes"] or 512, # allow minimum 512 bytes
                        "x-waf-allowed-headers": list(data["headers"]),
                        "x-waf-allowed-content-types": list(data["content_types"])
                    }
                    
        return schema
