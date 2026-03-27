"""
CyberNexus NGFW — Health Detail API Route
==========================================
Exposes circuit breaker states and module health.

GET /api/v1/system/health/detailed
"""

import logging
from fastapi import APIRouter, Depends

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/system", tags=["System Health"])


@router.get("/health")
async def health_basic():
    """Quick liveness probe for load balancers."""
    return {"status": "ok", "service": "CyberNexus NGFW"}


@router.get("/health/detailed")
async def health_detailed():
    """
    Returns circuit breaker state for every registered module.

    Response shape:
    {
      "status": "healthy" | "degraded",
      "features": { ... current feature flags ... },
      "modules": {
        "waf": { "state": "CLOSED", "error_rate": 0.01, ... },
        "ml_ai": { "state": "OPEN",  "error_rate": 0.42, ... }
      }
    }
    """
    from system.core.circuit_breaker import breaker_registry
    from system.config.feature_flags import FeatureFlagManager

    flags = FeatureFlagManager.instance().current
    summary = breaker_registry.health_summary()

    return {
        **summary,
        "feature_flags": {
            "event_bus_enabled": flags.event_bus.enabled,
            "event_bus_backend": flags.event_bus.backend,
            "ai_enabled": flags.ai_engine.enabled,
            "ai_mode": flags.ai_engine.mode,
            "ai_inline_blocking": flags.ai_engine.inline_blocking,
            "observability_metrics": flags.observability.metrics,
            "observability_tracing": flags.observability.tracing,
            "threat_intel_enabled": flags.threat_intel.enabled,
            "mtls_internal": flags.security.mtls_internal,
            "ha_enabled": flags.ha.enabled,
        }
    }


@router.post("/health/reset/{module_name}")
async def reset_breaker(module_name: str):
    """Admin endpoint: manually reset a module's circuit breaker to CLOSED."""
    from system.core.circuit_breaker import breaker_registry
    breaker = breaker_registry._breakers.get(module_name)
    if not breaker:
        return {"error": f"No circuit breaker found for module '{module_name}'"}
    breaker.reset()
    return {"status": "reset", "module": module_name}


@router.get("/features")
async def get_features():
    """Return the current feature flag state (from features.yaml)."""
    from system.config.feature_flags import FeatureFlagManager
    flags = FeatureFlagManager.instance().current
    return {
        "data_plane": {
            "enabled": flags.data_plane.enabled,
            "ebpf_acceleration": flags.data_plane.ebpf_acceleration,
            "tls_inspection": flags.data_plane.tls_inspection,
            "fail_mode": flags.data_plane.fail_mode,
        },
        "event_bus": {
            "enabled": flags.event_bus.enabled,
            "backend": flags.event_bus.backend,
        },
        "ai_engine": {
            "enabled": flags.ai_engine.enabled,
            "mode": flags.ai_engine.mode,
            "inline_blocking": flags.ai_engine.inline_blocking,
            "model_version": flags.ai_engine.model_version,
        },
        "observability": {
            "metrics": flags.observability.metrics,
            "logs": flags.observability.logs,
            "tracing": flags.observability.tracing,
        },
        "threat_intel": {"enabled": flags.threat_intel.enabled},
        "ha": {"enabled": flags.ha.enabled, "mode": flags.ha.mode},
        "security": {"mtls_internal": flags.security.mtls_internal},
        "optimizer": {"enabled": flags.optimizer.enabled},
    }


@router.post("/features/reload")
async def reload_features():
    """Force hot-reload of features.yaml without restart."""
    from system.config.feature_flags import FeatureFlagManager
    mgr = FeatureFlagManager.instance()
    mgr.force_reload()
    return {"status": "reloaded", "message": "Feature flags reloaded from features.yaml"}
