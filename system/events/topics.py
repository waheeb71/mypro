"""
CyberNexus NGFW — Event Bus Topic Registry
===========================================
Single source of truth for all event topic names.
Import only this file to avoid topic name typos.
"""


class Topics:
    # ── Data Plane ──────────────────────────────────────────────────
    PACKET_RECEIVED       = "packet.received"
    PACKET_INSPECTED      = "packet.inspected"
    CONNECTION_ESTABLISHED = "connection.established"
    CONNECTION_CLOSED     = "connection.closed"
    FLOW_CREATED          = "flow.created"

    # ── Security Events ─────────────────────────────────────────────
    THREAT_DETECTED       = "threat.detected"
    POLICY_EVALUATED      = "policy.evaluated"
    ANOMALY_SCORED        = "anomaly.scored"

    # ── AI Engine ───────────────────────────────────────────────────
    AI_SCORE_REQUESTED    = "ai.score_requested"
    AI_SCORE_GENERATED    = "ai.score_generated"

    # ── Response / Enforcement ─────────────────────────────────────
    RESPONSE_BLOCK        = "response.block"
    RESPONSE_QUARANTINE   = "response.quarantine"
    RESPONSE_ALERT        = "response.alert"

    # ── System Health ───────────────────────────────────────────────
    MODULE_HEALTH         = "module.health"
    MODULE_STARTED        = "module.started"
    MODULE_STOPPED        = "module.stopped"

    # ── Intelligence ────────────────────────────────────────────────
    INTEL_UPDATED         = "intel.updated"
    CORRELATION_TRIGGERED = "correlation.triggered"

    # ── Config / Feature Flags ──────────────────────────────────────
    CONFIG_RELOADED       = "config.reloaded"
    FEATURE_CHANGED       = "feature.changed"
