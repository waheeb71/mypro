"""
CyberNexus NGFW — Prometheus Metrics Exporter
===============================================
Exposes /metrics endpoint in Prometheus text format.

Controlled by features.yaml:
  features.observability.metrics: true
  features.observability.metrics_port: 9090

All metrics are lazily registered — no-op when observability.metrics = false.

Usage:
    exporter = MetricsExporter.instance()
    exporter.packets_inspected.inc()
    exporter.pipeline_latency.observe(0.002)  # 2ms
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Safe metric stubs — used when prometheus_client is not installed
# or observability.metrics = false
# ──────────────────────────────────────────────────────────────────────

class _NoOpMetric:
    def inc(self, amount=1): pass
    def dec(self, amount=1): pass
    def set(self, value): pass
    def observe(self, value): pass
    def labels(self, **kwargs): return self


# ──────────────────────────────────────────────────────────────────────
# Metrics Exporter
# ──────────────────────────────────────────────────────────────────────

class MetricsExporter:
    """
    Lazily imports prometheus_client so the system boots even without it.
    All metrics fall back to no-ops if disabled or not installed.
    """

    _instance: Optional["MetricsExporter"] = None

    def __init__(self, enabled: bool):
        self._enabled = enabled

        if enabled:
            self._init_prometheus()
        else:
            self._init_noop()

    @classmethod
    def instance(cls) -> "MetricsExporter":
        if cls._instance is None:
            from system.config.feature_flags import FeatureFlagManager
            flags = FeatureFlagManager.instance().current
            enabled = flags.observability.enabled and flags.observability.metrics
            cls._instance = cls(enabled)
        return cls._instance

    def _init_prometheus(self):
        try:
            from prometheus_client import Counter, Histogram, Gauge

            # ── Packet Processing ──────────────────────────────────
            self.packets_inspected = Counter(
                "ngfw_packets_inspected_total",
                "Total packets inspected by the DPI pipeline",
                ["action"],               # label: "ALLOW" | "BLOCK"
            )
            self.packets_per_second = Gauge(
                "ngfw_packets_per_second",
                "Current packet processing rate",
            )
            self.drop_rate = Gauge(
                "ngfw_drop_rate_percent",
                "Current packet drop rate as percentage",
            )

            # ── Pipeline Latency ───────────────────────────────────
            self.pipeline_latency = Histogram(
                "ngfw_pipeline_latency_seconds",
                "End-to-end DPI pipeline latency",
                buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
            )
            self.module_latency = Histogram(
                "ngfw_module_latency_seconds",
                "Per-module inspection latency",
                ["module_name"],
                buckets=[0.0001, 0.001, 0.01, 0.1],
            )

            # ── AI Engine ──────────────────────────────────────────
            self.ai_inference_latency = Histogram(
                "ngfw_ai_inference_ms",
                "AI model inference latency in milliseconds",
                buckets=[1, 2, 5, 10, 20, 50, 100],
            )
            self.ai_confidence = Histogram(
                "ngfw_ai_confidence_score",
                "Distribution of AI confidence scores",
                buckets=[0.1, 0.2, 0.3, 0.5, 0.7, 0.85, 0.9, 0.95, 1.0],
            )

            # ── Threat Detection ───────────────────────────────────
            self.threats_detected = Counter(
                "ngfw_threats_detected_total",
                "Total threats detected",
                ["module", "threat_type"],
            )

            # ── System Health ──────────────────────────────────────
            self.module_status = Gauge(
                "ngfw_module_status",
                "Module health status (1=healthy, 0=degraded)",
                ["module_name"],
            )
            self.active_connections = Gauge(
                "ngfw_active_connections",
                "Number of currently tracked connections",
            )
            self.event_bus_queue_depth = Gauge(
                "ngfw_event_bus_queue_depth",
                "Current event bus queue depth",
            )

            logger.info("[Metrics] Prometheus metrics initialized ✓")

        except ImportError:
            logger.warning("[Metrics] prometheus_client not installed — using no-ops")
            self._init_noop()
        except Exception as exc:
            logger.error(f"[Metrics] Init failed: {exc} — using no-ops")
            self._init_noop()

    def _init_noop(self):
        """All metrics are no-ops — zero overhead."""
        noop = _NoOpMetric()
        self.packets_inspected = noop
        self.packets_per_second = noop
        self.drop_rate = noop
        self.pipeline_latency = noop
        self.module_latency = noop
        self.ai_inference_latency = noop
        self.ai_confidence = noop
        self.threats_detected = noop
        self.module_status = noop
        self.active_connections = noop
        self.event_bus_queue_depth = noop

    def generate_latest(self) -> bytes:
        """Return Prometheus scrape output for /metrics endpoint."""
        if not self._enabled:
            return b"# Observability metrics disabled\n"
        try:
            from prometheus_client import generate_latest as _gen
            return _gen()
        except Exception:
            return b"# Error generating metrics\n"

    def content_type(self) -> str:
        try:
            from prometheus_client import CONTENT_TYPE_LATEST
            return CONTENT_TYPE_LATEST
        except Exception:
            return "text/plain"
