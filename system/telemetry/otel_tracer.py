"""
CyberNexus NGFW — OpenTelemetry Tracer
========================================
Distributed tracing with zero overhead when disabled.

Controlled by features.yaml:
  features.observability.tracing: true
  features.observability.otlp_endpoint: "http://localhost:4317"

When tracing is disabled → all spans are no-ops (zero allocation).

Usage:
    tracer = OTelTracer.instance()

    with tracer.span("waf.inspect") as span:
        span.set("src_ip", context.src_ip)
        result = await waf.inspect(context)
        span.set("action", result.action)
"""

import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# No-op Span (used when tracing is disabled)
# ──────────────────────────────────────────────────────────────────────

class _NoOpSpan:
    def set(self, key: str, value) -> "_NoOpSpan":
        return self

    def set_status_ok(self): pass
    def set_status_error(self, msg: str = ""): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


# ──────────────────────────────────────────────────────────────────────
# OTel Tracer
# ──────────────────────────────────────────────────────────────────────

class OTelTracer:
    """
    Wraps OpenTelemetry SDK behind a feature flag guard.

    When tracing = false: all spans are no-ops.
    When tracing = true: exports to OTLP endpoint (Tempo/Jaeger).
    """

    _instance: Optional["OTelTracer"] = None

    def __init__(self, enabled: bool, otlp_endpoint: str):
        self._enabled = enabled
        self._tracer = None

        if enabled:
            self._init_otel(otlp_endpoint)

    @classmethod
    def instance(cls) -> "OTelTracer":
        if cls._instance is None:
            from system.config.feature_flags import FeatureFlagManager
            flags = FeatureFlagManager.instance().current.observability
            cls._instance = cls(
                enabled=flags.enabled and flags.tracing,
                otlp_endpoint=flags.otlp_endpoint,
            )
        return cls._instance

    @contextmanager
    def span(self, name: str, **attributes):
        """
        Context manager to create a trace span.

        with tracer.span("pipeline.inspect", src_ip="1.2.3.4") as span:
            span.set("action", "BLOCK")
        """
        if not self._enabled or self._tracer is None:
            yield _NoOpSpan()
            return

        try:
            with self._tracer.start_as_current_span(name) as otel_span:
                for k, v in attributes.items():
                    otel_span.set_attribute(k, str(v))
                wrapper = _OTelSpanWrapper(otel_span)
                try:
                    yield wrapper
                    wrapper.set_status_ok()
                except Exception as exc:
                    wrapper.set_status_error(str(exc))
                    raise
        except Exception as exc:
            logger.debug(f"[OTel] Span error: {exc}")
            yield _NoOpSpan()

    def _init_otel(self, endpoint: str) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource

            resource = Resource.create({"service.name": "cybernexus-ngfw"})
            provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer("cybernexus.ngfw")
            logger.info(f"[OTel] Tracing initialized → {endpoint}")

        except ImportError:
            logger.warning("[OTel] opentelemetry packages not installed — tracing disabled")
            self._enabled = False
        except Exception as exc:
            logger.error(f"[OTel] Init failed: {exc} — tracing disabled")
            self._enabled = False


class _OTelSpanWrapper:
    def __init__(self, span):
        self._span = span

    def set(self, key: str, value) -> "_OTelSpanWrapper":
        self._span.set_attribute(key, str(value))
        return self

    def set_status_ok(self):
        from opentelemetry.trace import StatusCode
        self._span.set_status(StatusCode.OK)

    def set_status_error(self, msg: str = ""):
        from opentelemetry.trace import StatusCode
        self._span.set_status(StatusCode.ERROR, msg)
