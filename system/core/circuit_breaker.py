"""
CyberNexus NGFW — Circuit Breaker
====================================
Prevents cascade failures when a module becomes unavailable.

States:
  CLOSED     → Normal operation. Calls go through.
  OPEN       → Module failed too many times. Calls rejected immediately.
  HALF-OPEN  → Testing recovery. One call allowed through.

Fail-mode per module (from features.yaml):
  data_plane.fail_mode = "open"   → On OPEN: allow traffic through (safe default)
  data_plane.fail_mode = "close"  → On OPEN: block all traffic (strict security)

Usage:
    breaker = CircuitBreaker("waf", fail_threshold=5, timeout_s=30)

    result = await breaker.call(
        waf_plugin.inspect_async,
        context,
        fallback=InspectionResult(action="ALLOW", score=0.0)
    )

    # Or check state manually:
    if breaker.is_open():
        # module is unavailable
"""

import asyncio
import logging
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Awaitable

from system.events.topics import Topics

logger = logging.getLogger(__name__)


class BreakerState(str, Enum):
    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF-OPEN"


@dataclass
class BreakerStats:
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = field(default_factory=time.time)
    current_state: BreakerState = BreakerState.CLOSED
    error_rate: float = 0.0


class CircuitBreaker:
    """
    Async-compatible circuit breaker with sliding window failure detection.

    Automatically transitions:
    CLOSED → OPEN when consecutive failures ≥ fail_threshold
    OPEN → HALF-OPEN after timeout_s seconds
    HALF-OPEN → CLOSED on success | HALF-OPEN → OPEN on failure
    """

    def __init__(
        self,
        name: str,
        fail_threshold: int = 5,
        timeout_s: float = 30.0,
        fail_mode: str = "open",    # "open" = allow | "close" = block on OPEN state
    ):
        self.name = name
        self._fail_threshold = fail_threshold
        self._timeout_s = timeout_s
        self._fail_mode = fail_mode
        self._stats = BreakerStats()
        self._lock = threading.RLock()

        logger.debug(f"[CircuitBreaker:{name}] Initialized (fail_mode={fail_mode})")

    # ── Public API ─────────────────────────────────────────────────

    async def call(
        self,
        fn: Callable[..., Awaitable[Any]],
        *args,
        fallback: Any = None,
        **kwargs,
    ) -> Any:
        """
        Execute `fn(*args, **kwargs)` with circuit breaker protection.

        If circuit is OPEN:
          - fail_mode="open"  → returns `fallback` immediately (allow)
          - fail_mode="close" → returns `fallback` with BLOCK action
        """
        state = self._get_state()

        if state == BreakerState.OPEN:
            logger.warning(f"[CircuitBreaker:{self.name}] OPEN — rejecting call")
            await self._emit_health_event()
            return fallback

        if state == BreakerState.HALF_OPEN:
            logger.info(f"[CircuitBreaker:{self.name}] HALF-OPEN — testing recovery")

        try:
            result = await fn(*args, **kwargs)
            self._on_success()
            return result

        except Exception as exc:
            self._on_failure(exc)
            logger.error(f"[CircuitBreaker:{self.name}] Failure #{self._stats.consecutive_failures}: {exc}")
            return fallback

    def is_open(self) -> bool:
        return self._get_state() == BreakerState.OPEN

    def is_closed(self) -> bool:
        return self._get_state() == BreakerState.CLOSED

    @property
    def stats(self) -> BreakerStats:
        with self._lock:
            return self._stats

    def reset(self) -> None:
        """Manually reset to CLOSED state (admin override)."""
        with self._lock:
            self._stats.consecutive_failures = 0
            self._stats.current_state = BreakerState.CLOSED
            self._stats.last_state_change = time.time()
        logger.info(f"[CircuitBreaker:{self.name}] Manually reset to CLOSED")

    # ── Internal ───────────────────────────────────────────────────

    def _get_state(self) -> BreakerState:
        with self._lock:
            if self._stats.current_state == BreakerState.OPEN:
                # Check if timeout expired → try HALF-OPEN
                elapsed = time.time() - self._stats.last_state_change
                if elapsed >= self._timeout_s:
                    self._stats.current_state = BreakerState.HALF_OPEN
                    self._stats.last_state_change = time.time()
                    logger.info(f"[CircuitBreaker:{self.name}] OPEN → HALF-OPEN (testing)")
            return self._stats.current_state

    def _on_success(self) -> None:
        with self._lock:
            self._stats.total_calls += 1
            self._stats.total_successes += 1
            self._stats.consecutive_failures = 0
            if self._stats.current_state == BreakerState.HALF_OPEN:
                self._stats.current_state = BreakerState.CLOSED
                logger.info(f"[CircuitBreaker:{self.name}] HALF-OPEN → CLOSED ✓")
            self._update_error_rate()

    def _on_failure(self, exc: Exception) -> None:
        with self._lock:
            self._stats.total_calls += 1
            self._stats.total_failures += 1
            self._stats.consecutive_failures += 1
            self._stats.last_failure_time = time.time()

            if self._stats.consecutive_failures >= self._fail_threshold:
                if self._stats.current_state != BreakerState.OPEN:
                    self._stats.current_state = BreakerState.OPEN
                    self._stats.last_state_change = time.time()
                    logger.error(
                        f"[CircuitBreaker:{self.name}] CLOSED → OPEN "
                        f"({self._stats.consecutive_failures} consecutive failures)"
                    )
            self._update_error_rate()

    def _update_error_rate(self) -> None:
        if self._stats.total_calls > 0:
            self._stats.error_rate = self._stats.total_failures / self._stats.total_calls

    async def _emit_health_event(self) -> None:
        """Emit module health event when state changes to OPEN."""
        try:
            from system.events.bus import EventBus
            from system.events.schemas import ModuleHealthEvent
            bus = await EventBus.instance()
            event = ModuleHealthEvent(
                module_name=self.name,
                status="failed" if self.is_open() else "healthy",
                circuit_state=self._stats.current_state.value,
                error_rate=self._stats.error_rate,
            )
            await bus.publish(Topics.MODULE_HEALTH, event.to_dict())
        except Exception:
            pass   # Bus might also be unavailable — never let this cascade


# ──────────────────────────────────────────────────────────────────────
# Circuit Breaker Registry — one breaker per module
# ──────────────────────────────────────────────────────────────────────

class BreakerRegistry:
    """
    Centralized registry: one CircuitBreaker per pipeline module.
    Provides the health summary for the /health/detailed endpoint.
    """

    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()

    def get_or_create(
        self,
        module_name: str,
        fail_threshold: int = 5,
        timeout_s: float = 30.0,
        fail_mode: str = "open",
    ) -> CircuitBreaker:
        with self._lock:
            if module_name not in self._breakers:
                self._breakers[module_name] = CircuitBreaker(
                    module_name, fail_threshold, timeout_s, fail_mode
                )
            return self._breakers[module_name]

    def health_summary(self) -> dict:
        """Returns the health dict for /api/v1/system/health/detailed."""
        with self._lock:
            overall = "healthy"
            modules = {}
            for name, breaker in self._breakers.items():
                s = breaker.stats
                modules[name] = {
                    "state": s.current_state.value,
                    "consecutive_failures": s.consecutive_failures,
                    "error_rate": round(s.error_rate, 3),
                    "total_calls": s.total_calls,
                }
                if s.current_state == BreakerState.OPEN:
                    overall = "degraded"

            return {"status": overall, "modules": modules}

    def reset_all(self) -> None:
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()


# Global registry instance
breaker_registry = BreakerRegistry()
