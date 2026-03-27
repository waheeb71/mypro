"""
CyberNexus NGFW — Event Bus
=============================
Async event bus with hot-swappable backends.

Backends:
  "memory"  → in-process async queue (dev/testing, no external server)
  "nats"    → NATS JetStream (production, low-latency)
  "kafka"   → Apache Kafka (enterprise, high-throughput)

The bus is controlled by features.yaml:
  features.event_bus.enabled: true
  features.event_bus.backend: "nats"

Usage:
    bus = await EventBus.instance()
    await bus.publish(Topics.THREAT_DETECTED, event.to_dict())
    await bus.subscribe(Topics.THREAT_DETECTED, my_handler)
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Awaitable, Optional

from system.config.feature_flags import FeatureFlagManager
from system.events.topics import Topics

logger = logging.getLogger(__name__)

Handler = Callable[[dict], Awaitable[None]]


# ──────────────────────────────────────────────────────────────────────
# Abstract Backend
# ──────────────────────────────────────────────────────────────────────

class EventBusBackend(ABC):
    """All backends must implement this interface."""

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def publish(self, topic: str, payload: dict) -> None: ...

    @abstractmethod
    async def subscribe(self, topic: str, handler: Handler) -> None: ...


# ──────────────────────────────────────────────────────────────────────
# Memory Backend (In-process — dev/testing)
# ──────────────────────────────────────────────────────────────────────

class MemoryBackend(EventBusBackend):
    """
    In-process async pub/sub using asyncio.Queue.
    No external server needed. Suitable for development and unit tests.
    """

    def __init__(self):
        self._subscriptions: dict[str, list[Handler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        logger.info("[EventBus:memory] Connected (in-process)")

    async def disconnect(self) -> None:
        logger.info("[EventBus:memory] Disconnected")

    async def publish(self, topic: str, payload: dict) -> None:
        handlers = self._subscriptions.get(topic, [])
        if not handlers:
            return
        tasks = [asyncio.create_task(h(payload)) for h in handlers]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def subscribe(self, topic: str, handler: Handler) -> None:
        async with self._lock:
            self._subscriptions[topic].append(handler)
        logger.debug(f"[EventBus:memory] Subscribed to {topic}")


# ──────────────────────────────────────────────────────────────────────
# NATS Backend (Production — low latency)
# ──────────────────────────────────────────────────────────────────────

class NATSBackend(EventBusBackend):
    """
    NATS JetStream backend.
    Requires: pip install nats-py
    Requires: NATS server running (features.event_bus.nats_url)
    """

    def __init__(self, nats_url: str, reconnect_wait: int = 2, max_reconnect: int = 60):
        self._url = nats_url
        self._reconnect_wait = reconnect_wait
        self._max_reconnect = max_reconnect
        self._nc = None
        self._subscriptions: list = []

    async def connect(self) -> None:
        try:
            import nats                                              # noqa: F401
            self._nc = await nats.connect(
                servers=self._url,
                reconnect_time_wait=self._reconnect_wait,
                max_reconnect_attempts=self._max_reconnect,
                error_cb=self._on_error,
                disconnected_cb=lambda: logger.warning("[EventBus:nats] Disconnected"),
                reconnected_cb=lambda: logger.info("[EventBus:nats] Reconnected ✓"),
            )
            logger.info(f"[EventBus:nats] Connected to {self._url}")
        except Exception as exc:
            logger.error(f"[EventBus:nats] Connection failed: {exc}")
            raise

    async def disconnect(self) -> None:
        if self._nc:
            await self._nc.drain()

    async def publish(self, topic: str, payload: dict) -> None:
        data = json.dumps(payload).encode()
        await self._nc.publish(topic, data)

    async def subscribe(self, topic: str, handler: Handler) -> None:
        async def _wrapper(msg):
            try:
                data = json.loads(msg.data.decode())
                await handler(data)
            except Exception as exc:
                logger.error(f"[EventBus:nats] Handler error on {topic}: {exc}")

        sub = await self._nc.subscribe(topic, cb=_wrapper)
        self._subscriptions.append(sub)
        logger.debug(f"[EventBus:nats] Subscribed to {topic}")

    @staticmethod
    async def _on_error(exc):
        logger.error(f"[EventBus:nats] Error: {exc}")


# ──────────────────────────────────────────────────────────────────────
# Null Backend (when event_bus.enabled = false)
# ──────────────────────────────────────────────────────────────────────

class NullBackend(EventBusBackend):
    """No-op backend. Used when event bus is disabled in feature flags."""

    async def connect(self) -> None:
        logger.debug("[EventBus:null] Event bus disabled — using null backend")

    async def disconnect(self) -> None:
        pass

    async def publish(self, topic: str, payload: dict) -> None:
        pass   # Silently discard

    async def subscribe(self, topic: str, handler: Handler) -> None:
        pass   # Silently ignore subscriptions


# ──────────────────────────────────────────────────────────────────────
# EventBus — Public API (Singleton)
# ──────────────────────────────────────────────────────────────────────

class EventBus:
    """
    Feature-flag-aware event bus singleton.

    When event_bus.enabled = false → uses NullBackend (silent no-ops).
    When event_bus.backend = "memory" → MemoryBackend (in-process).
    When event_bus.backend = "nats"  → NATSBackend (production).

    All modules use ONLY this class — never import a backend directly.
    """

    _instance: Optional["EventBus"] = None

    def __init__(self, backend: EventBusBackend):
        self._backend = backend
        self._connected = False

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    async def instance(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = await cls._create()
        return cls._instance

    @classmethod
    async def _create(cls) -> "EventBus":
        flags = FeatureFlagManager.instance().current.event_bus

        if not FeatureFlagManager.instance().current.event_bus.enabled:
            backend: EventBusBackend = NullBackend()
            logger.info("[EventBus] Disabled — using NullBackend")
        elif flags.backend == "nats":
            backend = NATSBackend(
                nats_url=flags.nats_url,
                reconnect_wait=flags.reconnect_wait_s,
                max_reconnect=flags.max_reconnect,
            )
        elif flags.backend == "memory":
            backend = MemoryBackend()
        else:
            logger.warning(f"[EventBus] Unknown backend '{flags.backend}' — using memory")
            backend = MemoryBackend()

        bus = cls(backend)
        await bus._connect()
        return bus

    # ── Public API ─────────────────────────────────────────────────

    async def publish(self, topic: str, payload: dict) -> None:
        """Publish an event to a topic. Non-blocking on NullBackend."""
        try:
            await asyncio.wait_for(
                self._backend.publish(topic, payload),
                timeout=1.0,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[EventBus] Publish timeout on topic: {topic}")
        except Exception as exc:
            logger.error(f"[EventBus] Publish error ({topic}): {exc}")

    async def subscribe(self, topic: str, handler: Handler) -> None:
        """Subscribe an async handler to a topic."""
        await self._backend.subscribe(topic, handler)

    async def disconnect(self) -> None:
        await self._backend.disconnect()
        self._connected = False

    # ── Internal ───────────────────────────────────────────────────

    async def _connect(self) -> None:
        await self._backend.connect()
        self._connected = True
