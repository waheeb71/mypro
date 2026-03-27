"""
CyberNexus NGFW — HA Leader Election
======================================
Raft-inspired leader election using etcd for Active-Active/Active-Passive HA.

Architecture:
  - Each node tries to acquire a leader lease in etcd
  - Lease TTL = 5s, heartbeat = 1s
  - Leader failure → new election in < 3s
  - Non-leaders operate in standby (or active-active pass-through)

Controlled by features.yaml:
  features.ha.enabled: true
  features.ha.mode: "active-passive" | "active-active"
  features.ha.etcd_endpoints: ["localhost:2379"]

When disabled → this node always acts as standalone leader.

Usage:
    election = LeaderElection.instance()
    await election.start()

    @election.on_become_leader
    async def _on_leader():
        await threat_intel.start_refresh()

    @election.on_lose_leadership
    async def _on_follower():
        await threat_intel.stop_refresh()
"""

import asyncio
import logging
import time
import threading
import uuid
from typing import Callable, List, Optional

from system.config.feature_flags import FeatureFlagManager

logger = logging.getLogger(__name__)


class LeaderElection:
    """
    etcd-based distributed leader election.

    State machine:
      FOLLOWER  → Watching for leader lease expiry
      CANDIDATE → Attempting to acquire lease
      LEADER    → Holding lease, sending heartbeats
    """

    LEASE_TTL      = 5       # seconds
    HEARTBEAT_WAIT = 1       # seconds between heartbeats
    LEADER_KEY     = "/ngfw/leader"

    _instance: Optional["LeaderElection"] = None
    _lock = threading.RLock()

    def __init__(self, node_id: Optional[str] = None):
        self._node_id = node_id or str(uuid.uuid4())[:8]
        self._is_leader = False
        self._flags = FeatureFlagManager.instance()
        self._on_leader_callbacks: List[Callable] = []
        self._on_follower_callbacks: List[Callable] = []
        self._client = None
        self._lease = None
        self._running = False

    @classmethod
    def instance(cls) -> "LeaderElection":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    import os
                    node_id = os.getenv("NGFW_NODE_ID", str(uuid.uuid4())[:8])
                    cls._instance = cls(node_id)
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    def on_become_leader(self, fn: Callable) -> Callable:
        """Decorator: called when this node wins the election."""
        self._on_leader_callbacks.append(fn)
        return fn

    def on_lose_leadership(self, fn: Callable) -> Callable:
        """Decorator: called when this node loses leadership."""
        self._on_follower_callbacks.append(fn)
        return fn

    @property
    def is_leader(self) -> bool:
        """True if this node is currently the active leader."""
        if not self._flags.current.ha.enabled:
            return True   # Standalone mode: always leader
        return self._is_leader

    @property
    def node_id(self) -> str:
        return self._node_id

    async def start(self) -> None:
        """Start leader election loop."""
        ha = self._flags.current.ha

        if not ha.enabled:
            logger.info(f"[HA] Disabled — node {self._node_id} is standalone leader")
            self._is_leader = True
            await self._fire_callbacks(self._on_leader_callbacks)
            return

        try:
            self._client = await self._connect_etcd(list(ha.etcd_endpoints))
            self._running = True
            asyncio.create_task(self._election_loop())
            logger.info(f"[HA] Node {self._node_id} started election loop")
        except Exception as exc:
            logger.error(f"[HA] Failed to start election: {exc} — running as standalone")
            self._is_leader = True
            await self._fire_callbacks(self._on_leader_callbacks)

    async def stop(self) -> None:
        self._running = False
        if self._lease:
            try:
                await self._lease.revoke()
                self._is_leader = False
            except Exception:
                pass

    def get_status(self) -> dict:
        return {
            "node_id":    self._node_id,
            "is_leader":  self.is_leader,
            "ha_enabled": self._flags.current.ha.enabled,
            "ha_mode":    self._flags.current.ha.mode,
        }

    # ── Internal ───────────────────────────────────────────────────

    async def _election_loop(self) -> None:
        while self._running:
            try:
                if not self._is_leader:
                    await self._try_acquire()
                else:
                    await self._heartbeat()
            except Exception as exc:
                logger.error(f"[HA] Election loop error: {exc}")
                if self._is_leader:
                    self._is_leader = False
                    await self._fire_callbacks(self._on_follower_callbacks)
            await asyncio.sleep(self.HEARTBEAT_WAIT)

    async def _try_acquire(self) -> None:
        """Try to acquire the leader lease in etcd."""
        try:
            import etcd3
            lease = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.lease(self.LEASE_TTL)
            )
            success, _ = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.transaction(
                    compare=[self._client.transactions.version(self.LEADER_KEY) == 0],
                    success=[self._client.transactions.put(self.LEADER_KEY, self._node_id, lease=lease)],
                    failure=[],
                )
            )
            if success:
                self._lease = lease
                self._is_leader = True
                logger.info(f"[HA] Node {self._node_id} became LEADER ✓")
                await self._fire_callbacks(self._on_leader_callbacks)
            else:
                logger.debug(f"[HA] Node {self._node_id} is FOLLOWER")
        except ImportError:
            logger.warning("[HA] etcd3 not installed — running standalone. pip install etcd3")
            self._is_leader = True

    async def _heartbeat(self) -> None:
        """Refresh the lease to maintain leadership."""
        if self._lease:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._lease.refresh()
                )
            except Exception as exc:
                logger.warning(f"[HA] Heartbeat failed: {exc}")
                self._is_leader = False
                await self._fire_callbacks(self._on_follower_callbacks)

    async def _connect_etcd(self, endpoints: list):
        try:
            import etcd3
            host, port_str = endpoints[0].split(":")
            return etcd3.client(host=host, port=int(port_str))
        except ImportError:
            raise RuntimeError("etcd3 not installed — run: pip install etcd3")

    @staticmethod
    async def _fire_callbacks(callbacks: list) -> None:
        for cb in callbacks:
            try:
                result = cb()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.error(f"[HA] Callback error: {exc}")
