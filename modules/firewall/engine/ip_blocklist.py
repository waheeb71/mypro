"""
Enterprise NGFW — IP Blocklist Manager
==========================================
Manages the runtime IP blocklist that is enforced at two layers:
  1. eBPF/XDP kernel level — ultra-fast zero-copy drops via xdp_engine.
  2. Software fallback  — in-memory set used when BCC/eBPF is unavailable.

The blocklist is persisted to a JSON file so entries survive restarts.

API Endpoints (registered in modules/firewall/api/router.py):
  GET    /api/v1/block/ips            — list all blocked IPs
  POST   /api/v1/block/{ip}           — block an IP
  DELETE /api/v1/block/{ip}           — unblock an IP
  DELETE /api/v1/block/all            — clear all blocked IPs (admin only)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from acceleration.ebpf.xdp_engine import XDPEngine

logger = logging.getLogger(__name__)

# Persistent storage location for blocked IPs
_DEFAULT_STORE = Path(__file__).parent.parent.parent.parent / "system" / "data" / "blocked_ips.json"


class BlockedEntry:
    """Represents a single blocked IP entry with metadata."""

    def __init__(self, ip: str, reason: str = "Manual block", blocked_by: str = "admin",
                 expires_at: Optional[float] = None):
        self.ip = ip
        self.reason = reason
        self.blocked_by = blocked_by
        self.blocked_at = time.time()
        self.expires_at = expires_at   # None = permanent

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BlockedEntry":
        entry = cls(
            ip=data["ip"],
            reason=data.get("reason", "Restored from disk"),
            blocked_by=data.get("blocked_by", "system"),
            expires_at=data.get("expires_at"),
        )
        entry.blocked_at = data.get("blocked_at", time.time())
        return entry


class IPBlocklistManager:
    """
    Central IP Blocklist Manager.

    Thread-safe. Backed by eBPF when available, falls back to a pure
    Python in-memory set that integrates with the inspection pipeline.
    """

    def __init__(self, xdp_engine: Optional["XDPEngine"] = None,
                 store_path: Path = _DEFAULT_STORE):
        self._xdp: Optional["XDPEngine"] = xdp_engine
        self._entries: Dict[str, BlockedEntry] = {}
        self._store_path = store_path
        self._lock = asyncio.Lock()
        self._load_from_disk()
        logger.info(f"IPBlocklistManager initialized — {len(self._entries)} entries loaded")

    # ── Public API ─────────────────────────────────────────────────────────────

    async def block_ip(self, ip: str, reason: str = "Manual block",
                       blocked_by: str = "admin",
                       duration_seconds: Optional[int] = None) -> dict:
        """
        Block an IP address.

        Args:
            ip: IPv4 or IPv6 address string.
            reason: Human-readable reason for the block.
            blocked_by: Username or system component that initiated the block.
            duration_seconds: Block duration. None = permanent.

        Returns:
            dict with status and entry info.
        """
        # Validate IP
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip!r}")

        expires_at = None if duration_seconds is None else time.time() + duration_seconds

        async with self._lock:
            entry = BlockedEntry(ip, reason, blocked_by, expires_at)
            self._entries[ip] = entry

            # Kernel-level enforcement
            if self._xdp and self._xdp.enabled:
                await self._xdp.add_blocked_ip(ip)
                logger.info(f"🚫 [eBPF] Blocked {ip}: {reason}")
            else:
                logger.info(f"🚫 [Soft] Blocked {ip}: {reason}")

            self._save_to_disk()
            return {"status": "blocked", **entry.to_dict()}

    async def unblock_ip(self, ip: str) -> dict:
        """
        Remove an IP from the blocklist.

        Args:
            ip: IP address to unblock.

        Returns:
            dict with status.

        Raises:
            KeyError: if the IP is not currently blocked.
        """
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip!r}")

        async with self._lock:
            if ip not in self._entries:
                raise KeyError(f"{ip} is not in the blocklist")

            entry = self._entries.pop(ip)

            # Remove from kernel map
            if self._xdp and self._xdp.enabled:
                await self._xdp.remove_blocked_ip(ip)
                logger.info(f"✅ [eBPF] Unblocked {ip}")
            else:
                logger.info(f"✅ [Soft] Unblocked {ip}")

            self._save_to_disk()
            return {"status": "unblocked", "ip": ip,
                    "was_blocked_by": entry.blocked_by,
                    "was_blocked_at": entry.blocked_at}

    async def unblock_all(self) -> dict:
        """Clear the entire blocklist."""
        async with self._lock:
            ips = list(self._entries.keys())
            for ip in ips:
                self._entries.pop(ip)
                if self._xdp and self._xdp.enabled:
                    await self._xdp.remove_blocked_ip(ip)

            self._save_to_disk()
            logger.warning(f"⚠️  Cleared entire blocklist ({len(ips)} entries removed)")
            return {"status": "cleared", "count": len(ips)}

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked (used by software inspection pipeline)."""
        entry = self._entries.get(ip)
        if entry is None:
            return False
        if entry.is_expired():
            # Lazy cleanup
            asyncio.create_task(self.unblock_ip(ip))
            return False
        return True

    def get_all(self) -> list:
        """Return a list of all currently blocked IPs with their metadata."""
        self._purge_expired()
        return [e.to_dict() for e in self._entries.values()]

    def get_stats(self) -> dict:
        return {
            "total_blocked": len(self._entries),
            "ebpf_active": bool(self._xdp and self._xdp.enabled),
            "store_path": str(self._store_path),
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _purge_expired(self):
        expired = [ip for ip, e in self._entries.items() if e.is_expired()]
        for ip in expired:
            self._entries.pop(ip)
            logger.info(f"🕒 Auto-expired block for {ip}")
        if expired:
            self._save_to_disk()

    def _save_to_disk(self):
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._store_path, "w", encoding="utf-8") as f:
                json.dump([e.to_dict() for e in self._entries.values()], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save blocklist to disk: {e}")

    def _load_from_disk(self):
        if not self._store_path.exists():
            return
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                entry = BlockedEntry.from_dict(item)
                if not entry.is_expired():
                    self._entries[entry.ip] = entry
            logger.info(f"Loaded {len(self._entries)} blocked IPs from disk")
        except Exception as e:
            logger.error(f"Failed to load blocklist from disk: {e}")


# ── Module-level singleton ────────────────────────────────────────────────────

_instance: Optional[IPBlocklistManager] = None


def get_blocklist_manager() -> IPBlocklistManager:
    """Return or create the singleton IPBlocklistManager."""
    global _instance
    if _instance is None:
        _instance = IPBlocklistManager()
    return _instance


def init_blocklist_manager(xdp_engine=None) -> IPBlocklistManager:
    """Initialize the singleton with an eBPF engine (called at app startup)."""
    global _instance
    _instance = IPBlocklistManager(xdp_engine=xdp_engine)
    return _instance
