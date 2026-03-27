"""
CyberNexus NGFW — CPU Core Affinity Manager
============================================
Pins worker threads to specific CPU cores to minimize context-switching
latency and improve deterministic packet processing performance.

Core Assignment Strategy:
  Core 0-1:   OS + Management plane (reserved — never touch)
  Core 2-5:   Data Plane workers (packet inspection pipeline)
  Core 6-7:   AI Inference workers (separate from data plane)
  Core 8+:    Background tasks (Observability, Threat Intel, Config)

Controlled by features.yaml:
  features.data_plane.per_core_processing: true

When disabled → no affinity setting, OS scheduler decides.

Usage:
    mgr = CoreAffinityManager.instance()
    mgr.pin_current_thread_to(CoreRole.DATA_PLANE)
    mgr.configure_all()
"""

import logging
import os
import threading
from enum import Enum
from typing import Optional

from system.config.feature_flags import FeatureFlagManager

logger = logging.getLogger(__name__)


class CoreRole(str, Enum):
    OS_MANAGEMENT  = "os_management"    # Cores 0-1 (never pin to these)
    DATA_PLANE     = "data_plane"       # Cores 2-5
    AI_INFERENCE   = "ai_inference"     # Cores 6-7
    BACKGROUND     = "background"       # Cores 8+


class CoreAffinityManager:
    """
    Manages CPU core affinity assignments for low-latency packet processing.

    Design principles:
      - Data plane workers get dedicated cores → no context switches
      - AI inference runs on separate cores → never starves data plane
      - Background tasks (metrics, logging) on remaining cores
      - Gracefully degrades on systems with < 4 cores

    Requires: pip install psutil
    """

    _instance: Optional["CoreAffinityManager"] = None
    _lock = threading.RLock()

    def __init__(self):
        self._enabled = False
        self._cpu_count = os.cpu_count() or 1
        self._assignments: dict[CoreRole, list[int]] = {}

        try:
            flags = FeatureFlagManager.instance().current
            self._enabled = flags.data_plane.per_core_processing
        except Exception:
            pass

        self._build_assignments()

    @classmethod
    def instance(cls) -> "CoreAffinityManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    def pin_current_thread_to(self, role: CoreRole) -> bool:
        """
        Pin the calling thread's process to the cores assigned to `role`.
        Returns True on success, False if disabled or unavailable.
        """
        if not self._enabled:
            return False

        cores = self._assignments.get(role, [])
        if not cores:
            logger.warning(f"[CoreAffinity] No cores assigned for role: {role}")
            return False

        return self._do_pin(os.getpid(), cores)

    def pin_pid(self, pid: int, role: CoreRole) -> bool:
        """Pin a specific PID to cores for a given role."""
        if not self._enabled:
            return False
        cores = self._assignments.get(role, [])
        return self._do_pin(pid, cores)

    def configure_all(self) -> dict:
        """
        Apply the full affinity strategy to the current process.
        Call this once during system startup.
        """
        if not self._enabled:
            logger.info("[CoreAffinity] Disabled — using OS scheduler")
            return {"status": "disabled"}

        report = {}
        for role, cores in self._assignments.items():
            if role == CoreRole.OS_MANAGEMENT:
                continue
            success = self._do_pin(os.getpid(), cores)
            report[role.value] = {"cores": cores, "pinned": success}
            if success:
                logger.info(f"[CoreAffinity] {role.value} → cores {cores}")

        return {"status": "configured", "assignments": report}

    def get_assignments(self) -> dict:
        """Return current core assignment plan."""
        return {
            role.value: {
                "cores": cores,
                "count": len(cores),
            }
            for role, cores in self._assignments.items()
        }

    def is_enabled(self) -> bool:
        return self._enabled

    # ── Internal ───────────────────────────────────────────────────

    def _build_assignments(self) -> None:
        """Compute core assignments based on available CPU count."""
        n = self._cpu_count

        if n <= 2:
            # Tiny system — no isolation possible
            all_cores = list(range(n))
            self._assignments = {
                CoreRole.OS_MANAGEMENT: [],
                CoreRole.DATA_PLANE:    all_cores,
                CoreRole.AI_INFERENCE:  all_cores,
                CoreRole.BACKGROUND:    all_cores,
            }
            return

        if n <= 4:
            # Small: cores 0-1 for everything except data plane
            self._assignments = {
                CoreRole.OS_MANAGEMENT: [0, 1],
                CoreRole.DATA_PLANE:    [2] if n > 2 else [0],
                CoreRole.AI_INFERENCE:  [3] if n > 3 else [1],
                CoreRole.BACKGROUND:    [0, 1],
            }
            return

        if n <= 8:
            # Medium: 4-8 cores
            self._assignments = {
                CoreRole.OS_MANAGEMENT: [0, 1],
                CoreRole.DATA_PLANE:    list(range(2, min(6, n))),   # cores 2-5
                CoreRole.AI_INFERENCE:  list(range(6, min(8, n))),   # cores 6-7
                CoreRole.BACKGROUND:    [0, 1],
            }
            return

        # Large: 8+ cores
        data_plane_end = min(6, n - 2)
        ai_end = min(8, n - 1)
        self._assignments = {
            CoreRole.OS_MANAGEMENT: [0, 1],
            CoreRole.DATA_PLANE:    list(range(2, data_plane_end)),  # 2-5
            CoreRole.AI_INFERENCE:  list(range(6, ai_end)),           # 6-7
            CoreRole.BACKGROUND:    list(range(8, n)),               # 8+
        }

    @staticmethod
    def _do_pin(pid: int, cores: list[int]) -> bool:
        """Apply CPU affinity using psutil."""
        if not cores:
            return False
        try:
            import psutil
            process = psutil.Process(pid)
            process.cpu_affinity(cores)
            return True
        except ImportError:
            logger.debug("[CoreAffinity] psutil not installed — skipping affinity")
            return False
        except AttributeError:
            # cpu_affinity() not available on this OS (e.g. macOS)
            logger.debug("[CoreAffinity] cpu_affinity() not supported on this OS")
            return False
        except Exception as exc:
            logger.warning(f"[CoreAffinity] Failed to set affinity for PID {pid}: {exc}")
            return False
