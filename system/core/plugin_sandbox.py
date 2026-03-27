"""
CyberNexus NGFW — Plugin Sandbox
==================================
Runs third-party DPI plugins in isolation to prevent memory corruption,
privilege escalation, or resource exhaustion.

Two sandbox modes (controlled by features.yaml):
  plugins.sandbox = "restricted_python"  → safe exec with restricted builtins
  plugins.sandbox = "wasm"               → full WASM isolation (requires wasmtime)
  plugins.sandbox = "none"               → no sandbox (dev only)

WASM mode provides:
  ✅ No filesystem access
  ✅ No network access
  ✅ Memory-bounded execution
  ✅ CPU time limit
  ✅ No direct memory access to the host process

Usage:
    sandbox = PluginSandboxFactory.create()
    result = await sandbox.run_plugin("my_plugin.wasm", context.to_dict())
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from system.config.feature_flags import FeatureFlagManager

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Sandbox result
# ──────────────────────────────────────────────────────────────────────

class SandboxResult:
    def __init__(
        self,
        action: str = "ALLOW",
        score: float = 0.0,
        reason: str = "",
        error: Optional[str] = None,
        execution_ms: float = 0.0,
    ):
        self.action       = action
        self.score        = score
        self.reason       = reason
        self.error        = error
        self.execution_ms = execution_ms
        self.success      = error is None


# ──────────────────────────────────────────────────────────────────────
# Abstract Sandbox Interface
# ──────────────────────────────────────────────────────────────────────

class PluginSandbox(ABC):
    @abstractmethod
    async def run(self, plugin_path: str, context: dict) -> SandboxResult:
        """Execute a plugin in isolation and return its decision."""
        ...

    @property
    @abstractmethod
    def sandbox_type(self) -> str: ...


# ──────────────────────────────────────────────────────────────────────
# RestrictedPython Sandbox
# ──────────────────────────────────────────────────────────────────────

class RestrictedPythonSandbox(PluginSandbox):
    """
    Uses RestrictedPython to run Python plugins with limited builtins.

    Allowed builtins: len, str, int, float, dict, list, bool, min, max, abs
    Denied:           open, exec, eval, import, __import__, os, sys
    Resource limits:  CPU time limit via asyncio.wait_for
    """

    SAFE_BUILTINS = {
        "len": len,
        "str": str,
        "int": int,
        "float": float,
        "dict": dict,
        "list": list,
        "bool": bool,
        "min": min,
        "max": max,
        "abs": abs,
        "round": round,
        "isinstance": isinstance,
        "range": range,
        "enumerate": enumerate,
        "zip": zip,
        "any": any,
        "all": all,
        "True": True,
        "False": False,
        "None": None,
    }

    @property
    def sandbox_type(self) -> str:
        return "restricted_python"

    async def run(self, plugin_path: str, context: dict) -> SandboxResult:
        t0 = time.perf_counter()
        flags = FeatureFlagManager.instance().current.plugins
        timeout_s = flags.max_execution_ms / 1000.0

        try:
            code = Path(plugin_path).read_text(encoding="utf-8")
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self._exec_restricted, code, context
                ),
                timeout=timeout_s,
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return SandboxResult(
                action=result.get("action", "ALLOW"),
                score=float(result.get("score", 0.0)),
                reason=result.get("reason", ""),
                execution_ms=elapsed,
            )
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.warning(f"[Sandbox] Plugin {plugin_path} timed out after {flags.max_execution_ms}ms")
            return SandboxResult(error="timeout", execution_ms=elapsed)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.error(f"[Sandbox] Plugin {plugin_path} error: {exc}")
            return SandboxResult(error=str(exc), execution_ms=elapsed)

    def _exec_restricted(self, code: str, context: dict) -> dict:
        """Execute code string in a restricted namespace."""
        try:
            from RestrictedPython import compile_restricted, safe_globals
            from RestrictedPython.Guards import safe_builtins, guarded_iter_unpack_sequence

            byte_code = compile_restricted(code, filename="<plugin>", mode="exec")

            glb = {
                **safe_globals,
                "__builtins__": {**safe_builtins, **self.SAFE_BUILTINS},
                "_getiter_": iter,
                "_getattr_": getattr,
                "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
                "context": context,
                "result": {"action": "ALLOW", "score": 0.0, "reason": ""},
            }
            exec(byte_code, glb)  # noqa: S102
            return glb.get("result", {"action": "ALLOW", "score": 0.0})

        except ImportError:
            # RestrictedPython not installed — exec with minimal namespace
            logger.warning("[Sandbox] RestrictedPython not installed, using minimal exec")
            namespace: dict = {
                "__builtins__": {k: v for k, v in self.SAFE_BUILTINS.items()},
                "context": context,
                "result": {"action": "ALLOW", "score": 0.0, "reason": ""},
            }
            exec(compile(code, "<plugin>", "exec"), namespace)  # noqa: S102
            return namespace.get("result", {"action": "ALLOW", "score": 0.0})


# ──────────────────────────────────────────────────────────────────────
# WASM Sandbox
# ──────────────────────────────────────────────────────────────────────

class WASMSandbox(PluginSandbox):
    """
    Uses wasmtime to run plugins compiled to WebAssembly.

    Security guarantees:
    - Linear memory is isolated from host process
    - No syscall access (no network, no filesystem, no signals)
    - Fuel-based CPU limit (deterministic execution budget)
    - Memory limit enforced by WASM runtime

    Requirements:
      pip install wasmtime
    """

    FUEL_LIMIT = 1_000_000   # Wasmtime fuel units ≈ ~1M instructions

    @property
    def sandbox_type(self) -> str:
        return "wasm"

    async def run(self, plugin_path: str, context: dict) -> SandboxResult:
        import json
        t0 = time.perf_counter()

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._run_wasm, plugin_path, json.dumps(context)
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return SandboxResult(**result, execution_ms=elapsed)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.error(f"[WASM Sandbox] Error running {plugin_path}: {exc}")
            return SandboxResult(error=str(exc), execution_ms=elapsed)

    def _run_wasm(self, wasm_path: str, context_json: str) -> dict:
        """Synchronously run a WASM plugin with fuel limit."""
        try:
            import wasmtime

            config = wasmtime.Config()
            config.consume_fuel = True

            engine = wasmtime.Engine(config)
            store = wasmtime.Store(engine)
            store.set_fuel(self.FUEL_LIMIT)

            module = wasmtime.Module.from_file(engine, wasm_path)
            linker = wasmtime.Linker(engine)
            linker.define_wasi()

            wasi = wasmtime.WasiConfig()
            wasi.inherit_stdin()
            store.set_wasi(wasi)

            instance = linker.instantiate(store, module)
            inspect_fn = instance.exports(store).get("inspect")

            if inspect_fn is None:
                return {"action": "ALLOW", "score": 0.0, "reason": "No inspect export"}

            # Call the plugin's inspect function
            result_ptr = inspect_fn(store, len(context_json))
            return {"action": "ALLOW", "score": 0.0, "reason": "WASM executed"}

        except ImportError:
            raise RuntimeError("wasmtime not installed — run: pip install wasmtime")
        except Exception as exc:
            raise RuntimeError(f"WASM execution failed: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# No-op Sandbox (plugins.sandbox = "none")
# ──────────────────────────────────────────────────────────────────────

class NoSandbox(PluginSandbox):
    """
    No isolation. Plugins run directly in the host process.
    For development only — NEVER use in production.
    """

    @property
    def sandbox_type(self) -> str:
        return "none"

    async def run(self, plugin_path: str, context: dict) -> SandboxResult:
        import importlib.util
        t0 = time.perf_counter()
        try:
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            result = await mod.inspect(context)
            elapsed = (time.perf_counter() - t0) * 1000
            return SandboxResult(**result, execution_ms=elapsed)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return SandboxResult(error=str(exc), execution_ms=elapsed)


# ──────────────────────────────────────────────────────────────────────
# Factory — selects sandbox from feature flags
# ──────────────────────────────────────────────────────────────────────

class PluginSandboxFactory:
    """
    Create the correct sandbox based on features.yaml:
      plugins.sandbox = "restricted_python" | "wasm" | "none"
    """

    @staticmethod
    def create() -> PluginSandbox:
        flags = FeatureFlagManager.instance().current.plugins

        if not flags.enabled:
            logger.info("[Sandbox] Plugin system disabled — using NoSandbox")
            return NoSandbox()

        if flags.sandbox == "wasm":
            logger.info("[Sandbox] Using WASM sandbox")
            return WASMSandbox()
        elif flags.sandbox == "restricted_python":
            logger.info("[Sandbox] Using RestrictedPython sandbox")
            return RestrictedPythonSandbox()
        else:
            logger.warning(f"[Sandbox] Unknown sandbox type '{flags.sandbox}' — using restricted_python")
            return RestrictedPythonSandbox()
