"""
CyberNexus NGFW — AI Engine Wrapper
=====================================
Makes the AI Engine fully optional via feature flags.

Modes (controlled by features.yaml):
  ai_engine.mode = "disabled"  → returns neutral score, zero overhead
  ai_engine.mode = "async"     → fires inference to event bus, non-blocking
  ai_engine.mode = "inline"    → awaits inference result before returning
                                  + inline_blocking = true → can block traffic

Design Rules (from Master Prompt):
  ✅ AI must NEVER block traffic unless mode=inline AND inline_blocking=true
  ✅ AI must fall back to neutral score on failure if fallback_on_failure=true
  ✅ AI must be independently restartable
  ✅ All AI actions emit events to the event bus

Usage:
    wrapper = AIEngineWrapper.instance()
    score = await wrapper.score(context)
    if wrapper.should_block(score):
        return InspectionResult(action="BLOCK", reason="AI inline block")
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional, Any

from system.config.feature_flags import FeatureFlagManager
from system.events.bus import EventBus
from system.events.topics import Topics
from system.events.schemas import AIScoreRequestedEvent, AIScoreGeneratedEvent

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# AI Score result
# ──────────────────────────────────────────────────────────────────────

@dataclass
class AIScore:
    score: float = 0.0
    confidence: float = 0.0
    mode: str = "disabled"           # "inline" | "async" | "disabled" | "fallback"
    skipped: bool = False
    reason: str = ""
    inference_ms: float = 0.0
    model_version: str = ""


# ──────────────────────────────────────────────────────────────────────
# AI Engine Wrapper
# ──────────────────────────────────────────────────────────────────────

class AIEngineWrapper:
    """
    Feature-flag-controlled AI engine interface.

    Supports three modes:
    - disabled: immediate neutral score (0.0), no model loaded
    - async:    non-blocking publish to bus, pipeline continues immediately
    - inline:   awaits model inference, optionally blocks traffic

    All modes are hot-switchable via features.yaml — no restart needed.
    """

    _instance: Optional["AIEngineWrapper"] = None

    def __init__(self):
        self._flags = FeatureFlagManager.instance()
        self._model: Optional[Any] = None
        self._model_version: str = "none"

        # Register for hot-reload to swap model if version changes
        self._flags.on_reload(self._on_flags_reload)

    @classmethod
    def instance(cls) -> "AIEngineWrapper":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Public API ─────────────────────────────────────────────────

    async def score(self, context: Any) -> AIScore:
        """
        Score a packet/session. Behaviour depends on ai_engine.mode flag.
        Never raises — always returns an AIScore (with skipped=True on error).
        """
        ai_flags = self._flags.current.ai_engine
        t0 = time.perf_counter()

        # Mode: disabled — immediate return, zero overhead
        if not ai_flags.enabled or ai_flags.mode == "disabled":
            return AIScore(score=0.0, confidence=0.0, mode="disabled", skipped=True,
                           reason="AI disabled via feature flag")

        # Mode: async — fire-and-forget to event bus
        if ai_flags.mode == "async":
            return await self._score_async(context, ai_flags)

        # Mode: inline — await result, may block traffic
        if ai_flags.mode == "inline":
            return await self._score_inline(context, ai_flags, t0)

        # Unknown mode — safe fallback
        logger.warning(f"[AI] Unknown mode '{ai_flags.mode}' — skipping")
        return AIScore(skipped=True, mode="fallback", reason="Unknown mode")

    def should_block(self, score: AIScore) -> bool:
        """
        Returns True ONLY when:
        - mode = inline
        - inline_blocking = true (must be explicitly configured)
        - score >= confidence_threshold
        - score was not skipped (AI actually ran)

        This implements the Master Prompt rule:
        "AI must NEVER block traffic unless configured inline blocking mode"
        """
        ai_flags = self._flags.current.ai_engine
        return (
            ai_flags.mode == "inline"
            and ai_flags.inline_blocking
            and not score.skipped
            and score.score >= ai_flags.confidence_threshold
        )

    # ── Internal ───────────────────────────────────────────────────

    async def _score_async(self, context: Any, ai_flags) -> AIScore:
        """Publish scoring request to event bus — returns immediately."""
        try:
            bus = await EventBus.instance()
            event = AIScoreRequestedEvent(
                session_id=getattr(context, "session_id", ""),
                features=self._extract_features(context),
                priority="normal",
            )
            await bus.publish(Topics.AI_SCORE_REQUESTED, event.to_dict())
        except Exception as exc:
            logger.error(f"[AI:async] Failed to publish score request: {exc}")

        # Always return neutral — result arrives later via bus
        return AIScore(
            score=0.0,
            confidence=0.0,
            mode="async",
            skipped=False,
            reason="Async inference dispatched",
            model_version=ai_flags.model_version,
        )

    async def _score_inline(self, context: Any, ai_flags, t0: float) -> AIScore:
        """Await model inference within timeout — falls back on failure."""
        try:
            timeout_s = ai_flags.inference_timeout_ms / 1000.0

            result = await asyncio.wait_for(
                self._run_inference(context, ai_flags),
                timeout=timeout_s,
            )

            inference_ms = (time.perf_counter() - t0) * 1000
            score = AIScore(
                score=result["score"],
                confidence=result["confidence"],
                mode="inline",
                skipped=False,
                inference_ms=inference_ms,
                model_version=ai_flags.model_version,
            )

            # Publish score result to event bus (non-blocking)
            await self._emit_score(score, context)
            return score

        except asyncio.TimeoutError:
            logger.warning(f"[AI:inline] Inference timeout after {ai_flags.inference_timeout_ms}ms")
            return self._fallback_score(ai_flags, reason="Inference timeout")

        except Exception as exc:
            logger.error(f"[AI:inline] Inference error: {exc}")
            return self._fallback_score(ai_flags, reason=f"Inference error: {exc}")

    async def _run_inference(self, context: Any, ai_flags) -> dict:
        """
        Run the actual model inference.
        Loads model lazily on first use.
        Replace this with real ONNX/PyTorch inference in future.
        """
        if self._model is None:
            await self._load_model(ai_flags.model_version)

        features = self._extract_features(context)
        # TODO: Replace with real model.predict(features)
        # Placeholder: deterministic mock based on feature count
        mock_score = min(0.1 * len(features), 0.99)
        return {"score": mock_score, "confidence": 0.7}

    async def _load_model(self, version: str) -> None:
        """Load model from registry. Lazy — only loads when inline mode used."""
        logger.info(f"[AI] Loading model version {version}...")
        await asyncio.sleep(0)   # yield — non-blocking
        self._model = object()   # Placeholder until real model registry is wired
        self._model_version = version
        logger.info(f"[AI] Model {version} loaded ✓")

    async def _emit_score(self, score: AIScore, context: Any) -> None:
        """Publish AI score to event bus (fire and forget)."""
        try:
            bus = await EventBus.instance()
            event = AIScoreGeneratedEvent(
                session_id=getattr(context, "session_id", ""),
                score=score.score,
                confidence=score.confidence,
                model_version=score.model_version,
                inference_ms=score.inference_ms,
            )
            await bus.publish(Topics.AI_SCORE_GENERATED, event.to_dict())
        except Exception:
            pass   # Never let event emission affect the main path

    def _fallback_score(self, ai_flags, reason: str) -> AIScore:
        """Return neutral/safe score when AI fails."""
        if ai_flags.fallback_on_failure:
            return AIScore(score=0.0, mode="fallback", skipped=True, reason=reason)
        # If fallback disabled, re-raise would have happened — this means allow
        return AIScore(score=0.0, mode="fallback", skipped=True, reason=reason)

    @staticmethod
    def _extract_features(context: Any) -> dict:
        """Extract numerical features from InspectionContext for ML model."""
        return {
            "src_ip_class": hash(getattr(context, "src_ip", "")) % 256,
            "dst_port": getattr(context, "dst_port", 0),
            "protocol": hash(getattr(context, "protocol", "tcp")) % 10,
            "risk_score": float(getattr(context, "risk_score", 0.0)),
            "is_authenticated": int(bool(getattr(context, "user_id", None))),
        }

    def _on_flags_reload(self, new_flags) -> None:
        """Called when features.yaml changes — reset model if version changed."""
        new_version = new_flags.ai_engine.model_version
        if new_version != self._model_version:
            logger.info(f"[AI] Model version changed {self._model_version} → {new_version}. Resetting.")
            self._model = None
