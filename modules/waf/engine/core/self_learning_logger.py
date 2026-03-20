"""
Enterprise NGFW — WAF Self-Learning Logger

Writes every WAF inspection decision to `waf_training_data` SQLite table.

Gated by `WAFSettings.self_learning.enabled` — when disabled in waf.yaml
(or toggled via the API) the logger silently does nothing.

Design goals:
  - Zero-overhead when disabled (single bool check, no DB call)
  - Non-blocking write (background thread queue)
  - Max-records enforcement (oldest rows purged automatically)
  - Zero external dependencies beyond SQLAlchemy (already used in project)
"""

import json
import logging
import queue
import threading
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# WAF model version tag — bump when NLP / Bot models are retrained
WAF_MODEL_VERSION = "1.0.0"

_SENTINEL = None  # signals the background thread to stop


class WAFSelfLearningLogger:
    """
    Thread-safe, async-friendly logger for WAF training data.

    Usage (called from WAFInspectorPlugin.inspect()):
        self_logger.record(
            src_ip="1.2.3.4",
            request_path="/api/v1/users",
            request_method="GET",
            payload="SELECT * FROM users",
            features={...},
            risk_score=0.87,
            decision="BLOCK",
            nlp_score=0.91,
            bot_score=0.12,
            anomaly_score=0.05,
            reputation=0.80,
            label=1,                    # auto-set for blocks
            label_source="auto_block",
        )
    """

    def __init__(self, settings, db_session_factory):
        """
        Args:
            settings:           WAFSettings.self_learning  (SelfLearningSettings)
            db_session_factory: callable → SQLAlchemy Session  (e.g. SessionLocal)
        """
        self._cfg = settings                 # live reference — reacts to toggles
        self._session_factory = db_session_factory
        self._queue: queue.Queue = queue.Queue(maxsize=2000)
        self._thread: Optional[threading.Thread] = None
        self._start_worker()

    # ── Public API ──────────────────────────────────────────────────────

    def record(
        self,
        *,
        src_ip: str,
        request_path: str,
        request_method: str,
        payload: str,
        features: dict,
        risk_score: float,
        decision: str,
        nlp_score: float      = 0.0,
        bot_score: float      = 0.0,
        anomaly_score: float  = 0.0,
        reputation: float     = 0.0,
        label: Optional[int]  = None,
        label_source: str     = "auto",
    ) -> None:
        """Enqueue a record for background write. Never blocks the WAF."""
        if not self._cfg.enabled:
            return  # Feature disabled for this company — silent no-op

        # Decide whether to log based on settings
        if decision == "ALLOW" and not self._cfg.log_allowed:
            return
        if decision in ("CHALLENGE", "SOFT_BLOCK") and not self._cfg.log_challenged:
            return
        if decision == "BLOCK" and not self._cfg.log_blocked:
            return

        row = {
            "timestamp":      datetime.utcnow(),
            "src_ip":         src_ip,
            "request_path":   request_path[:1024],   # cap length
            "request_method": request_method,
            "payload":        payload[:4096] if payload else "",
            "features":       features,
            "risk_score":     round(risk_score, 4),
            "decision":       decision,
            "nlp_score":      round(nlp_score, 4),
            "bot_score":      round(bot_score, 4),
            "anomaly_score":  round(anomaly_score, 4),
            "reputation":     round(reputation, 4),
            "label":          label,
            "label_source":   label_source,
            "model_version":  WAF_MODEL_VERSION,
        }

        try:
            self._queue.put_nowait(row)
        except queue.Full:
            logger.debug("WAFSelfLearningLogger queue full — dropping record")

    def shutdown(self, timeout: float = 5.0) -> None:
        """Gracefully drain and stop the background writer thread."""
        self._queue.put(_SENTINEL)
        if self._thread:
            self._thread.join(timeout=timeout)

    # ── Internal ────────────────────────────────────────────────────────

    def _start_worker(self) -> None:
        self._thread = threading.Thread(
            target=self._writer_loop,
            daemon=True, name="waf-sl-logger"
        )
        self._thread.start()
        logger.info("WAFSelfLearningLogger background writer started.")

    def _writer_loop(self) -> None:
        """Drain the queue and persist records in small batches."""
        from system.database.database import WAFTrainingData

        BATCH = 50          # commit every N rows
        batch = []

        while True:
            try:
                row = self._queue.get(timeout=2.0)
            except queue.Empty:
                row = None

            if row is _SENTINEL:
                # Flush remaining and exit
                if batch:
                    self._flush(batch)
                break

            if row is not None:
                batch.append(row)

            if len(batch) >= BATCH or (row is None and batch):
                self._flush(batch)
                batch = []

    def _flush(self, rows: list) -> None:
        """Write a batch to the DB and enforce max_records cap."""
        from system.database.database import WAFTrainingData

        try:
            session = self._session_factory()
            try:
                session.bulk_insert_mappings(WAFTrainingData, rows)
                session.commit()

                # Enforce max record cap — delete oldest rows if over limit
                max_r = getattr(self._cfg, "max_records", 100_000)
                total = session.query(WAFTrainingData).count()
                if total > max_r:
                    over = total - max_r
                    oldest_ids = (
                        session.query(WAFTrainingData.id)
                        .order_by(WAFTrainingData.id.asc())
                        .limit(over)
                        .subquery()
                    )
                    session.query(WAFTrainingData).filter(
                        WAFTrainingData.id.in_(oldest_ids)
                    ).delete(synchronize_session=False)
                    session.commit()
                    logger.debug("WAFSelfLearningLogger: pruned %d old rows", over)

            except Exception as e:
                session.rollback()
                logger.warning("WAFSelfLearningLogger flush error: %s", e)
            finally:
                session.close()
        except Exception as e:
            logger.error("WAFSelfLearningLogger session error: %s", e)
