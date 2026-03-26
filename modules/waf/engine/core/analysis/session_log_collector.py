"""
Enterprise CyberNexus — WAF Session Log Collector

Collects HTTP session data in real-time as traffic flows through the WAF.
Persists data to a CSV file for later use in GNN model training.

Thread-safe ring buffer with auto-flush capability.
"""

import csv
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Data model
# ──────────────────────────────────────────────

@dataclass
class SessionLogEntry:
    """Represents a single HTTP request log entry."""
    session_id:    str
    src_ip:        str
    timestamp:     float
    path:          str
    method:        str
    response_code: int
    latency_ms:    float = 0.0
    payload_bytes: int   = 0


CSV_COLUMNS = [
    "session_id", "src_ip", "timestamp",
    "path", "method", "response_code",
    "latency_ms", "payload_bytes",
]


# ──────────────────────────────────────────────
#  SessionLogCollector
# ──────────────────────────────────────────────

class SessionLogCollector:
    """
    Thread-safe session log collector.

    Records HTTP request data in memory and periodically flushes
    to a CSV file for GNN training.

    Usage:
        collector = SessionLogCollector(output_path="datasets/session_logs.csv")
        collector.record(src_ip="1.2.3.4", path="/api/login", method="POST",
                         response_code=200, session_id="abc123")
    """

    def __init__(
        self,
        output_path:    str,
        max_records:    int = 500_000,
        flush_every:    int = 1_000,    # flush every N records
        auto_flush_sec: int = 60,       # also flush every N seconds
    ):
        self.output_path    = output_path
        self.max_records    = max_records
        self.flush_every    = flush_every
        self.auto_flush_sec = auto_flush_sec

        self._buffer: Deque[SessionLogEntry] = deque(maxlen=max_records)
        self._lock      = threading.Lock()
        self._record_count = 0          # total since last flush
        self._total_flushed = 0

        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # Initialize CSV with header if file does not exist
        if not os.path.exists(output_path):
            self._write_header()

        # Start background auto-flush timer
        self._timer: Optional[threading.Timer] = None
        self._start_auto_flush()
        logger.info("SessionLogCollector initialized → %s", output_path)

    # ── Public API ──────────────────────────────

    def record(
        self,
        src_ip:        str,
        path:          str,
        method:        str,
        response_code: int,
        session_id:    str = "",
        latency_ms:    float = 0.0,
        payload_bytes: int = 0,
    ) -> None:
        """Record one HTTP request. Thread-safe."""
        entry = SessionLogEntry(
            session_id    = session_id or src_ip,
            src_ip        = src_ip,
            timestamp     = time.time(),
            path          = path,
            method        = method.upper(),
            response_code = response_code,
            latency_ms    = round(latency_ms, 2),
            payload_bytes = payload_bytes,
        )
        with self._lock:
            self._buffer.append(entry)
            self._record_count += 1
            should_flush = self._record_count >= self.flush_every

        if should_flush:
            self._flush()

    def flush(self) -> int:
        """Manually flush buffer to CSV. Returns number of records flushed."""
        return self._flush()

    def get_record_count(self) -> int:
        """Return number of records currently in buffer."""
        with self._lock:
            return len(self._buffer)

    def get_total_flushed(self) -> int:
        """Return total records ever flushed to CSV."""
        return self._total_flushed

    def get_output_path(self) -> str:
        return self.output_path

    def shutdown(self) -> None:
        """Flush remaining data and stop timer."""
        if self._timer:
            self._timer.cancel()
        self._flush()
        logger.info("SessionLogCollector shutdown. Total flushed: %d", self._total_flushed)

    # ── Internals ──────────────────────────────

    def _flush(self) -> int:
        with self._lock:
            if not self._buffer:
                return 0
            to_write = list(self._buffer)
            self._buffer.clear()
            self._record_count = 0

        count = len(to_write)
        try:
            file_exists = os.path.exists(self.output_path)
            with open(self.output_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                if not file_exists:
                    writer.writeheader()
                for entry in to_write:
                    writer.writerow({
                        "session_id":    entry.session_id,
                        "src_ip":        entry.src_ip,
                        "timestamp":     entry.timestamp,
                        "path":          entry.path,
                        "method":        entry.method,
                        "response_code": entry.response_code,
                        "latency_ms":    entry.latency_ms,
                        "payload_bytes": entry.payload_bytes,
                    })
            self._total_flushed += count
            logger.debug("Flushed %d session log entries → %s", count, self.output_path)
        except Exception as e:
            logger.error("SessionLogCollector flush error: %s", e)
            return 0

        return count

    def _write_header(self) -> None:
        """Create the CSV file with header."""
        try:
            with open(self.output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()
        except Exception as e:
            logger.warning("Could not write CSV header: %s", e)

    def _start_auto_flush(self) -> None:
        """Start a repeating timer to auto-flush every N seconds."""
        self._timer = threading.Timer(self.auto_flush_sec, self._auto_flush_tick)
        self._timer.daemon = True
        self._timer.start()

    def _auto_flush_tick(self) -> None:
        self._flush()
        self._start_auto_flush()   # reschedule
