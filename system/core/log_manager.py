import logging
from collections import deque
from datetime import datetime
import asyncio

class UnifiedMemoryLogHandler(logging.Handler):
    """
    A custom logging handler that buffers the last N messages in memory.
    This allows the web UI terminal router to fetch historical logs.
    """
    def __init__(self, max_records=2000):
        super().__init__()
        self.max_records = max_records
        self.log_ring = deque(maxlen=max_records)
        self.formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self._new_log_event = asyncio.Event()

    def emit(self, record):
        try:
            msg = self.format(record)
            entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage(),
                "formatted": msg
            }
            self.log_ring.append(entry)
            
            # Trigger real-time waiters
            self._new_log_event.set()
            self._new_log_event.clear()
        except Exception:
            self.handleError(record)
            
    def get_recent_logs(self, limit=500):
        """Returns the most recent log entries."""
        logs = list(self.log_ring)
        return logs[-limit:]

# Global log handler instance easily accessible by the router
global_memory_handler = UnifiedMemoryLogHandler(max_records=2000)
global_memory_handler.setLevel(logging.INFO)

def setup_terminal_logging():
    """Attaches the memory log handler to the root logger."""
    root_logger = logging.getLogger()
    
    # Avoid duplicate attachments
    for handler in root_logger.handlers:
        if isinstance(handler, UnifiedMemoryLogHandler):
            return
            
    root_logger.addHandler(global_memory_handler)
