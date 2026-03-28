import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import deque
import asyncio
import aiosqlite

logger = logging.getLogger(__name__)

class UnifiedMemoryLogHandler(logging.Handler):
    """Buffers recent log messages in memory for real-time UI terminal."""
    def __init__(self, max_records=2000):
        super().__init__()
        self.max_records = max_records
        self.log_ring = deque(maxlen=max_records)
        self.formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.subscriptions: List[asyncio.Queue] = []

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
            
            # Real-time streaming to active subscribers
            for queue in self.subscriptions:
                asyncio.create_task(queue.put(entry))
        except Exception:
            self.handleError(record)

    def get_recent_logs(self, limit=500):
        return list(self.log_ring)[-limit:]

    async def subscribe(self):
        """Yields new logs as they arrive."""
        queue = asyncio.Queue()
        self.subscriptions.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self.subscriptions.remove(queue)

# Global memory handler tied to the central controller
global_memory_handler = UnifiedMemoryLogHandler(max_records=2000)
global_memory_handler.setLevel(logging.INFO)

def setup_terminal_logging():
    """Attaches the memory log handler to the root logger."""
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, UnifiedMemoryLogHandler):
            return
    root_logger.addHandler(global_memory_handler)

class LogController:
    """Manages system `.log` files, filtering, flushing, and searching."""
    
    def __init__(self, log_dir: str = "logs", event_db_path: str = "CyberNexus_events.db"):
        self.log_dir = os.path.abspath(log_dir)
        os.makedirs(self.log_dir, exist_ok=True)
        self.memory_handler = global_memory_handler
        self.event_db_path = event_db_path
    
    async def query_events(self, src_ip: Optional[str] = None, verdict: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Queries the security events database (Visitor Tracking)."""
        if not os.path.exists(self.event_db_path):
            return []
            
        results = []
        try:
            async with aiosqlite.connect(self.event_db_path) as db:
                db.row_factory = aiosqlite.Row
                query = "SELECT * FROM events WHERE 1=1"
                params = []
                
                if src_ip:
                    query += " AND src_ip = ?"
                    params.append(src_ip)
                if verdict:
                    query += " AND verdict = ?"
                    params.append(verdict)
                    
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                async with db.execute(query, params) as cursor:
                    async for row in cursor:
                        results.append(dict(row))
        except Exception as e:
            logger.error(f"Error querying event database: {e}")
            
        return results

    def list_log_files(self) -> List[str]:
        if not os.path.exists(self.log_dir):
            return []
        # Return all .log and .json files, sorted by name (or modify time)
        files = [f for f in os.listdir(self.log_dir) if f.endswith('.log') or f.endswith('.json')]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(self.log_dir, x)), reverse=True)
        # Also check logs/events directory if it exists
        events_dir = os.path.join(self.log_dir, "events")
        if os.path.exists(events_dir):
            evt_files = [f"events/{f}" for f in os.listdir(events_dir) if f.endswith('.json') or f.endswith('.log')]
            evt_files.sort(key=lambda x: os.path.getmtime(os.path.join(self.log_dir, x)), reverse=True)
            files.extend(evt_files)
        return files
        
    def search_logs(self, file_name: Optional[str] = None, level: Optional[str] = None, keyword: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        """A robust line-based parser for searching standard log files or JSON events."""
        results = []
        target_files = [file_name] if file_name else self.list_log_files()
        
        for f in target_files:
            file_path = os.path.join(self.log_dir, f)
            if not os.path.isfile(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as log_file:
                    lines = log_file.readlines()
                    # Read backward for newest first
                    for line in reversed(lines):
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                            
                        # Apply filters
                        if keyword and keyword.lower() not in line_stripped.lower():
                            continue
                        if level and level.upper() not in line_stripped.upper():
                            continue
                        
                        # Try parsing as JSON for structured logs, otherwise return raw text
                        content = line_stripped
                        try:
                            if line_stripped.startswith('{') and line_stripped.endswith('}'):
                                content = json.loads(line_stripped)
                        except json.JSONDecodeError:
                            pass
                            
                        results.append({
                            "file": f,
                            "content": content
                        })
                        
                        if len(results) >= limit:
                            return results
            except Exception as e:
                logger.error(f"Error reading log file {f}: {e}")
                
        return results

    def clear_logs(self, file_name: Optional[str] = None) -> int:
        """Truncates specific log file or all log files."""
        target_files = [file_name] if file_name else self.list_log_files()
        cleared = 0
        for f in target_files:
            file_path = os.path.join(self.log_dir, f)
            try:
                if os.path.isfile(file_path):
                    with open(file_path, 'w') as log_file:
                        log_file.truncate(0)
                    cleared += 1
            except Exception as e:
                logger.error(f"Error clearing log file {f}: {e}")
        return cleared

    def get_stats(self) -> Dict[str, Any]:
        total_size = 0
        files = self.list_log_files()
        for f in files:
            file_path = os.path.join(self.log_dir, f)
            if os.path.isfile(file_path):
                total_size += os.path.getsize(file_path)
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "log_dir": self.log_dir
        }

class LogControllerManager:
    """Singleton pattern to access the controller globally within the module."""
    _instance = None
    
    @classmethod
    def get_instance(cls, config: Dict[str, Any] = None) -> LogController:
        if cls._instance is None:
            settings = config if config else {}
            log_dir = settings.get("primary_log_dir", "logs")
            # Determine event_db_path from the event_sink config or module settings
            event_db_path = settings.get("event_db_path", "CyberNexus_events.db")
            cls._instance = LogController(log_dir=log_dir, event_db_path=event_db_path)
        return cls._instance
