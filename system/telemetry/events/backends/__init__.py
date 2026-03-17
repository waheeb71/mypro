"""
Enterprise NGFW - Event Backends
Pluggable backends for event storage and streaming.
"""

from .base import EventBackend
from .file_backend import FileBackend
from .database_backend import DatabaseBackend
from .streaming_backend import StreamingBackend

__all__ = [
    'EventBackend',
    'FileBackend',
    'DatabaseBackend',
    'StreamingBackend',
]
