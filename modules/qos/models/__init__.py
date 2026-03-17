"""
modules/qos/models/__init__.py

Re-exports QoSConfig from the central database module for backward compatibility.
All imports across the codebase that do `from modules.qos.models import QoSConfig`
will continue to work without changes.
"""

from system.database.database import QoSConfig  # noqa: F401

__all__ = ["QoSConfig"]
