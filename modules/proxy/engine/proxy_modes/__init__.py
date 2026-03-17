#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Proxy Modes Package
═══════════════════════════════════════════════════════════════════

Different proxy operation modes:
- Forward Proxy: Explicit proxy configuration
- Transparent Proxy: Gateway mode (current implementation)
- Reverse Proxy: Web server protection
- Hybrid Proxy: Mixed mode operation

Author: Enterprise Security Team
"""

from .base_proxy import BaseProxy, ProxyConnection
from .transparent_proxy import MITMProxy as TransparentProxy
from .forward_proxy import ForwardProxy
from .reverse_proxy import ReverseProxy

__all__ = [
    "BaseProxy",
    "ProxyConnection",
    "TransparentProxy",
    "ForwardProxy",
    "ReverseProxy",
]
