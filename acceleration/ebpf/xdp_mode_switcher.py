#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - XDP Runtime Mode Switching

Provides functionality to switch XDP modes at runtime without
restarting the service.

Features:
- Switch between XDP modes (native, generic, offload)
- Switch between XDP and normal proxy mode
- Graceful transition with minimal packet loss
"""

import asyncio
import logging
from enum import Enum
from typing import Optional


logger = logging.getLogger(__name__)


class XDPMode(Enum):
    """XDP attachment modes"""
    NATIVE = "native"      # Native XDP (driver support required)
    GENERIC = "generic"    # Generic XDP (kernel fallback)
    OFFLOAD = "offload"    # XDP offload to NIC firmware
    DISABLED = "disabled"  # XDP disabled (normal mode)


class XDPModeSwitcher:
    """
    Handles runtime switching of XDP modes
    
    This allows changing XDP configuration without service restart,
    enabling dynamic optimization based on traffic patterns or
    system conditions.
    """
    
    def __init__(self, xdp_engine):
        """
        Initialize mode switcher
        
        Args:
            xdp_engine: XDPEngine instance
        """
        self.xdp_engine = xdp_engine
        self.current_mode = XDPMode.DISABLED
        self.logger = logger
        
        # Detect current mode from engine
        if hasattr(xdp_engine, 'mode'):
            mode_str = getattr(xdp_engine, 'mode', 'generic')
            self.current_mode = XDPMode(mode_str)
    
    async def switch_mode(
        self,
        target_mode: XDPMode,
        interface: Optional[str] = None
    ) -> bool:
        """
        Switch XDP mode at runtime
        
        Args:
            target_mode: Target XDP mode
            interface: Network interface (optional, uses current if not provided)
            
        Returns:
            True if switch successful, False otherwise
        """
        if target_mode == self.current_mode:
            self.logger.info(f"Already in {target_mode.value} mode")
            return True
        
        self.logger.info(
            f"Switching XDP mode: {self.current_mode.value} -> {target_mode.value}"
        )
        
        try:
            # Step 1: Detach current XDP program
            if self.current_mode != XDPMode.DISABLED:
                await self._detach_xdp()
            
            # Step 2: Attach new XDP program (if not disabling)
            if target_mode != XDPMode.DISABLED:
                success = await self._attach_xdp(target_mode, interface)
                if not success:
                    self.logger.error(f"Failed to attach XDP in {target_mode.value} mode")
                    # Try to restore previous mode
                    await self._attach_xdp(self.current_mode, interface)
                    return False
            
            # Step 3: Update state
            old_mode = self.current_mode
            self.current_mode = target_mode
            
            self.logger.info(
                f"✅ Successfully switched XDP mode: {old_mode.value} -> {target_mode.value}"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Error switching XDP mode: {e}", exc_info=True)
            return False
    
    async def _detach_xdp(self) -> bool:
        """
        Detach current XDP program
        
        Returns:
            True if successful
        """
        try:
            if hasattr(self.xdp_engine, 'detach'):
                await self.xdp_engine.detach()
            elif hasattr(self.xdp_engine, 'stop'):
                await self.xdp_engine.stop()
            
            self.logger.debug("XDP program detached")
            return True
            
        except Exception as e:
            self.logger.error(f"Error detaching XDP: {e}")
            return False
    
    async def _attach_xdp(
        self,
        mode: XDPMode,
        interface: Optional[str] = None
    ) -> bool:
        """
        Attach XDP program in specified mode
        
        Args:
            mode: XDP mode to attach
            interface: Network interface
            
        Returns:
            True if successful
        """
        try:
            # Update engine mode
            if hasattr(self.xdp_engine, 'mode'):
                setattr(self.xdp_engine, 'mode', mode.value)
            
            # Update interface if provided
            if interface and hasattr(self.xdp_engine, 'interface'):
                setattr(self.xdp_engine, 'interface', interface)
            
            # Attach/restart engine
            if hasattr(self.xdp_engine, 'attach'):
                await self.xdp_engine.attach()
            elif hasattr(self.xdp_engine, 'start'):
                await self.xdp_engine.start()
            
            self.logger.debug(f"XDP program attached in {mode.value} mode")
            return True
            
        except Exception as e:
            self.logger.error(f"Error attaching XDP in {mode.value} mode: {e}")
            return False
    
    async def switch_to_native(self, interface: Optional[str] = None) -> bool:
        """Switch to native XDP mode"""
        return await self.switch_mode(XDPMode.NATIVE, interface)
    
    async def switch_to_generic(self, interface: Optional[str] = None) -> bool:
        """Switch to generic XDP mode"""
        return await self.switch_mode(XDPMode.GENERIC, interface)
    
    async def switch_to_offload(self, interface: Optional[str] = None) -> bool:
        """Switch to offload XDP mode"""
        return await self.switch_mode(XDPMode.OFFLOAD, interface)
    
    async def disable_xdp(self) -> bool:
        """Disable XDP (switch to normal proxy mode)"""
        return await self.switch_mode(XDPMode.DISABLED)
    
    def get_current_mode(self) -> XDPMode:
        """Get current XDP mode"""
        return self.current_mode
    
    async def test_mode_compatibility(self, mode: XDPMode) -> bool:
        """
        Test if a mode is compatible with current hardware/kernel
        
        Args:
            mode: XDP mode to test
            
        Returns:
            True if compatible
        """
        # This would check kernel version, driver capabilities, etc.
        # For now, simplified implementation
        
        if mode == XDPMode.NATIVE:
            # Check if driver supports XDP
            # Would need to query ethtool or check driver info
            return True  # Simplified
        
        elif mode == XDPMode.GENERIC:
            # Generic mode should always work (kernel fallback)
            return True
        
        elif mode == XDPMode.OFFLOAD:
            # Requires NIC firmware support
            # Very few NICs support this
            return False  # Conservative default
        
        else:  # DISABLED
            return True
    
    def get_mode_info(self) -> dict:
        """
        Get information about current mode
        
        Returns:
            Dictionary with mode information
        """
        return {
            'current_mode': self.current_mode.value,
            'interface': getattr(self.xdp_engine, 'interface', 'unknown'),
            'active': self.current_mode != XDPMode.DISABLED,
            'native_supported': True,  # Would check actual capability
            'generic_supported': True,
            'offload_supported': False
        }


# Convenience function for API integration
async def create_mode_switcher(xdp_engine) -> XDPModeSwitcher:
    """
    Create XDP mode switcher
    
    Args:
        xdp_engine: XDPEngine instance
        
    Returns:
        XDPModeSwitcher instance
    """
    return XDPModeSwitcher(xdp_engine)
