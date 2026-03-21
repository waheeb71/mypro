"""
Enterprise NGFW v2.0 - Inspection Pipeline

Main inspection pipeline that orchestrates all plugins.

Author: Enterprise NGFW Team
License: Proprietary
"""

import logging
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import IntEnum
import threading

from .plugin_base import InspectorPlugin, InspectionContext, InspectionFinding, InspectionResult, InspectionAction



class InspectionPipeline:
    """
    Main inspection pipeline.
    
    Orchestrates multiple inspection plugins to analyze traffic.
    Plugins are executed in priority order.
    """
    
    def __init__(
        self,
        logger: Optional[logging.Logger] = None
    ):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Plugin registry
        self._plugins: List[InspectorPlugin] = []
        self._plugins_by_name: Dict[str, InspectorPlugin] = {}
        
        # Configuration
        self._fail_open = False  # Fail open (allow) or fail closed (block)
        self._max_processing_time_ms = 1000  # Max time per inspection
        
        # Statistics
        self._total_inspections = 0
        self._total_blocks = 0
        self._total_processing_time_ms = 0.0
        
        # Thread safety
        self._lock = threading.RLock()
        
        self.logger.info("Inspection pipeline initialized")
        
    def register_plugin(self, plugin: InspectorPlugin) -> None:
        """
        Register an inspection plugin.
        
        Args:
            plugin: Plugin to register
        """
        with self._lock:
            if plugin.name in self._plugins_by_name:
                self.logger.warning(f"Plugin {plugin.name} already registered, replacing")
                self.unregister_plugin(plugin.name)
                
            self._plugins.append(plugin)
            self._plugins_by_name[plugin.name] = plugin
            
            # Re-sort by priority
            self._plugins.sort(key=lambda p: p.priority)
            
            self.logger.info(f"Registered plugin: {plugin}")
            
    def unregister_plugin(self, plugin_name: str) -> bool:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of plugin to remove
            
        Returns:
            True if plugin was removed
        """
        with self._lock:
            if plugin_name not in self._plugins_by_name:
                return False
                
            plugin = self._plugins_by_name[plugin_name]
            self._plugins.remove(plugin)
            del self._plugins_by_name[plugin_name]
            
            self.logger.info(f"Unregistered plugin: {plugin_name}")
            return True
            
    def inspect(
        self,
        context: InspectionContext,
        data: bytes
    ) -> InspectionResult:
        """
        Inspect traffic through all applicable plugins.
        
        Args:
            context: Inspection context
            data: Traffic data to inspect
            
        Returns:
            InspectionResult with aggregated findings
        """
        start_time = time.time()
        
        with self._lock:
            self._total_inspections += 1
            
        result = InspectionResult(action=InspectionAction.ALLOW)
        
        try:
            # Execute plugins in priority order
            for plugin in self._plugins:
                if not plugin.enabled:
                    continue
                    
                # Check if plugin can handle this traffic
                if not plugin.can_inspect(context):
                    continue
                    
                # Check timeout
                elapsed = (time.time() - start_time) * 1000
                if elapsed > self._max_processing_time_ms:
                    self.logger.warning(
                        f"Inspection timeout reached at plugin {plugin.name}"
                    )
                    break
                    
                try:
                    # Run plugin inspection
                    plugin_result = plugin.inspect(context, data)
                    
                    # Aggregate findings
                    result.findings.extend(plugin_result.findings)
                    
                    # Take most restrictive action
                    if plugin_result.action > result.action:
                        result.action = plugin_result.action
                        
                    # Merge metadata
                    result.metadata.update(plugin_result.metadata)
                    
                    # Update plugin stats
                    plugin._inspected_count += 1
                    if plugin_result.findings:
                        plugin._detected_count += 1
                    if plugin_result.is_blocked:
                        plugin._blocked_count += 1
                        
                except Exception as e:
                    self.logger.error(
                        f"Plugin {plugin.name} failed: {e}",
                        exc_info=True
                    )
                    
                    if not self._fail_open:
                        # Fail closed: block on error
                        result.action = InspectionAction.BLOCK
                        result.findings.append(InspectionFinding(
                            severity='HIGH',
                            category='inspection_error',
                            description=f"Plugin {plugin.name} error",
                            plugin_name=plugin.name,
                            confidence=1.0
                        ))
                        break
                        
        except Exception as e:
            self.logger.error(f"Pipeline inspection failed: {e}", exc_info=True)
            
            if not self._fail_open:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding(
                    severity='CRITICAL',
                    category='pipeline_error',
                    description="Pipeline error",
                    plugin_name='pipeline',
                    confidence=1.0
                ))
                
        # Calculate processing time
        end_time = time.time()
        result.processing_time_ms = (end_time - start_time) * 1000
        
        with self._lock:
            self._total_processing_time_ms += result.processing_time_ms
            if result.is_blocked:
                self._total_blocks += 1
                
        # Log result
        if result.findings:
            self.logger.info(
                f"Inspection completed: {len(result.findings)} findings, "
                f"action={result.action.name}, time={result.processing_time_ms:.2f}ms"
            )
            
        return result

    async def inspect_async(
        self,
        context: InspectionContext,
        data: bytes
    ) -> InspectionResult:
        """
        Asynchronously inspect traffic through all applicable plugins.
        """
        import time
        start_time = time.time()
        
        with self._lock:
            self._total_inspections += 1
            
        result = InspectionResult(action=InspectionAction.ALLOW)
        
        try:
            for plugin in self._plugins:
                if not plugin.enabled or not plugin.can_inspect(context):
                    continue
                    
                elapsed = (time.time() - start_time) * 1000
                if elapsed > self._max_processing_time_ms:
                    self.logger.warning(
                        f"Async Inspection timeout reached at plugin {plugin.name}"
                    )
                    break
                    
                try:
                    plugin_result = await plugin.inspect_async(context, data)
                    
                    result.findings.extend(plugin_result.findings)
                    if plugin_result.action > result.action:
                        result.action = plugin_result.action
                    result.metadata.update(plugin_result.metadata)
                    
                    plugin._inspected_count += 1
                    if plugin_result.findings:
                        plugin._detected_count += 1
                    if plugin_result.is_blocked:
                        plugin._blocked_count += 1
                        
                except Exception as e:
                    self.logger.error(
                        f"Plugin {plugin.name} failed during async execution: {e}",
                        exc_info=True
                    )
                    if not self._fail_open:
                        result.action = InspectionAction.BLOCK
                        result.findings.append(InspectionFinding(
                            severity='HIGH', category='inspection_error',
                            description=f"Plugin {plugin.name} async error",
                            plugin_name=plugin.name, confidence=1.0
                        ))
                        break
                        
        except Exception as e:
            self.logger.error(f"Async Pipeline inspection failed: {e}", exc_info=True)
            if not self._fail_open:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding(
                    severity='CRITICAL', category='pipeline_error',
                    description="Async Pipeline error", plugin_name='pipeline', confidence=1.0
                ))
                
        end_time = time.time()
        result.processing_time_ms = (end_time - start_time) * 1000
        
        with self._lock:
            self._total_processing_time_ms += result.processing_time_ms
            if result.is_blocked:
                self._total_blocks += 1
                
        if result.findings:
            self.logger.info(
                f"Async Inspection completed: {len(result.findings)} findings, "
                f"action={result.action.name}, time={result.processing_time_ms:.2f}ms"
            )
            
        return result
        
    def set_fail_mode(self, fail_open: bool) -> None:
        """Set fail mode (open or closed)"""
        self._fail_open = fail_open
        mode = "open" if fail_open else "closed"
        self.logger.info(f"Fail mode set to: {mode}")
        
    def set_max_processing_time(self, time_ms: int) -> None:
        """Set maximum processing time per inspection"""
        self._max_processing_time_ms = time_ms
        self.logger.info(f"Max processing time set to: {time_ms}ms")
        
    def get_plugins(self) -> List[InspectorPlugin]:
        """Get all registered plugins"""
        with self._lock:
            return list(self._plugins)
            
    def get_plugin(self, name: str) -> Optional[InspectorPlugin]:
        """Get plugin by name"""
        with self._lock:
            return self._plugins_by_name.get(name)
            
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enable()
            return True
        return False
        
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.disable()
            return True
        return False
        
    def get_statistics(self) -> Dict:
        """Get pipeline statistics"""
        with self._lock:
            avg_time = (
                self._total_processing_time_ms / max(self._total_inspections, 1)
            )
            
            return {
                'total_inspections': self._total_inspections,
                'total_blocks': self._total_blocks,
                'block_rate': (
                    self._total_blocks / max(self._total_inspections, 1) * 100
                ),
                'avg_processing_time_ms': avg_time,
                'total_processing_time_ms': self._total_processing_time_ms,
                'plugins_count': len(self._plugins),
                'enabled_plugins': sum(1 for p in self._plugins if p.enabled),
                'fail_mode': 'open' if self._fail_open else 'closed',
                'max_processing_time_ms': self._max_processing_time_ms
            }
            
    def get_plugin_statistics(self) -> Dict[str, Dict]:
        """Get statistics for all plugins"""
        with self._lock:
            return {
                plugin.name: plugin.get_statistics()
                for plugin in self._plugins
            }
