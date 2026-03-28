import logging
from typing import Optional
from system.inspection_core.framework.plugin_base import InspectorPlugin, InspectionContext, InspectionResult
from .log_controller import LogControllerManager

class LogManagerPlugin(InspectorPlugin):
    """
    Log Manager Plugin.
    Provides lifecycle hooks into ModuleManager but does not inspect traffic.
    Mainly used to initialize the global LogController instance.
    """
    PLUGIN_NAME = "log_manager"
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(name=self.PLUGIN_NAME, priority=100, logger=logger)
        self.config = {}
        
    def can_inspect(self, context: InspectionContext) -> bool:
        # We don't inspect network packets
        return False
        
    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        # No-op
        return InspectionResult()
        
    def initialize(self):
        """Called automatically or manually if supported by the Module initialization flow."""
        # Initialize the global LogController singleton
        LogControllerManager.get_instance(self.config)
        self.logger.info("LogManagerPlugin initialized.")
