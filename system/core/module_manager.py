import logging
import importlib
from typing import Dict, Any
from system.inspection_core.framework.pipeline import InspectionPipeline

logger = logging.getLogger(__name__)

class ModuleManager:
    """ Reads config and dynamically loads enabled CyberNexus modules into the pipeline """
    
    # Mapping config keys to plugin import paths and classes
    PLUGIN_REGISTRY = {
        "dlp": {
            "module": "modules.dlp.engine.dlp_inspector",
            "class": "DLPInspectorPlugin"
        },
        "waf": {
            "module": "modules.waf.engine.waf_inspector",
            "class": "WAFInspectorPlugin"
        },
        "web_filter": {
            "module": "modules.web_filter.engine.plugin",
            "class": "WebFilterPlugin"
        },
        "malware_av": {
            "module": "modules.malware_av.engine.plugin",
            "class": "MalwareAVPlugin"
        },
        "dns_security": {
            "module": "modules.dns_security.engine.plugin",
            "class": "DNSSecurityPlugin"
        },
        "http_inspection": {
            "module": "modules.http_inspection.engine.plugin",
            "class": "HTTPInspectorPlugin"
        },
        "email_security": {
            "module": "modules.email_security.engine.core.email_inspector",
            "class": "EmailInspectorPlugin"
        },
        "uba": {
            "module": "modules.uba.engine.core.uba_plugin",
            "class": "UBAPlugin"
        },
        "qos": {
            "module": "modules.qos.engine.qos_plugin",
            "class": "QoSPlugin"
        },
        "firewall": {
            "module": "modules.firewall.engine.firewall_plugin",
            "class": "FirewallPlugin"
        },
    }
    
    def __init__(self, config: Dict[str, Any], pipeline: InspectionPipeline):
        self.config = config
        self.pipeline = pipeline
        self.modules_config = self.config.get('modules', {})
        
    def load_plugins(self):
        """ Dynamically loads and registers plugins for enabled modules """
        loaded_count = 0
        logger.info("Starting Dynamic Module Loader...")
        
        for module_name, plugin_info in self.PLUGIN_REGISTRY.items():
            mod_conf = self.modules_config.get(module_name, {})
            # If enabled in config (default False if missing)
            if mod_conf.get('enabled', False):
                try:
                    logger.debug(f"Attempting to load {module_name} plugin...")
                    mod = importlib.import_module(plugin_info["module"])
                    plugin_class = getattr(mod, plugin_info["class"])
                    plugin_instance = plugin_class()
                    
                    self.pipeline.register_plugin(plugin_instance)
                    loaded_count += 1
                    logger.info(f"✅ Successfully loaded and activated plugin: {plugin_class.__name__}")
                except Exception as e:
                    logger.error(f"Failed to load plugin for module '{module_name}': {e}", exc_info=True)
            else:
                logger.debug(f"Module '{module_name}' is disabled in configuration. Skipping.")
                
        logger.info(f"Dynamic Module Loader finished. Activated {loaded_count} plugins.")
