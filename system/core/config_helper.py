#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Configuration Management

Helpers for loading and validating configuration with schema.
"""

import sys
from pathlib import Path
import yaml
import logging
from typing import Dict, Any
logger = logging.getLogger(__name__)
def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config is invalid YAML
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        if config is None:
            config = {}
        
        # Apply defaults
        config = apply_defaults(config)
        
        logger.info(f"Configuration loaded from {config_path}")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML in config file: {e}")
        raise


def apply_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply default values to configuration
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Configuration with defaults applied
    """
    defaults = {
        'event_sink': {
            'buffer_size': 1000,
            'flush_interval': 1.0,
            'batch_size': 100,
            'backends': [
                {
                    'type': 'file',
                    'output_dir': 'logs/events',
                    'format': 'json',
                    'rotation': 'daily'
                }
            ]
        },
        'ebpf': {
            'enabled': True,
            'interface': 'eth0',
            'xدp_mode': 'native',
            'feedback_interval': 5
        },
        'proxy': {
            'mode': 'transparent',
            'listen_port': 8080
        },
        'ml': {
            'enabled': True
        },
        'logging': {
            'level': 'INFO',
            'format': 'json'
        }
    }
    
    # Deep merge defaults with config
    return deep_merge(defaults, config)


def deep_merge(default: Dict, override: Dict) -> Dict:
    """
    Deep merge two dictionaries
    
    Args:
        default: Default values
        override: Override values
        
    Returns:
        Merged dictionary
    """
    result = default.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Basic validation
    required_sections = ['proxy']
    
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")
    
    # Validate event_sink backends
    if 'event_sink' in config:
        backends = config['event_sink'].get('backends', [])
        for backend in backends:
            if 'type' not in backend:
                raise ValueError("Event sink backend missing 'type' field")
    
    logger.info("Configuration validation passed")
    return True
