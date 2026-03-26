#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - Main Entry Point
═══════════════════════════════════════════════════════════════════

Author: Enterprise Security Team
License: Proprietary
Version: 2.0.0
"""

import sys
import logging
import asyncio
import argparse
from pathlib import Path

# Setup initial console logging formatting before engine load
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)8s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Setup Web UI Logging Ring Buffer
from system.core.log_manager import setup_terminal_logging
setup_terminal_logging()

# Import the core engine
from system.core.engine import CyberNexusApplication
from modules.ssl_inspection.engine.ca_pool import CAPoolManager

def _print_banner(app):
    """Print startup banner"""
    if not app.config:
        logger.info("  🔥 Enterprise CyberNexus starting with default configuration")
        return
        
    proxy_config = app.config.get('proxy', {})
    tls_config = app.config.get('tls', {})
    ebpf_config = app.config.get('ebpf', {})
    api_config = app.config.get('api', {})
    
    logger.info("")
    logger.info("╔═══════════════════════════════════════════════════════════════════╗")
    logger.info("║         🔥 Enterprise CyberNexus - Successfully Started                ║")
    logger.info("╚═══════════════════════════════════════════════════════════════════╝")
    logger.info("")
    logger.info(f"  📡 Forward Proxy:  {proxy_config.get('forward_listen_host', '0.0.0.0')}:{proxy_config.get('forward_listen_port', 8080)}")
    logger.info(f"  🔒 Reverse Proxy:  {proxy_config.get('reverse_listen_host', '0.0.0.0')}:{proxy_config.get('reverse_listen_port', 443)}")
    logger.info(f"  📜 Root CA:        {tls_config.get('ca_cert_path', 'certs/root-ca.crt')}")
    logger.info(f"  ⚡ eBPF XDP:       {ebpf_config.get('enabled', False)}")
    logger.info(f"  🧠 ML Engine:      {app.config.get('ml', {}).get('enabled', True)}")
    logger.info(f"  🌐 VPN Server:     {app.vpn_enabled} (WireGuard)")
    logger.info(f"  🔌 REST API:       http://{api_config.get('host', '0.0.0.0')}:{api_config.get('port', 8000)}")
    logger.info("")
    logger.info("  ⚠️  IMPORTANT: Review SystemTerminal for Active Dashboard Logs!")
    logger.info("  Press Ctrl+C to stop")
    logger.info("")

async def async_main():
    parser = argparse.ArgumentParser(description='Enterprise CyberNexus - Next-Generation Firewall')
    parser.add_argument('-c', '--config', type=Path, default=Path('system/config/base.yaml'), help='Configuration API Path')
    parser.add_argument('--init-ca', action='store_true', help='Initialize CA certificates and exit')
    parser.add_argument('--export-ca', type=Path, metavar='DIR', help='Export CA certificates for client installation and exit')
    
    args = parser.parse_args()
    
    # Handle special operations
    if args.init_ca or args.export_ca:
        app = CyberNexusApplication(args.config)
        app.load_config()
        
        ca_manager = CAPoolManager(app.config)
        
        if args.export_ca:
            ca_manager.export_ca_for_clients(args.export_ca)
            logger.info(f"✅ CA certificates exported to {args.export_ca}")
        
        return
    
    # Normal operation
    app = CyberNexusApplication(args.config)
    
    try:
        app.load_config()
        await app.initialize_components()
        
        # Start API server
        from api.rest.main import app as api_app
        import uvicorn
        
        # Pass CyberNexus instance to API
        api_app.state.CyberNexus = app
        
        api_config = app.config.get('api', {})
        host = api_config.get('host', '0.0.0.0')
        port = api_config.get('port', 8000)
        
        _print_banner(app)
        
        # Start Firewall Engine Default Loop Thread
        await app.start_firewall_components()
        app.running = True
        
        # Run API
        config = uvicorn.Config(api_app, host=host, port=port, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()
        
        await app.run_forever()
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        await app.stop()


if __name__ == '__main__':
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
        sys.exit(0)
