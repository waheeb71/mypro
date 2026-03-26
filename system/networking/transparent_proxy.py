#!/usr/bin/env python3
"""
Enterprise CyberNexus - Dynamic Transparent Proxy Configuration Manager
Replaces the old setup-transparent-proxy.sh with a pure Python orchestrator.
Reads from system/config/base.yaml to automatically configure iptables on Linux.
"""

import os
import subprocess
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class TransparentProxyManager:
    """
    Manages systemic network rules (iptables/ip6tables) to actively intercept
    traffic based on the CyberNexus configuration.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.proxy_config = self.config.get("proxy", {})
        self.routing_config = self.config.get("routing", {})
        
        # We need to know which port the actual Python transparent proxy process listens on.
        # Typically 8443 for HTTPS intercept and 8080 for HTTP intercept.
        port_mappings = self.routing_config.get("port_mappings", {})
        self.https_redirect_port = 8443
        self.http_redirect_port = 8080
        
        for k, v in port_mappings.items():
            if str(k) == "443" and "transparent" in str(v):
                # Configuration doesn't directly tell what the intercept port is, assuming standard CyberNexus ports
                pass
                
        self.lan_interface = self._detect_bridge_or_lan()
        self.wan_interface = self._detect_wan()

    def _execute_iptables(self, args: List[str], ignore_errors: bool = False):
        try:
            cmd = ["iptables"] + args
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                logger.error(f"iptables error: {' '.join(cmd)}\n{e.stderr}")
            return False

    def _detect_wan(self) -> str:
        """Detect the default gateway interface."""
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if "dev" in parts:
                        idx = parts.index("dev")
                        return parts[idx + 1]
        except Exception as e:
            logger.debug(f"Could not auto-detect WAN: {e}")
        return "eth0"
        
    def _detect_bridge_or_lan(self) -> str:
        """Detect an internal facing interface. E.g. eth1 or br0"""
        try:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
            interfaces = [line.split(":")[1].strip() for line in result.stdout.splitlines() if "lo" not in line]
            if len(interfaces) > 1:
                # Exclude the WAN
                wan = self._detect_wan()
                for ifc in interfaces:
                    if ifc != wan:
                        return ifc
            elif set(interfaces):
                return interfaces[0]
        except Exception:
            pass
        return "eth0"

    def enable_ip_forwarding(self):
        """Enable Linux IP forwarding globally."""
        if os.name != "posix" or not os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            logger.warning("OS does not support standard Linux IP forwarding.")
            return

        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            logger.info("✅ IPv4 Forwarding enabled natively.")
        except PermissionError:
            logger.error("Failed to enable IP forwarding. Requires root.")

    def clear_existing_rules(self):
        """Clears all old CyberNexus_REDIRECT chains and rules."""
        if os.geteuid() != 0:
            logger.warning("Not root. Cannot modify iptables.")
            return
            
        logger.info("Cleaning up old CyberNexus iptables rules...")
        self._execute_iptables(["-t", "nat", "-D", "PREROUTING", "-j", "CyberNexus_REDIRECT"], ignore_errors=True)
        self._execute_iptables(["-t", "nat", "-F", "CyberNexus_REDIRECT"], ignore_errors=True)
        self._execute_iptables(["-t", "nat", "-X", "CyberNexus_REDIRECT"], ignore_errors=True)
        
        self._execute_iptables(["-D", "FORWARD", "-j", "CyberNexus_FORWARD"], ignore_errors=True)
        self._execute_iptables(["-F", "CyberNexus_FORWARD"], ignore_errors=True)
        self._execute_iptables(["-X", "CyberNexus_FORWARD"], ignore_errors=True)

    def setup_transparent_rules(self):
        """Configures the host to redirect traffic to the local inspection ports."""
        if os.geteuid() != 0:
            logger.warning("Skipping transparent iptables setup due to lack of root privileges.")
            return
            
        logger.info(f"Setting up transparent interception on LAN: {self.lan_interface}, WAN: {self.wan_interface}")
        
        try:
            # Create Custom Chain
            self._execute_iptables(["-t", "nat", "-N", "CyberNexus_REDIRECT"])
            
            # Exclude local traffic bounds
            for subnet in ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"]:
                self._execute_iptables(["-t", "nat", "-A", "CyberNexus_REDIRECT", "-d", subnet, "-j", "RETURN"])
            
            # By default, do not inspect traffic generated by the root proxy process itself
            # We assume the python proxy runs as root or a dedicated 'CyberNexus' user.
            uid = os.geteuid()
            self._execute_iptables(["-t", "nat", "-A", "CyberNexus_REDIRECT", "-m", "owner", "--uid-owner", str(uid), "-j", "RETURN"], ignore_errors=True)

            # Redirect Port 80
            self._execute_iptables(["-t", "nat", "-A", "CyberNexus_REDIRECT", "-p", "tcp", "--dport", "80", 
                                  "-j", "REDIRECT", "--to-ports", str(self.http_redirect_port)])
                                  
            # Redirect Port 443
            self._execute_iptables(["-t", "nat", "-A", "CyberNexus_REDIRECT", "-p", "tcp", "--dport", "443", 
                                  "-j", "REDIRECT", "--to-ports", str(self.https_redirect_port)])

            # Attach to PREROUTING for the LAN interface
            self._execute_iptables(["-t", "nat", "-I", "PREROUTING", "-i", self.lan_interface, "-j", "CyberNexus_REDIRECT"])
            
            # Forward masquerade for internet outbound
            if self.lan_interface != self.wan_interface:
                self._execute_iptables(["-t", "nat", "-A", "POSTROUTING", "-o", self.wan_interface, "-j", "MASQUERADE"])
                
            logger.info("✅ IPTables transparent NAT rules built successfully.")
        except Exception as e:
            logger.error(f"Failed to build transparent IPTables logic: {e}")

    def teardown(self):
        """Remove dynamically added rules during graceful shutdown."""
        self.clear_existing_rules()
        logger.info("✅ CyberNexus Network rules reverted.")

