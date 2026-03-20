"""
Enterprise NGFW - WireGuard VPN Manager

Manages WireGuard VPN interfaces, keys, and peers for Site-to-Site
and Remote Access VPN capabilities.

Provides a Python wrapper around the `wg` and `ip` command-line tools.
"""

import os
import subprocess
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class PeerConfig:
    public_key: str
    allowed_ips: List[str]
    endpoint: Optional[str] = None
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = 25

class WireGuardManager:
    """Manages WireGuard interfaces and configuration."""
    
    def __init__(self, interface: str = "wg0", logger: Optional[logging.Logger] = None):
        self.interface = interface
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.listen_port: int = 51820
        self.peers: Dict[str, PeerConfig] = {}
        
    def _run_cmd(self, cmd: List[str], check: bool = True, log_error: bool = True) -> str:
        """Run a shell command and return its output."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if log_error:
                self.logger.error(f"Command failed: {' '.join(cmd)}\nError: {e.stderr}")
            if check:
                raise
            return ""

    def generate_keys(self) -> tuple[str, str]:
        """Generate a new Ed25519 keypair for WireGuard."""
        try:
            priv_key = self._run_cmd(["wg", "genkey"])
            
            # Generate public key from private key
            process = subprocess.Popen(
                ["wg", "pubkey"], 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            pub_key, err = process.communicate(input=priv_key)
            
            if process.returncode != 0:
                raise RuntimeError(f"Failed to generate public key: {err}")
                
            self.private_key = priv_key.strip()
            self.public_key = pub_key.strip()
            
            self.logger.info("Generated new WireGuard keypair.")
            return self.private_key, self.public_key
        except FileNotFoundError:
            self.logger.error("WireGuard tools ('wg') not found. Please install wireguard-tools.")
            raise

    def setup_interface(self, ip_address: str, port: int = 51820) -> bool:
        """Create and configure the WireGuard interface."""
        self.listen_port = port
        if not self.private_key:
            self.generate_keys()
            
        try:
            # Check if interface exists
            if not self._interface_exists():
                self._run_cmd(["ip", "link", "add", "dev", self.interface, "type", "wireguard"])
            
            # Assign IP
            self._run_cmd(["ip", "address", "add", "dev", self.interface, ip_address])
            
            # Configure WireGuard
            with open(f"/tmp/{self.interface}_private.key", "w") as f:
                f.write(self.private_key)
                
            self._run_cmd([
                "wg", "set", self.interface, 
                "listen-port", str(self.listen_port), 
                "private-key", f"/tmp/{self.interface}_private.key"
            ])
            
            os.remove(f"/tmp/{self.interface}_private.key")
            
            # Bring interface up
            self._run_cmd(["ip", "link", "set", "up", "dev", self.interface])
            
            self.logger.info(f"WireGuard interface {self.interface} configured and up (IP: {ip_address}, Port: {port})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup WireGuard interface {self.interface}: {e}")
            return False

    def add_peer(self, peer: PeerConfig) -> bool:
        """Add a peer to the WireGuard interface."""
        if not self._interface_exists():
            self.logger.error(f"Cannot add peer: Interface {self.interface} does not exist.")
            return False
            
        cmd = ["wg", "set", self.interface, "peer", peer.public_key, "allowed-ips", ",".join(peer.allowed_ips)]
        
        if peer.endpoint:
            cmd.extend(["endpoint", peer.endpoint])
        if peer.persistent_keepalive:
            cmd.extend(["persistent-keepalive", str(peer.persistent_keepalive)])
        if peer.preshared_key:
            with open(f"/tmp/{peer.public_key[:8]}.psk", "w") as f:
                f.write(peer.preshared_key)
            cmd.extend(["preshared-key", f"/tmp/{peer.public_key[:8]}.psk"])
            
        try:
            self._run_cmd(cmd)
            self.peers[peer.public_key] = peer
            self.logger.info(f"Added peer {peer.public_key[:8]}... to {self.interface}")
            
            if peer.preshared_key:
                os.remove(f"/tmp/{peer.public_key[:8]}.psk")
                
            return True
        except Exception as e:
            self.logger.error(f"Failed to add peer: {e}")
            return False

    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from the WireGuard interface."""
        try:
            self._run_cmd(["wg", "set", self.interface, "peer", public_key, "remove"])
            if public_key in self.peers:
                del self.peers[public_key]
            self.logger.info(f"Removed peer {public_key[:8]}... from {self.interface}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to remove peer: {e}")
            return False

    def teardown(self) -> bool:
        """Bring down and delete the WireGuard interface."""
        if self._interface_exists():
            try:
                self._run_cmd(["ip", "link", "del", "dev", self.interface])
                self.logger.info(f"Deleted WireGuard interface {self.interface}.")
                return True
            except Exception as e:
                self.logger.error(f"Failed to delete interface {self.interface}: {e}")
                return False
        return True

    def _interface_exists(self) -> bool:
        """Check if the network interface exists."""
        try:
            self._run_cmd(["ip", "link", "show", "dev", self.interface], log_error=False)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def get_status(self) -> str:
        """Get the current status of the WireGuard interface."""
        if not self._interface_exists():
            return "Interface down"
        return self._run_cmd(["wg", "show", self.interface], check=False)
