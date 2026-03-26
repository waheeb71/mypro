#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise CyberNexus - CA Pool Manager (Multi-CA Support)
═══════════════════════════════════════════════════════════════════

Handles Root CA, Intermediate CA, and dynamic certificate generation
for SSL/TLS interception. Implements industry-standard PKI practices.

Author: Enterprise Security Team
License: Proprietary
"""
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple
import hashlib
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    Certificate, CertificateBuilder, Name, SubjectAlternativeName,
    BasicConstraints, KeyUsage, ExtendedKeyUsage
)

logger = logging.getLogger(__name__)


class CertificateCache:
    """Thread-safe LRU cache for generated certificates"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.cache = {}
        self.access_times = {}
        self.lock = threading.Lock()
    
    def get(self, hostname: str) -> Optional[Tuple[bytes, bytes]]:
        """Get cached certificate and private key"""
        with self.lock:
            if hostname in self.cache:
                self.access_times[hostname] = datetime.now()
                return self.cache[hostname]
            return None
    
    def put(self, hostname: str, cert: bytes, key: bytes):
        """Store certificate in cache"""
        with self.lock:
            # Remove oldest entry if cache is full
            if len(self.cache) >= self.max_size:
                oldest = min(self.access_times.items(), key=lambda x: x[1])
                del self.cache[oldest[0]]
                del self.access_times[oldest[0]]
            
            self.cache[hostname] = (cert, key)
            self.access_times[hostname] = datetime.now()
    
    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()


class CAPoolManager:
    """
    Certificate Authority Manager
    
    Manages Root CA, Intermediate CA, and dynamically generates
    server certificates for MITM interception.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.tls_config = config.get('tls', {})
        
        # Paths
        self.ca_cert_path = Path(self.tls_config.get('ca_cert_path'))
        self.ca_key_path = Path(self.tls_config.get('ca_key_path'))
        self.intermediate_cert_path = Path(self.tls_config.get('intermediate_ca_cert'))
        self.intermediate_key_path = Path(self.tls_config.get('intermediate_ca_key'))
        self.cert_cache_dir = Path(self.tls_config.get('cert_cache_dir'))
        
        # Create directories
        self.ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Certificate cache
        cache_size = self.tls_config.get('cert_cache_size', 10000)
        self.cert_cache = CertificateCache(max_size=cache_size)
        
        # Load or create CA
        self.use_intermediate = self.tls_config.get('use_intermediate_ca', True)
        self.root_ca_cert: Optional[Certificate] = None
        self.root_ca_key = None
        self.intermediate_ca_cert: Optional[Certificate] = None
        self.intermediate_ca_key = None
        
        self._initialize_ca()
    
    def _initialize_ca(self):
        """Initialize Certificate Authority"""
        logger.info("Initializing Certificate Authority...")
        
        # Load or create Root CA
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info(f"Loading existing Root CA from {self.ca_cert_path}")
            self._load_root_ca()
        else:
            logger.warning("Root CA not found. Creating new Root CA...")
            self._create_root_ca()
        
        # Load or create Intermediate CA
        if self.use_intermediate:
            if self.intermediate_cert_path.exists() and self.intermediate_key_path.exists():
                logger.info(f"Loading Intermediate CA from {self.intermediate_cert_path}")
                self._load_intermediate_ca()
            else:
                logger.warning("Intermediate CA not found. Creating new Intermediate CA...")
                self._create_intermediate_ca()
        
        logger.info("Certificate Authority initialized successfully")
    
    def _load_root_ca(self):
        """Load existing Root CA"""
        try:
            with open(self.ca_cert_path, 'rb') as f:
                self.root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(self.ca_key_path, 'rb') as f:
                self.root_ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Verify CA is valid
            subject = self.root_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            logger.info(f"Loaded Root CA: {subject}")
            logger.info(f"Valid until: {self.root_ca_cert.not_valid_after}")
            
        except Exception as e:
            logger.error(f"Failed to load Root CA: {e}")
            raise
    
    def _create_root_ca(self):
        """Create new Root CA"""
        logger.info("Generating Root CA certificate...")
        
        # Generate private key
        key_size = self.tls_config.get('cert_key_size', 2048)
        self.root_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise MITM Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Root CA"),
        ])
        
        self.root_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.root_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_ca_key.public_key()),
                critical=False,
            )
            .sign(self.root_ca_key, hashes.SHA256(), default_backend())
        )
        
        # Save to disk
        self._save_certificate(self.ca_cert_path, self.root_ca_cert)
        self._save_private_key(self.ca_key_path, self.root_ca_key)
        
        logger.info(f"Root CA created and saved to {self.ca_cert_path}")
        logger.warning("⚠️  IMPORTANT: Install root-ca.crt on all client devices!")
    
    def _load_intermediate_ca(self):
        """Load existing Intermediate CA"""
        try:
            with open(self.intermediate_cert_path, 'rb') as f:
                self.intermediate_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(self.intermediate_key_path, 'rb') as f:
                self.intermediate_ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            subject = self.intermediate_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            logger.info(f"Loaded Intermediate CA: {subject}")
            
        except Exception as e:
            logger.error(f"Failed to load Intermediate CA: {e}")
            raise
    
    def _create_intermediate_ca(self):
        """Create Intermediate CA signed by Root CA"""
        logger.info("Generating Intermediate CA certificate...")
        
        # Generate private key
        key_size = self.tls_config.get('cert_key_size', 2048)
        self.intermediate_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise MITM Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Intermediate CA"),
        ])
        
        issuer = self.root_ca_cert.subject
        
        self.intermediate_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.intermediate_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=1825))  # 5 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.intermediate_ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_ca_key.public_key()),
                critical=False,
            )
            .sign(self.root_ca_key, hashes.SHA256(), default_backend())
        )
        
        # Save to disk
        self._save_certificate(self.intermediate_cert_path, self.intermediate_ca_cert)
        self._save_private_key(self.intermediate_key_path, self.intermediate_ca_key)
        
        logger.info(f"Intermediate CA created and saved to {self.intermediate_cert_path}")
    
    def generate_server_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        Generate server certificate for MITM interception
        
        Args:
            hostname: Target hostname (e.g., "www.google.com")
        
        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        # Check cache first
        cached = self.cert_cache.get(hostname)
        if cached:
            logger.debug(f"Using cached certificate for {hostname}")
            return cached
        
        logger.debug(f"Generating certificate for {hostname}")
        
        # Choose signing CA
        if self.use_intermediate and self.intermediate_ca_cert:
            signing_cert = self.intermediate_ca_cert
            signing_key = self.intermediate_ca_key
        else:
            signing_cert = self.root_ca_cert
            signing_key = self.root_ca_key
        
        # Generate private key
        key_size = self.tls_config.get('cert_key_size', 2048)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise MITM Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        issuer = signing_cert.subject
        
        # Prepare SAN (Subject Alternative Names)
        san_list = [x509.DNSName(hostname)]
        
        # Add wildcard if not already wildcard
        if not hostname.startswith('*.'):
            san_list.append(x509.DNSName(f"*.{hostname}"))
        
        # Handle www prefix
        if hostname.startswith('www.'):
            san_list.append(x509.DNSName(hostname[4:]))
        else:
            san_list.append(x509.DNSName(f"www.{hostname}"))
        
        validity_days = self.tls_config.get('cert_validity_days', 365)
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=1))  # Allow 1 day clock skew
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
                critical=False,
            )
            .sign(signing_key, hashes.SHA256(), default_backend())
        )
        
        # Serialize
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Cache result
        self.cert_cache.put(hostname, cert_pem, key_pem)
        
        # Optionally save to disk cache
        self._save_to_disk_cache(hostname, cert_pem, key_pem)
        
        logger.info(f"Generated certificate for {hostname}")
        return cert_pem, key_pem
    
    def _save_to_disk_cache(self, hostname: str, cert_pem: bytes, key_pem: bytes):
        """Save certificate to disk cache"""
        try:
            # Create safe filename
            safe_name = hashlib.sha256(hostname.encode()).hexdigest()[:16]
            cert_file = self.cert_cache_dir / f"{safe_name}.crt"
            key_file = self.cert_cache_dir / f"{safe_name}.key"
            
            cert_file.write_bytes(cert_pem)
            key_file.write_bytes(key_pem)
            
        except Exception as e:
            logger.warning(f"Failed to save certificate to disk cache: {e}")
    
    def _save_certificate(self, path: Path, cert: Certificate):
        """Save certificate to file"""
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        path.write_bytes(cert_pem)
        os.chmod(path, 0o644)
    
    def _save_private_key(self, path: Path, key):
        """Save private key to file"""
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        path.write_bytes(key_pem)
        os.chmod(path, 0o600)  # Restrict access
    
    def get_ca_bundle(self) -> bytes:
        """
        Get CA bundle (Root + Intermediate) for client installation
        
        Returns:
            PEM-encoded certificate bundle
        """
        bundle = self.root_ca_cert.public_bytes(serialization.Encoding.PEM)
        
        if self.use_intermediate and self.intermediate_ca_cert:
            bundle += self.intermediate_ca_cert.public_bytes(serialization.Encoding.PEM)
        
        return bundle
    
    def export_ca_for_clients(self, output_dir: Path):
        """
        Export CA certificates in various formats for client installation
        
        Args:
            output_dir: Directory to save client installation files
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # PEM format (Linux, macOS)
        pem_file = output_dir / "enterprise-ca.pem"
        pem_file.write_bytes(self.get_ca_bundle())
        
        # CRT format (Windows, Linux)
        crt_file = output_dir / "enterprise-ca.crt"
        crt_file.write_bytes(self.get_ca_bundle())
        
        # DER format (Windows)
        der_file = output_dir / "enterprise-ca.der"
        der_data = self.root_ca_cert.public_bytes(serialization.Encoding.DER)
        der_file.write_bytes(der_data)
        
        logger.info(f"CA certificates exported to {output_dir}")
        logger.info("Installation instructions:")
        logger.info("  Linux: cp enterprise-ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates")
        logger.info("  macOS: Open enterprise-ca.crt and add to System Keychain")
        logger.info("  Windows: Double-click enterprise-ca.der and install to Trusted Root")