"""
CyberNexus NGFW — mTLS Manager
================================
Auto-generates short-lived service certificates from the internal CA.
Enables mTLS between all internal FastAPI services.

Controlled by features.yaml:
  features.security.mtls_internal: true

When disabled → no-op, standard HTTP between services.

Usage:
    mtls = MTLSManager.instance()
    ssl_ctx = mtls.get_ssl_context("api-service")

    # For httpx inter-service calls
    async with httpx.AsyncClient(verify=ssl_ctx) as client:
        r = await client.get("https://ml-service/infer")
"""

import logging
import ssl
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class MTLSManager:
    """
    Manages internal TLS certificate lifecycle for mTLS between services.
    Generates 24-hour service certs signed by the existing internal CA.
    Auto-rotates before expiry via background thread.
    """

    _instance: Optional["MTLSManager"] = None
    _lock = threading.RLock()

    CERT_VALIDITY_HOURS = 24
    ROTATION_CHECK_INTERVAL_S = 3600      # Check for rotation every hour

    def __init__(self, ca_dir: Optional[Path] = None):
        self._flags = None
        self._ca_dir = ca_dir or Path("system/auth/pki")
        self._certs_dir = Path("certs/internal")
        self._certs_dir.mkdir(parents=True, exist_ok=True)
        self._enabled = False

        try:
            from system.config.feature_flags import FeatureFlagManager
            self._flags = FeatureFlagManager.instance()
            self._enabled = self._flags.current.security.mtls_internal
        except Exception:
            pass

        if self._enabled:
            self._watcher = threading.Thread(
                target=self._rotation_loop,
                name="mTLS-CertRotation",
                daemon=True,
            )
            self._watcher.start()
            logger.info("[mTLS] Manager started — cert rotation active")
        else:
            logger.info("[mTLS] Disabled via feature flag — using plain HTTP internally")

    @classmethod
    def instance(cls) -> "MTLSManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get_ssl_context(self, service_name: str) -> Optional[ssl.SSLContext]:
        """
        Returns an ssl.SSLContext configured for mTLS.
        Returns None when mTLS is disabled (caller uses plain HTTP).
        """
        if not self._enabled:
            return None

        cert_path = self._certs_dir / f"{service_name}.crt"
        key_path  = self._certs_dir / f"{service_name}.key"
        ca_path   = self._ca_dir    / "ca.crt"

        if not cert_path.exists() or not key_path.exists():
            logger.warning(f"[mTLS] Cert not found for {service_name} — falling back to no mTLS")
            return None

        try:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            return ctx
        except Exception as exc:
            logger.error(f"[mTLS] Failed to create SSL context for {service_name}: {exc}")
            return None

    def get_server_ssl_context(self, service_name: str) -> Optional[ssl.SSLContext]:
        """SSL context for FastAPI server (requires client cert)."""
        if not self._enabled:
            return None

        cert_path = self._certs_dir / f"{service_name}.crt"
        key_path  = self._certs_dir / f"{service_name}.key"
        ca_path   = self._ca_dir    / "ca.crt"

        if not cert_path.exists():
            return None

        try:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(ca_path))
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            return ctx
        except Exception as exc:
            logger.error(f"[mTLS] Server SSL context error: {exc}")
            return None

    def generate_service_cert(self, service_name: str) -> bool:
        """
        Generate a new service certificate signed by the internal CA.
        Requires: cryptography library + CA private key accessible.
        Returns True on success.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress

            # Load CA
            ca_cert_path = self._ca_dir / "ca.crt"
            ca_key_path  = self._ca_dir / "ca.key"

            if not ca_cert_path.exists() or not ca_key_path.exists():
                logger.warning(f"[mTLS] CA files not found at {self._ca_dir}")
                return False

            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)

            # Generate service key
            svc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Build certificate
            now = datetime.now(timezone.utc)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"ngfw.{service_name}.internal"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberNexus NGFW"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(svc_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(hours=self.CERT_VALIDITY_HOURS))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(f"ngfw.{service_name}.internal"),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]),
                    critical=False,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Write cert and key
            cert_path = self._certs_dir / f"{service_name}.crt"
            key_path  = self._certs_dir / f"{service_name}.key"

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(svc_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))

            logger.info(f"[mTLS] Generated cert for {service_name} (valid 24h)")
            return True

        except ImportError:
            logger.warning("[mTLS] cryptography library not installed — cannot generate certs")
            return False
        except Exception as exc:
            logger.error(f"[mTLS] Cert generation failed for {service_name}: {exc}")
            return False

    def _rotation_loop(self) -> None:
        """Background thread: rotate certs approaching expiry."""
        import time
        services = ["api-service", "ml-service", "correlation-engine"]

        while True:
            time.sleep(self.ROTATION_CHECK_INTERVAL_S)
            try:
                for svc in services:
                    cert_path = self._certs_dir / f"{svc}.crt"
                    if not cert_path.exists():
                        self.generate_service_cert(svc)
                        continue

                    # Check expiry
                    from cryptography import x509
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                    remaining = cert.not_valid_after_utc - datetime.now(timezone.utc)
                    if remaining < timedelta(hours=4):   # Rotate when < 4h remain
                        logger.info(f"[mTLS] Rotating cert for {svc} ({remaining} remaining)")
                        self.generate_service_cert(svc)
            except Exception as exc:
                logger.error(f"[mTLS] Rotation loop error: {exc}")
