from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import FileResponse, Response
from typing import Dict, Any
import os
import time
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from api.rest.auth import require_admin, verify_token

router = APIRouter(prefix="/api/v1/certificates", tags=["certificates", "system"])

# Default paths used by the system
DEFAULT_CA_CERT_PATH = "/etc/enterprise-CyberNexus/certs/ca.crt"
DEFAULT_CA_KEY_PATH = "/etc/enterprise-CyberNexus/certs/ca.key"

def get_cert_paths(request: Request):
    """Try to determine the exact cert path from running config, otherwise fallback to default."""
    try:
        if hasattr(request.app.state, 'CyberNexus_controller'):
            cfg = request.app.state.CyberNexus_controller.config
            tls_cfg = cfg.get('tls', {})
            cert_path = tls_cfg.get('ca_cert_path', DEFAULT_CA_CERT_PATH)
            key_path = tls_cfg.get('ca_key_path', DEFAULT_CA_KEY_PATH)
            return cert_path, key_path
    except Exception:
        pass
    return DEFAULT_CA_CERT_PATH, DEFAULT_CA_KEY_PATH


@router.get("/ca/info", response_model=Dict[str, Any])
async def get_ca_info(request: Request, token: dict = Depends(verify_token)):
    """Get internal details about the CyberNexus Transparent Proxy Root CA"""
    cert_path, _ = get_cert_paths(request)
    
    if not os.path.exists(cert_path):
        return {"status": "not_found", "message": "Root CA certificate not found on disk."}
        
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data)
        
        # Build Subject String
        subject_parts = []
        for attr in cert.subject:
            subject_parts.append(f"{attr.oid._name}={attr.value}")
        subject_str = ", ".join(subject_parts)
        
        # Build Issuer String
        issuer_parts = []
        for attr in cert.issuer:
            issuer_parts.append(f"{attr.oid._name}={attr.value}")
        issuer_str = ", ".join(issuer_parts)
        
        # Compute Fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_formatted = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        return {
            "status": "active",
            "subject": subject_str,
            "issuer": issuer_str,
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "fingerprint": fingerprint_formatted,
            "file_path": cert_path
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse CA certificate: {str(e)}")


@router.get("/ca/download")
async def download_ca(
    request: Request,
    format: str = Query("pem", description="Format of the certificate to download (pem, der, p12)"),
    token: dict = Depends(require_admin) # Must be admin to download CA files, especially P12 with key
):
    """Download the Enterprise CyberNexus Root CA in various formats for client installation"""
    cert_path, key_path = get_cert_paths(request)
    
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="CA Certificate not found.")
        
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data)
        
        if format.lower() == "pem" or format.lower() == "crt":
            return Response(
                content=cert_data,
                media_type="application/x-x509-ca-cert",
                headers={"Content-Disposition": "attachment; filename=CyberNexus-root-ca.pem"}
            )
            
        elif format.lower() == "der" or format.lower() == "cer":
            der_data = cert.public_bytes(serialization.Encoding.DER)
            return Response(
                content=der_data,
                media_type="application/pkix-cert",
                headers={"Content-Disposition": "attachment; filename=CyberNexus-root-ca.der"}
            )
            
        elif format.lower() == "p12" or format.lower() == "pfx":
            if not os.path.exists(key_path):
                raise HTTPException(status_code=400, detail="Private key not found, cannot generate P12.")
                
            with open(key_path, "rb") as k:
                key_data = k.read()
                
            key = serialization.load_pem_private_key(key_data, password=None)
            
            p12_data = pkcs12.serialize_key_and_certificates(
                name=b"Enterprise CyberNexus Root CA",
                key=key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(b"CyberNexus-ca-password")
            )
            
            return Response(
                content=p12_data,
                media_type="application/x-pkcs12",
                headers={"Content-Disposition": "attachment; filename=CyberNexus-root-ca.p12"}
            )
            
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use pem, der, or p12.")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export certificate: {str(e)}")


@router.post("/ca/generate")
async def generate_ca(request: Request, token: dict = Depends(require_admin)):
    """Generate a brand new 4096-bit RSA Root CA on-the-fly and overwrite the old one."""
    cert_path, key_path = get_cert_paths(request)
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    
    try:
        # Generate Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        # Generate Subject and Issuer (Self-Signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Enterprise CyberNexus"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Security Appliances"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Enterprise CyberNexus Root CA"),
        ])
        
        # Build Certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650) # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(private_key, hashes.SHA256())
        
        # Write Key
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Write Cert
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        # Set restricted permissions on key if possible
        try:
            os.chmod(key_path, 0o600)
        except:
            pass
            
        return {"status": "success", "message": "New Root CA generated successfully. Requires service restart to take effect."}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate Root CA: {str(e)}")
