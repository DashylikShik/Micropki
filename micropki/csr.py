"""CSR (Certificate Signing Request) handling for MicroPKI."""
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend

from micropki import certificates


def generate_csr(
    private_key: PrivateKeyTypes,
    subject_dn: str,
    extensions: Optional[List[x509.Extension]] = None
) -> x509.CertificateSigningRequest:
    """
    Generate PKCS#10 Certificate Signing Request.
    
    Args:
        private_key: Private key for the CSR
        subject_dn: Distinguished Name string
        extensions: Optional list of extensions to include
        
    Returns:
        CertificateSigningRequest object
    """
    # Parse DN
    rdns = certificates.parse_dn(subject_dn)
    
    # Build subject name
    name_attributes = [x509.NameAttribute(oid, value) for oid, value in rdns]
    name = x509.Name(name_attributes)
    
    # Build CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(name)
    
    # Add extensions if provided
    if extensions:
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
    
    # Determine signature algorithm
    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384()
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")
    
    # Sign CSR
    csr = builder.sign(private_key, algorithm, default_backend())
    
    return csr


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """Convert CSR to PEM format."""
    return csr.public_bytes(encoding=serialization.Encoding.PEM)


def load_csr(pem_data: bytes) -> x509.CertificateSigningRequest:
    """Load CSR from PEM data."""
    return x509.load_pem_x509_csr(pem_data, default_backend())


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """Verify CSR signature."""
    try:
        public_key = csr.public_key()
        public_key.verify(
            csr.signature,
            csr.tbs_certificate_request_bytes,
            csr.signature_hash_algorithm
        )
        return True
    except Exception:
        return False


def create_intermediate_ca_extensions(pathlen: int = 0) -> List[x509.Extension]:
    """
    Create extensions for Intermediate CA CSR.
    
    Args:
        pathlen: Path length constraint for CA (default 0)
        
    Returns:
        List of extensions to include in CSR
    """
    extensions = []
    
    # Basic Constraints: CA=TRUE with pathlen
    basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
    extensions.append(
        x509.Extension(
            oid=ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=basic_constraints
        )
    )
    
    # Key Usage: keyCertSign, cRLSign
    key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )
    extensions.append(
        x509.Extension(
            oid=ExtensionOID.KEY_USAGE,
            critical=True,
            value=key_usage
        )
    )
    
    return extensions