"""X.509 certificate handling for MicroPKI."""
import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from micropki import crypto_utils


def parse_dn(dn_string: str) -> list:
    """
    Parse Distinguished Name from various formats.
    
    Args:
        dn_string: Distinguished Name string
        
    Returns:
        List of (oid, value) tuples
        
    Raises:
        ValueError: If DN string is empty or invalid
    """
    if not dn_string or not dn_string.strip():
        raise ValueError("DN string cannot be empty")
    
    # Remove leading/trailing whitespace
    dn_string = dn_string.strip()
    
    # Dictionary to store RDNs
    rdns = {}
    
    # Handle slash notation (/CN=Test/O=Org)
    if dn_string.startswith('/'):
        # Remove leading slash and split
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                rdns[key.strip()] = value.strip()
    else:
        # Handle comma notation (CN=Test,O=Org)
        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                rdns[key.strip()] = value.strip()
    
    if not rdns:
        raise ValueError(f"Invalid DN format: {dn_string}")
    
    # Map to OIDs
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'E': NameOID.EMAIL_ADDRESS,
    }
    
    # Convert to list of (oid, value)
    result = []
    for key, value in rdns.items():
        if key in oid_map:
            result.append((oid_map[key], value))
    
    if not result:
        raise ValueError("No valid DN attributes found")
    
    return result


def create_self_signed_certificate(
    private_key: PrivateKeyTypes,
    subject_dn: str,
    validity_days: int,
    serial_number: Optional[int] = None
) -> x509.Certificate:
    """
    Create a self-signed X.509 v3 certificate.
    
    Args:
        private_key: Private key for signing
        subject_dn: Distinguished Name string
        validity_days: Validity period in days
        serial_number: Optional serial number (generated if not provided)
        
    Returns:
        Self-signed certificate
    """
    # Parse DN
    rdns = parse_dn(subject_dn)
    
    # Build subject/issuer name
    name_attributes = [x509.NameAttribute(oid, value) for oid, value in rdns]
    name = x509.Name(name_attributes)
    
    # Generate serial number if not provided
    if serial_number is None:
        serial_number = crypto_utils.generate_serial_number()
    
    # Set validity (UTC time)
    not_before = datetime.datetime.now(datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=validity_days)
    
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)  # Self-signed
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(private_key.public_key())
    
    # Add extensions
    
    # Basic Constraints: CA=TRUE (critical)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    
    # Key Usage: keyCertSign, cRLSign (critical)
    builder = builder.add_extension(
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
    )
    
    # Subject Key Identifier
    ski = crypto_utils.compute_ski(private_key.public_key())
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski),
        critical=False
    )
    
    # Authority Key Identifier (same as SKI for self-signed)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier(ski)
        ),
        critical=False
    )
    
    # Determine signature algorithm based on key type
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature_algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")
    
    # Sign certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )
    
    return certificate


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    """
    Convert certificate to PEM format.
    
    Args:
        certificate: X.509 certificate
        
    Returns:
        PEM-encoded certificate
    """
    return certificate.public_bytes(encoding=serialization.Encoding.PEM)


def verify_certificate(certificate: x509.Certificate) -> bool:
    """
    Verify a self-signed certificate.
    
    Args:
        certificate: Certificate to verify
        
    Returns:
        True if verification succeeds
    """
    try:
        # Get the public key from the certificate
        public_key = certificate.public_key()
        
        # Get the signature
        signature = certificate.signature
        
        # Get the TBS (To Be Signed) certificate bytes
        tbs_certificate_bytes = certificate.tbs_certificate_bytes
        
        # Verify based on key type
        if isinstance(public_key, rsa.RSAPublicKey):
            # For RSA, we need to know the padding and hash algorithm
            # The hash algorithm is determined by the certificate's signature algorithm
            hash_algorithm = certificate.signature_hash_algorithm
            
            # Проверяем подпись
            public_key.verify(
                signature,
                tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algorithm
            )
            return True
            
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # For ECDSA
            public_key.verify(
                signature,
                tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm)
            )
            return True
        else:
            print(f"Unsupported public key type: {type(public_key)}")
            return False
            
    except Exception as e:
        print(f"Verification error details: {e}")
        return False


def load_certificate(pem_data: bytes) -> x509.Certificate:
    """
    Load certificate from PEM data.
    
    Args:
        pem_data: PEM-encoded certificate
        
    Returns:
        Loaded certificate
    """
    return x509.load_pem_x509_certificate(pem_data, backend=default_backend())