"""Certificate chain validation for MicroPKI."""
from typing import List, Optional, Tuple
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import ExtensionOID


def validate_certificate_chain(
    leaf_cert: x509.Certificate,
    intermediate_cert: Optional[x509.Certificate],
    root_cert: x509.Certificate
) -> Tuple[bool, List[str]]:
    """
    Validate certificate chain: leaf -> intermediate -> root.
    
    Args:
        leaf_cert: End-entity certificate
        intermediate_cert: Intermediate CA certificate (or None)
        root_cert: Root CA certificate
        
    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors = []
    now = datetime.now(timezone.utc)
    
    # Check leaf validity
    if leaf_cert.not_valid_before_utc > now:
        errors.append(f"Leaf certificate not yet valid (valid from {leaf_cert.not_valid_before_utc})")
    if leaf_cert.not_valid_after_utc < now:
        errors.append(f"Leaf certificate expired (valid until {leaf_cert.not_valid_after_utc})")
    
    # Validate leaf signature
    try:
        if intermediate_cert:
            issuer = intermediate_cert
        else:
            issuer = root_cert
        
        public_key = issuer.public_key()
        signature = leaf_cert.signature
        tbs_bytes = leaf_cert.tbs_certificate_bytes
        
        # Получаем хэш-алгоритм из сертификата
        hash_algorithm = leaf_cert.signature_hash_algorithm
        
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PKCS1v15(),
                hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                tbs_bytes,
                ec.ECDSA(hash_algorithm)
            )
        else:
            errors.append(f"Unsupported public key type: {type(public_key)}")
    except Exception as e:
        errors.append(f"Leaf certificate signature verification failed: {e}")
    
    # Validate intermediate if present
    if intermediate_cert:
        # Check intermediate validity
        if intermediate_cert.not_valid_before_utc > now:
            errors.append("Intermediate certificate not yet valid")
        if intermediate_cert.not_valid_after_utc < now:
            errors.append("Intermediate certificate expired")
        
        # Check intermediate is CA
        try:
            basic_constraints = intermediate_cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            if not basic_constraints.value.ca:
                errors.append("Intermediate certificate missing CA=TRUE constraint")
        except x509.ExtensionNotFound:
            errors.append("Intermediate certificate missing BasicConstraints extension")
        
        # Validate intermediate signature
        try:
            public_key = root_cert.public_key()
            signature = intermediate_cert.signature
            tbs_bytes = intermediate_cert.tbs_certificate_bytes
            hash_algorithm = intermediate_cert.signature_hash_algorithm
            
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    tbs_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    tbs_bytes,
                    ec.ECDSA(hash_algorithm)
                )
        except Exception as e:
            errors.append(f"Intermediate certificate signature verification failed: {e}")
    
    # Validate root is CA
    try:
        basic_constraints = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        if not basic_constraints.value.ca:
            errors.append("Root certificate missing CA=TRUE constraint")
    except x509.ExtensionNotFound:
        errors.append("Root certificate missing BasicConstraints extension")
    
    return (len(errors) == 0, errors)