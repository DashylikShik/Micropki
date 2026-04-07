"""CRL (Certificate Revocation List) handling for MicroPKI."""
import os
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_crl(crl_path: str) -> x509.CertificateRevocationList:
    """
    Load CRL from PEM file.
    
    Args:
        crl_path: Path to CRL file
        
    Returns:
        CRL object
    """
    with open(crl_path, 'rb') as f:
        crl_pem = f.read()
    return x509.load_pem_x509_crl(crl_pem, default_backend())


def crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    """Convert CRL to PEM format."""
    return crl.public_bytes(serialization.Encoding.PEM)


def verify_crl_signature(crl: x509.CertificateRevocationList, ca_cert: x509.Certificate) -> bool:
    """
    Verify CRL signature using CA certificate.
    
    Args:
        crl: CRL to verify
        ca_cert: CA certificate that signed the CRL
        
    Returns:
        True if signature is valid
    """
    try:
        public_key = ca_cert.public_key()
        public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            crl.signature_hash_algorithm
        )
        return True
    except Exception:
        return False


def get_revoked_serials(crl: x509.CertificateRevocationList) -> List[int]:
    """Get list of revoked serial numbers from CRL."""
    return [cert.serial_number for cert in crl]


def is_revoked(crl: x509.CertificateRevocationList, serial_hex: str) -> bool:
    """Check if certificate is revoked according to CRL."""
    serial_int = int(serial_hex, 16)
    for cert in crl:
        if cert.serial_number == serial_int:
            return True
    return False


def get_crl_info(crl: x509.CertificateRevocationList) -> dict:
    """
    Get human-readable information about CRL.
    
    Args:
        crl: CRL object
        
    Returns:
        Dictionary with CRL information
    """
    info = {
        'issuer': crl.issuer.rfc4514_string(),
        'last_update': crl.last_update.isoformat(),
        'next_update': crl.next_update.isoformat(),
        'revoked_count': len(crl),
        'revoked_certificates': []
    }
    
    # Get CRL number if present
    try:
        crl_number_ext = crl.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_NUMBER
        )
        info['crl_number'] = crl_number_ext.value.crl_number
    except x509.ExtensionNotFound:
        info['crl_number'] = None
    
    # Get revoked certificates info
    for cert in crl:
        cert_info = {
            'serial': hex(cert.serial_number)[2:].upper(),
            'revocation_date': cert.revocation_date.isoformat()
        }
        
        # Get reason code if present
        try:
            reason_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_REASON
            )
            cert_info['reason'] = reason_ext.value._name
        except x509.ExtensionNotFound:
            cert_info['reason'] = 'unspecified'
        
        info['revoked_certificates'].append(cert_info)
    
    return info