"""Utility functions for MicroPKI."""
import os
import re
import stat
from typing import Tuple, Optional


def parse_dn(dn_string: str) -> dict:
    """
    Parse Distinguished Name from various formats.
    
    Supports:
    - Slash notation: /CN=Test/O=Org/C=US
    - Comma notation: CN=Test,O=Org,C=US
    - OpenSSL style: /CN=Test/O=Org
    
    Args:
        dn_string: Distinguished Name string
        
    Returns:
        Dictionary of RDNs
        
    Raises:
        ValueError: If DN string is empty or invalid
    """
    if not dn_string or not dn_string.strip():
        raise ValueError("DN string cannot be empty")
    
    result = {}
    
    # Remove leading/trailing whitespace
    dn_string = dn_string.strip()
    
    # Handle slash notation
    if dn_string.startswith('/'):
        # Remove leading slash and split
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
    else:
        # Handle comma notation
        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
    
    if not result:
        raise ValueError(f"Invalid DN format: {dn_string}")
    
    return result


def dn_to_rdn_sequence(dn_dict: dict) -> list:
    """
    Convert DN dictionary to list of tuples for x509.Name.
    
    Args:
        dn_dict: Dictionary of RDNs
        
    Returns:
        List of (oid, value) tuples
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'E': NameOID.EMAIL_ADDRESS,
    }
    
    result = []
    for key, value in dn_dict.items():
        if key in oid_map:
            result.append((oid_map[key], value))
    
    return result


def ensure_directory(path: str, mode: int = 0o755) -> None:
    """
    Ensure directory exists with proper permissions.
    
    Args:
        path: Directory path
        mode: Permission mode (Unix-like)
        
    Raises:
        OSError: If directory cannot be created or permissions cannot be set
    """
    if not os.path.exists(path):
        os.makedirs(path, mode=mode)
    elif not os.path.isdir(path):
        raise OSError(f"Path exists but is not a directory: {path}")


def set_file_permissions(path: str, mode: int) -> None:
    """
    Set file permissions on Unix-like systems.
    
    Args:
        path: File path
        mode: Permission mode
        
    Returns:
        True if permissions were set, False otherwise
    """
    try:
        os.chmod(path, mode)
    except (OSError, AttributeError):
        # Windows or permission error
        pass


def validate_passphrase_file(passphrase_file: str) -> bytes:
    """
    Validate and read passphrase from file.
    
    Args:
        passphrase_file: Path to passphrase file
        
    Returns:
        Passphrase as bytes with trailing newline stripped
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
        ValueError: If passphrase is empty
    """
    if not os.path.exists(passphrase_file):
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")
    
    if not os.access(passphrase_file, os.R_OK):
        raise PermissionError(f"Cannot read passphrase file: {passphrase_file}")
    
    with open(passphrase_file, 'rb') as f:
        passphrase = f.read()
    
    # Strip trailing newline if present
    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
    
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    return passphrase