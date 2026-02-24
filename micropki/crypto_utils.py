"""Cryptographic utilities for MicroPKI."""
import os
from typing import Optional, Union

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.backends import default_backend


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate RSA private key.
    
    Args:
        key_size: Key size in bits (must be 4096 for this project)
        
    Returns:
        RSA private key
        
    Raises:
        ValueError: If key_size is not 4096
    """
    if key_size != 4096:
        raise ValueError(f"RSA key size must be 4096 bits, got {key_size}")
    
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key(key_size: int = 384) -> ec.EllipticCurvePrivateKey:
    """
    Generate ECC private key on P-384 curve.
    
    Args:
        key_size: Key size (must be 384 for P-384)
        
    Returns:
        ECC private key
        
    Raises:
        ValueError: If key_size is not 384
    """
    if key_size != 384:
        raise ValueError(f"ECC key size must be 384 bits (P-384 curve), got {key_size}")
    
    return ec.generate_private_key(
        ec.SECP384R1(),
        backend=default_backend()
    )


def encrypt_private_key(private_key: PrivateKeyTypes, passphrase: bytes) -> bytes:
    """
    Encrypt private key with passphrase using PKCS#8.
    
    Args:
        private_key: Private key to encrypt
        passphrase: Passphrase bytes
        
    Returns:
        PEM-encoded encrypted private key
    """
    # Use PKCS#8 with best available encryption (AES-256-CBC + PBKDF2)
    encryption = serialization.BestAvailableEncryption(passphrase)
    
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )


def generate_serial_number() -> int:
    """
    Generate cryptographically secure random serial number.
    
    Returns:
        Random positive integer with at least 20 bits of entropy
        but not exceeding 159 bits (to comply with cryptography library)
    """
    # Генерируем 19 байт (152 бита) - безопасно для библиотеки
    random_bytes = os.urandom(19)
    
    # Convert to integer and ensure positive
    serial = int.from_bytes(random_bytes, byteorder='big')
    
    # Убеждаемся, что серийный номер не равен 0
    if serial == 0:
        serial = 1
    
    return serial


def compute_ski(public_key: PublicKeyTypes) -> bytes:
    """
    Compute Subject Key Identifier as SHA-1 hash of public key.
    
    Args:
        public_key: Public key
        
    Returns:
        SKI bytes
    """
    # Get DER-encoded public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Compute SHA-1 hash
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    return digest.finalize()