"""Tests for crypto utilities."""
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from micropki import crypto_utils


class TestCryptoUtils:
    """Test crypto utility functions."""
    
    def test_generate_rsa_key(self):
        """Test RSA key generation."""
        key = crypto_utils.generate_rsa_key(4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096
    
    def test_generate_rsa_key_wrong_size(self):
        """Test RSA key generation with wrong size."""
        with pytest.raises(ValueError, match="RSA key size must be 4096 bits"):
            crypto_utils.generate_rsa_key(2048)
    
    def test_generate_ecc_key(self):
        """Test ECC key generation."""
        key = crypto_utils.generate_ecc_key(384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == 'secp384r1'
    
    def test_generate_ecc_key_wrong_size(self):
        """Test ECC key generation with wrong size."""
        with pytest.raises(ValueError, match="ECC key size must be 384 bits"):
            crypto_utils.generate_ecc_key(256)
    
    def test_encrypt_private_key(self):
        """Test private key encryption."""
        key = crypto_utils.generate_rsa_key(4096)
        passphrase = b'test-passphrase'
        
        encrypted = crypto_utils.encrypt_private_key(key, passphrase)
        assert encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
    
    def test_generate_serial_number(self):
        """Test serial number generation."""
        serial1 = crypto_utils.generate_serial_number()
        serial2 = crypto_utils.generate_serial_number()
        
        assert isinstance(serial1, int)
        assert serial1 > 0
        assert serial1 != serial2
        assert serial1.bit_length() >= 20
    
    def test_compute_ski(self):
        """Test SKI computation."""
        key = crypto_utils.generate_rsa_key(4096)
        ski = crypto_utils.compute_ski(key.public_key())
        
        assert isinstance(ski, bytes)
        assert len(ski) == 20  # SHA-1 is 20 bytes