"""Tests for CA operations."""
import os
import tempfile
import pytest

from micropki.ca import CertificateAuthority


class TestCA:
    """Test Certificate Authority."""
    
    @pytest.fixture
    def temp_dir(self):
        """Fixture for temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def passphrase_file(self, temp_dir):
        """Fixture for passphrase file."""
        pass_file = os.path.join(temp_dir, 'pass.txt')
        with open(pass_file, 'w') as f:
            f.write('test-passphrase-123')
        return pass_file
    
    def test_ca_init_rsa(self, temp_dir, passphrase_file):
        """Test CA initialization with RSA."""
        ca = CertificateAuthority()
        
        out_dir = os.path.join(temp_dir, 'pki')
        ca.init_root_ca(
            subject="/CN=Test CA/O=MicroPKI",
            key_type="rsa",
            key_size=4096,
            passphrase_file=passphrase_file,
            out_dir=out_dir,
            validity_days=365
        )
        
        # Check files were created
        assert os.path.exists(os.path.join(out_dir, 'private', 'ca.key.pem'))
        assert os.path.exists(os.path.join(out_dir, 'certs', 'ca.cert.pem'))
        assert os.path.exists(os.path.join(out_dir, 'policy.txt'))
    
    def test_ca_init_ecc(self, temp_dir, passphrase_file):
        """Test CA initialization with ECC."""
        ca = CertificateAuthority()
        
        out_dir = os.path.join(temp_dir, 'pki')
        ca.init_root_ca(
            subject="CN=Test ECC CA,O=MicroPKI",
            key_type="ecc",
            key_size=384,
            passphrase_file=passphrase_file,
            out_dir=out_dir,
            validity_days=365
        )
        
        # Check files were created
        assert os.path.exists(os.path.join(out_dir, 'private', 'ca.key.pem'))
        assert os.path.exists(os.path.join(out_dir, 'certs', 'ca.cert.pem'))
    
    def test_ca_verify(self, temp_dir, passphrase_file):
        """Test certificate verification."""
        ca = CertificateAuthority()
        
        out_dir = os.path.join(temp_dir, 'pki')
        ca.init_root_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=passphrase_file,
            out_dir=out_dir,
            validity_days=365
        )
        
        cert_path = os.path.join(out_dir, 'certs', 'ca.cert.pem')
        assert ca.verify(cert_path) is True
    
    def test_ca_verify_key_match(self, temp_dir, passphrase_file):
        """Test key-certificate matching."""
        ca = CertificateAuthority()
        
        out_dir = os.path.join(temp_dir, 'pki')
        ca.init_root_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=passphrase_file,
            out_dir=out_dir,
            validity_days=365
        )
        
        key_path = os.path.join(out_dir, 'private', 'ca.key.pem')
        cert_path = os.path.join(out_dir, 'certs', 'ca.cert.pem')
        
        with open(passphrase_file, 'rb') as f:
            passphrase = f.read().strip()
        
        assert ca.verify_key_match(key_path, passphrase, cert_path) is True