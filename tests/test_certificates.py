"""Tests for certificate handling."""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

from micropki import crypto_utils, certificates


class TestCertificates:
    """Test certificate functions."""
    
    @pytest.fixture
    def rsa_key(self):
        """Fixture for RSA key."""
        return crypto_utils.generate_rsa_key(4096)
    
    def test_parse_dn_slash(self):
        """Test DN parsing with slash notation."""
        rdns = certificates.parse_dn("/CN=Test/O=MicroPKI/C=US")
        assert len(rdns) == 3
        
        # Find CN
        cn_found = False
        for oid, value in rdns:
            if oid._name == 'commonName':
                assert value == 'Test'
                cn_found = True
        assert cn_found
    
    def test_parse_dn_comma(self):
        """Test DN parsing with comma notation."""
        rdns = certificates.parse_dn("CN=Test,O=MicroPKI,C=US")
        assert len(rdns) == 3
    
    def test_parse_dn_empty(self):
        """Test DN parsing with empty string."""
        with pytest.raises(ValueError, match="DN string cannot be empty"):
            certificates.parse_dn("")
    
    def test_create_self_signed_certificate(self, rsa_key):
        """Test self-signed certificate creation."""
        subject = "/CN=Test Root CA/O=MicroPKI"
        validity_days = 365
        
        cert = certificates.create_self_signed_certificate(
            private_key=rsa_key,
            subject_dn=subject,
            validity_days=validity_days
        )
        
        assert isinstance(cert, x509.Certificate)
        assert cert.subject == cert.issuer  # Self-signed
        
        # Check Basic Constraints
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.critical is True
        
        # Check Key Usage
        key_usage = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        assert key_usage.critical is True
        
        # Check SKI and AKI
        ski = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ski.value.digest == aki.value.key_identifier
    
    def test_verify_certificate(self, rsa_key):
        """Test certificate verification."""
        subject = "/CN=Test Root CA"
        cert = certificates.create_self_signed_certificate(
            private_key=rsa_key,
            subject_dn=subject,
            validity_days=365
        )
        
        assert certificates.verify_certificate(cert) is True
    
    def test_certificate_to_pem(self, rsa_key):
        """Test PEM conversion."""
        subject = "/CN=Test Root CA"
        cert = certificates.create_self_signed_certificate(
            private_key=rsa_key,
            subject_dn=subject,
            validity_days=365
        )
        
        pem_data = certificates.certificate_to_pem(cert)
        assert pem_data.startswith(b'-----BEGIN CERTIFICATE-----')
        
        # Load back
        loaded_cert = certificates.load_certificate(pem_data)
        assert loaded_cert.subject == cert.subject