"""Tests for MicroPKI Sprint 2 functionality."""
import os
import tempfile
import pytest

from micropki.ca import CertificateAuthority
from micropki import csr, san, templates, chain


class TestSprint2:
    """Test Sprint 2 functionality."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def root_ca(self, temp_dir):
        """Create a Root CA for testing."""
        ca = CertificateAuthority()
        pass_file = os.path.join(temp_dir, 'root.pass')
        with open(pass_file, 'w') as f:
            f.write('root-password')
        
        out_dir = os.path.join(temp_dir, 'root')
        ca.init_root_ca(
            subject="CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=pass_file,
            out_dir=out_dir,
            validity_days=365
        )
        
        return {
            'ca': ca,
            'cert': os.path.join(out_dir, 'certs', 'ca.cert.pem'),
            'key': os.path.join(out_dir, 'private', 'ca.key.pem'),
            'pass': pass_file,
            'out_dir': out_dir
        }
    
    def test_parse_san_dns(self):
        """Test parsing DNS SAN."""
        san_type, value = san.parse_san_string("dns:example.com")
        assert san_type == san.SANType.DNS
        assert value == "example.com"
    
    def test_parse_san_ip(self):
        """Test parsing IP SAN."""
        san_type, value = san.parse_san_string("ip:192.168.1.1")
        assert san_type == san.SANType.IP
        assert value == "192.168.1.1"
    
    def test_parse_san_email(self):
        """Test parsing email SAN."""
        san_type, value = san.parse_san_string("email:user@example.com")
        assert san_type == san.SANType.EMAIL
        assert value == "user@example.com"
    
    def test_parse_san_invalid(self):
        """Test invalid SAN format."""
        with pytest.raises(san.SANParseError):
            san.parse_san_string("invalid")
    
    def test_server_template_validation(self):
        """Test server template SAN validation."""
        template = templates.ServerTemplate()
        
        valid, error = template.validate_san([
            (san.SANType.DNS, "example.com"),
            (san.SANType.IP, "192.168.1.1")
        ])
        assert valid is True
        
        valid, error = template.validate_san([
            (san.SANType.EMAIL, "user@example.com")
        ])
        assert valid is False
    
    def test_intermediate_ca_issuance(self, root_ca, temp_dir):
        """Test Intermediate CA issuance."""
        ca = CertificateAuthority()
        
        intermediate_pass = os.path.join(temp_dir, 'intermediate.pass')
        with open(intermediate_pass, 'w') as f:
            f.write('intermediate-password')
        
        out_dir = os.path.join(temp_dir, 'intermediate')
        
        ca.issue_intermediate_ca(
            root_cert_path=root_ca['cert'],
            root_key_path=root_ca['key'],
            root_passphrase_file=root_ca['pass'],
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase_file=intermediate_pass,
            out_dir=out_dir,
            validity_days=365,
            pathlen=0
        )
        
        # Check files were created
        assert os.path.exists(os.path.join(out_dir, 'private', 'intermediate.key.pem'))
        assert os.path.exists(os.path.join(out_dir, 'certs', 'intermediate.cert.pem'))
        assert os.path.exists(os.path.join(out_dir, 'csrs', 'intermediate.csr.pem'))
    
    def test_server_certificate_issuance(self, root_ca, temp_dir):
        """Test server certificate issuance."""
        ca = CertificateAuthority()
        
        # Create Intermediate CA first
        intermediate_pass = os.path.join(temp_dir, 'intermediate.pass')
        with open(intermediate_pass, 'w') as f:
            f.write('intermediate-password')
        
        inter_out = os.path.join(temp_dir, 'intermediate')
        ca.issue_intermediate_ca(
            root_cert_path=root_ca['cert'],
            root_key_path=root_ca['key'],
            root_passphrase_file=root_ca['pass'],
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase_file=intermediate_pass,
            out_dir=inter_out,
            validity_days=365,
            pathlen=0
        )
        
        # Issue server certificate
        cert_out = os.path.join(temp_dir, 'certs')
        ca.issue_certificate(
            ca_cert_path=os.path.join(inter_out, 'certs', 'intermediate.cert.pem'),
            ca_key_path=os.path.join(inter_out, 'private', 'intermediate.key.pem'),
            ca_passphrase_file=intermediate_pass,
            template_name="server",
            subject="CN=test.example.com",
            san_list=["dns:test.example.com", "dns:www.example.com"],
            out_dir=cert_out,
            validity_days=365
        )
        
        # Check certificate was created
        certs = [f for f in os.listdir(cert_out) if f.endswith('.cert.pem')]
        assert len(certs) >= 1
    
    def test_chain_validation(self, root_ca, temp_dir):
        """Test certificate chain validation."""
        ca = CertificateAuthority()
        
        # Create Intermediate CA
        intermediate_pass = os.path.join(temp_dir, 'intermediate.pass')
        with open(intermediate_pass, 'w') as f:
            f.write('intermediate-password')
        
        inter_out = os.path.join(temp_dir, 'intermediate')
        ca.issue_intermediate_ca(
            root_cert_path=root_ca['cert'],
            root_key_path=root_ca['key'],
            root_passphrase_file=root_ca['pass'],
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase_file=intermediate_pass,
            out_dir=inter_out,
            validity_days=365,
            pathlen=0
        )
        
        # Issue leaf certificate
        cert_out = os.path.join(temp_dir, 'certs')
        ca.issue_certificate(
            ca_cert_path=os.path.join(inter_out, 'certs', 'intermediate.cert.pem'),
            ca_key_path=os.path.join(inter_out, 'private', 'intermediate.key.pem'),
            ca_passphrase_file=intermediate_pass,
            template_name="server",
            subject="CN=leaf.example.com",
            san_list=["dns:leaf.example.com"],
            out_dir=cert_out,
            validity_days=365
        )
        
        # Find leaf certificate
        leaf_files = [f for f in os.listdir(cert_out) if f.endswith('.cert.pem')]
        leaf_path = os.path.join(cert_out, leaf_files[0])
        
        # Verify chain
        is_valid, errors = ca.verify_chain(
            leaf_path=leaf_path,
            intermediate_path=os.path.join(inter_out, 'certs', 'intermediate.cert.pem'),
            root_path=root_ca['cert']
        )
        
        assert is_valid is True, f"Chain validation failed: {errors}"