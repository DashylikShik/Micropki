"""Tests for Sprint 7 - Compromise Simulation."""
import os
import tempfile
import pytest

from micropki.ca import CertificateAuthority
from micropki.database import CertificateDatabase
from micropki.audit import init_audit_logger, audit_log


class TestCompromiseSimulation:
    """Test compromise simulation."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def setup_ca(self, temp_dir):
        """Setup Root and Intermediate CA for testing."""
        # Инициализируем БД
        db_path = os.path.join(temp_dir, 'micropki.db')
        db = CertificateDatabase(db_path)
        db.init_schema()
        
        ca = CertificateAuthority(db_path=db_path)
        
        # Root CA
        root_pass = os.path.join(temp_dir, 'root.pass')
        with open(root_pass, 'w') as f:
            f.write('root-password')
        
        root_out = os.path.join(temp_dir, 'root')
        ca.init_root_ca(
            subject="CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=root_pass,
            out_dir=root_out,
            validity_days=365
        )
        
        # Intermediate CA
        inter_pass = os.path.join(temp_dir, 'intermediate.pass')
        with open(inter_pass, 'w') as f:
            f.write('intermediate-password')
        
        inter_out = os.path.join(temp_dir, 'intermediate')
        ca.issue_intermediate_ca(
            root_cert_path=os.path.join(root_out, 'certs', 'ca.cert.pem'),
            root_key_path=os.path.join(root_out, 'private', 'ca.key.pem'),
            root_passphrase_file=root_pass,
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase_file=inter_pass,
            out_dir=inter_out,
            validity_days=365,
            pathlen=0
        )
        
        return {
            'root_out': root_out,
            'inter_out': inter_out,
            'root_pass': root_pass,
            'inter_pass': inter_pass,
            'db_path': db_path
        }
    
    def test_revoke_with_audit(self, setup_ca, temp_dir):
        """Test revocation with audit logging."""
        db_path = setup_ca['db_path']
        ca = CertificateAuthority(db_path=db_path)
        
        # Issue a certificate
        cert_out = os.path.join(temp_dir, 'certs')
        os.makedirs(cert_out, exist_ok=True)
        
        ca.issue_certificate(
            ca_cert_path=os.path.join(setup_ca['inter_out'], 'certs', 'intermediate.cert.pem'),
            ca_key_path=os.path.join(setup_ca['inter_out'], 'private', 'intermediate.key.pem'),
            ca_passphrase_file=setup_ca['inter_pass'],
            template_name="server",
            subject="CN=test.example.com",
            san_list=["dns:test.example.com"],
            out_dir=cert_out,
            validity_days=365
        )
        
        # Get certificate serial
        db = CertificateDatabase(db_path)
        certs = db.list_certificates()
        assert len(certs) >= 1
        serial = certs[0]['serial_hex']
        
        # Initialize audit
        init_audit_logger(temp_dir)
        
        # Revoke with audit
        result = db.revoke_certificate(serial, 'keyCompromise')
        assert result is True
        
        # Verify status changed
        cert = db.get_certificate_by_serial(serial)
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keyCompromise'
    
    def test_compromise_workflow(self, setup_ca, temp_dir):
        """Test compromise workflow."""
        db_path = setup_ca['db_path']
        ca = CertificateAuthority(db_path=db_path)
        
        # Issue a certificate
        cert_out = os.path.join(temp_dir, 'certs')
        os.makedirs(cert_out, exist_ok=True)
        
        ca.issue_certificate(
            ca_cert_path=os.path.join(setup_ca['inter_out'], 'certs', 'intermediate.cert.pem'),
            ca_key_path=os.path.join(setup_ca['inter_out'], 'private', 'intermediate.key.pem'),
            ca_passphrase_file=setup_ca['inter_pass'],
            template_name="server",
            subject="CN=test.example.com",
            san_list=["dns:test.example.com"],
            out_dir=cert_out,
            validity_days=365
        )
        
        # Get certificate
        db = CertificateDatabase(db_path)
        certs = db.list_certificates()
        assert len(certs) >= 1
        serial = certs[0]['serial_hex']
        
        # Simulate compromise
        result = db.revoke_certificate(serial, 'keyCompromise')
        assert result is True
        
        # Verify status
        cert = db.get_certificate_by_serial(serial)
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keyCompromise'