"""Tests for revocation and CRL functionality."""
import os
import tempfile
import pytest

from micropki.ca import CertificateAuthority
from micropki.database import CertificateDatabase
from micropki.revocation import get_reason_code, RevocationReason


class TestRevocation:
    
    @pytest.fixture
    def temp_dir(self):
        import time
        import shutil
        tmpdir = tempfile.mkdtemp()
        yield tmpdir
        time.sleep(0.1)  # Даем время закрыть файлы
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except PermissionError:
            pass  # Игнорируем ошибки на Windows
    
    def test_reason_code_mapping(self):
        """Test revocation reason code mapping."""
        assert get_reason_code('keyCompromise') == RevocationReason.KEY_COMPROMISE.value
        assert get_reason_code('unspecified') == RevocationReason.UNSPECIFIED.value
        assert get_reason_code('cACompromise') == RevocationReason.CA_COMPROMISE.value
        assert get_reason_code('superseded') == RevocationReason.SUPERSEDED.value
        assert get_reason_code('cessationOfOperation') == RevocationReason.CESSATION_OF_OPERATION.value
    
    def test_revoke_certificate_direct(self, temp_dir):
        """Test certificate revocation directly via database."""
        db_path = os.path.join(temp_dir, 'test.db')
        db = CertificateDatabase(db_path)
        db.init_schema()
        
        # Insert a test certificate (serial as integer)
        serial_int = 0x123456789  # Правильный hex литерал
        serial_hex = hex(serial_int)[2:].upper()
        
        cert_data = {
            'serial_hex': serial_hex,
            'serial_int': str(serial_int),
            'subject': 'CN=test.example.com',
            'issuer': 'CN=Test CA',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)
        
        # Revoke certificate
        result = db.revoke_certificate(serial_hex, 'keyCompromise')
        assert result is True
        
        # Verify status changed
        cert = db.get_certificate_by_serial(serial_hex)
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keyCompromise'
    
    def test_revoke_already_revoked(self, temp_dir):
        """Test revoking already revoked certificate."""
        db_path = os.path.join(temp_dir, 'test.db')
        db = CertificateDatabase(db_path)
        db.init_schema()
        
        # Insert a test certificate
        serial_int = 0x987654321
        serial_hex = hex(serial_int)[2:].upper()
        
        cert_data = {
            'serial_hex': serial_hex,
            'serial_int': str(serial_int),
            'subject': 'CN=test2.example.com',
            'issuer': 'CN=Test CA',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST2\n-----END CERTIFICATE-----',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)
        
        # First revocation
        result1 = db.revoke_certificate(serial_hex, 'keyCompromise')
        assert result1 is True
        
        # Second revocation (should return False because already revoked)
        result2 = db.revoke_certificate(serial_hex, 'superseded')
        assert result2 is False
        
        # Verify status is still revoked with original reason
        cert = db.get_certificate_by_serial(serial_hex)
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keyCompromise'
    
    def test_revoke_nonexistent_certificate(self, temp_dir):
        """Test revoking non-existent certificate."""
        db_path = os.path.join(temp_dir, 'test.db')
        db = CertificateDatabase(db_path)
        db.init_schema()
        
        # Try to revoke non-existent certificate
        result = db.revoke_certificate('NONEXISTENT', 'keyCompromise')
        assert result is False