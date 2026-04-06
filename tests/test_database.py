"""Tests for database functionality."""
import os
import tempfile
import pytest

from micropki.database import CertificateDatabase


class TestDatabase:
    
    @pytest.fixture
    def temp_db(self):
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        # Закрываем все соединения перед удалением
        try:
            # Принудительно закрываем соединения
            sqlite3.connect(db_path).close()
        except:
            pass
        try:
            os.unlink(db_path)
        except PermissionError:
            # Игнорируем ошибки на Windows
            pass
    
    def test_init_schema(self, temp_db):
        db = CertificateDatabase(temp_db)
        db.init_schema()
        
        # Check that table exists
        import sqlite3
        conn = sqlite3.connect(temp_db)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
        assert cursor.fetchone() is not None
        conn.close()
    
    def test_insert_and_retrieve(self, temp_db):
        db = CertificateDatabase(temp_db)
        db.init_schema()
        
        cert_data = {
            'serial_hex': '123ABC',
            'serial_int': 0x123ABC,
            'subject': 'CN=Test',
            'issuer': 'CN=Root',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
            'status': 'valid'
        }
        
        row_id = db.insert_certificate(cert_data)
        assert row_id > 0
        
        retrieved = db.get_certificate_by_serial('123ABC')
        assert retrieved is not None
        assert retrieved['subject'] == 'CN=Test'
        assert retrieved['serial_hex'] == '123ABC'
    
    def test_list_certificates(self, temp_db):
        db = CertificateDatabase(temp_db)
        db.init_schema()
        
        # Insert test data
        for i in range(3):
            cert_data = {
                'serial_hex': f'SERIAL{i:03X}',
                'serial_int': i,
                'subject': f'CN=Test{i}',
                'issuer': 'CN=Root',
                'not_before': '2024-01-01T00:00:00',
                'not_after': '2025-01-01T00:00:00',
                'cert_pem': 'TEST',
                'status': 'valid' if i < 2 else 'expired'
            }
            db.insert_certificate(cert_data)
        
        # List all
        all_certs = db.list_certificates()
        assert len(all_certs) == 3
        
        # Filter by status
        valid_certs = db.list_certificates(status='valid')
        assert len(valid_certs) == 2
        
        expired_certs = db.list_certificates(status='expired')
        assert len(expired_certs) == 1
    
    def test_update_status(self, temp_db):
        db = CertificateDatabase(temp_db)
        db.init_schema()
        
        cert_data = {
            'serial_hex': 'TEST001',
            'serial_int': 1,
            'subject': 'CN=Test',
            'issuer': 'CN=Root',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': 'TEST',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)
        
        # Update status
        result = db.update_certificate_status('TEST001', 'revoked', 'Compromised')
        assert result is True
        
        # Verify update
        cert = db.get_certificate_by_serial('TEST001')
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'Compromised'