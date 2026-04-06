"""Tests for unique serial number generator."""
import os
import tempfile
import pytest

from micropki.serial import SerialGenerator


class TestSerialGenerator:
    
    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        # Закрываем все соединения перед удалением
        try:
            conn = sqlite3.connect(db_path)
            conn.close()
        except:
            pass
        try:
            os.unlink(db_path)
        except PermissionError:
            pass
    
    def test_generate_unique_serial(self, temp_db):
        gen = SerialGenerator(temp_db)
        
        serial_int, serial_hex = gen.generate_serial()
        
        assert isinstance(serial_int, int)
        assert serial_int > 0
        assert isinstance(serial_hex, str)
        assert len(serial_hex) >= 8
    
    def test_serial_uniqueness(self, temp_db):
        gen = SerialGenerator(temp_db)
        
        serials = set()
        for _ in range(10):
            serial_int, serial_hex = gen.generate_serial()
            assert serial_int not in serials
            serials.add(serial_int)
    
    def test_serial_exists_check(self, temp_db):
        gen = SerialGenerator(temp_db)
        
        serial_int, serial_hex = gen.generate_serial()
        
        assert gen.check_serial_exists(serial_int) is True
        assert gen.check_serial_exists(serial_int + 1) is False