"""Negative test scenarios for MicroPKI."""
import os
import tempfile
import pytest
import subprocess
import sys


class TestNegativeScenarios:
    """Test negative scenarios (error cases)."""
    
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
    
    def test_missing_subject(self, passphrase_file, temp_dir):
        """Test: Missing --subject argument."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        # Run without --subject
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about missing subject
        assert 'required' in result.stderr.lower() or 'subject' in result.stderr.lower()
    
    def test_invalid_dn_syntax(self, passphrase_file, temp_dir):
        """Test: Invalid DN syntax (empty subject)."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        # Try empty subject
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', '',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
    
    def test_wrong_key_size_rsa(self, passphrase_file, temp_dir):
        """Test: RSA with wrong key size (2048 instead of 4096)."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'rsa',
             '--key-size', '2048',  # Wrong size for RSA
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about key size
        assert '4096' in result.stderr.lower() or 'size' in result.stderr.lower()
    
    def test_wrong_key_size_ecc(self, passphrase_file, temp_dir):
        """Test: ECC with wrong key size (256 instead of 384)."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'ecc',
             '--key-size', '256',  # Wrong size for ECC
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about key size
        assert '384' in result.stderr.lower() or 'size' in result.stderr.lower()
    
    def test_nonexistent_passphrase_file(self, temp_dir):
        """Test: Non-existent passphrase file."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', 'non_existent_file_12345.txt',
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about file not found
        assert 'not found' in result.stderr.lower() or 'exist' in result.stderr.lower()
    
    def test_negative_validity_days(self, passphrase_file, temp_dir):
        """Test: Negative validity days."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir,
             '--validity-days', '-100'],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about positive integer
        assert 'positive' in result.stderr.lower() or 'validity' in result.stderr.lower()
    
    def test_zero_validity_days(self, passphrase_file, temp_dir):
        """Test: Zero validity days."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir,
             '--validity-days', '0'],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
        # Should have error about positive integer
        assert 'positive' in result.stderr.lower()
    
    def test_invalid_key_type(self, passphrase_file, temp_dir):
        """Test: Invalid key type."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'invalid_type',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail
        assert result.returncode != 0
    
    def test_missing_passphrase_file_argument(self, temp_dir):
        """Test: Missing --passphrase-file argument."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        result = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Test',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--out-dir', out_dir],
            capture_output=True,
            text=True
        )
        # Should fail because passphrase-file is required
        assert result.returncode != 0
        assert 'required' in result.stderr.lower()
    
    def test_force_flag_overwrites(self, passphrase_file, temp_dir):
        """Test: --force flag allows overwriting without confirmation."""
        out_dir = os.path.join(temp_dir, 'pki')
        
        # First initialization
        result1 = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=First CA',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir,
             '--force'],
            capture_output=True,
            text=True
        )
        assert result1.returncode == 0
        
        # Second initialization with --force (should overwrite without asking)
        result2 = subprocess.run(
            [sys.executable, '-m', 'micropki.cli', 'ca', 'init',
             '--subject', 'CN=Second CA',
             '--key-type', 'rsa',
             '--key-size', '4096',
             '--passphrase-file', passphrase_file,
             '--out-dir', out_dir,
             '--force'],
            capture_output=True,
            text=True
        )
        assert result2.returncode == 0
        
        # Check that files exist
        assert os.path.exists(os.path.join(out_dir, 'certs', 'ca.cert.pem'))
        assert os.path.exists(os.path.join(out_dir, 'private', 'ca.key.pem'))