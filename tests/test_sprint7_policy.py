"""Tests for Sprint 7 - Policy Enforcement."""
import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from micropki.policy import PolicyEnforcer, PolicyConfig, TemplateType
from micropki.san import SANType


class TestPolicyEnforcement:
    """Test policy enforcement system."""
    
    @pytest.fixture
    def policy(self):
        return PolicyEnforcer(PolicyConfig())
    
    def test_rsa_key_size_end_entity_valid(self, policy):
        """Test RSA 2048 for end-entity - should pass."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid, msg = policy.check_key_size(key, is_ca=False, is_root=False)
        assert valid is True
    
    def test_rsa_key_size_end_entity_invalid(self, policy):
        """Test RSA 1024 for end-entity - should fail."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        valid, msg = policy.check_key_size(key, is_ca=False, is_root=False)
        assert valid is False
        assert "below minimum" in msg or "2048" in msg
    
    def test_rsa_key_size_ca_valid(self, policy):
        """Test RSA 4096 for CA - should pass."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        valid, msg = policy.check_key_size(key, is_ca=True, is_root=False)
        assert valid is True
    
    def test_ecc_key_size_end_entity_valid(self, policy):
        """Test ECC P-256 for end-entity - should pass."""
        key = ec.generate_private_key(ec.SECP256R1())
        valid, msg = policy.check_key_size(key, is_ca=False, is_root=False)
        assert valid is True
    
    def test_ecc_key_size_ca_invalid(self, policy):
        """Test ECC P-256 for CA - should fail (requires P-384)."""
        key = ec.generate_private_key(ec.SECP256R1())
        valid, msg = policy.check_key_size(key, is_ca=True, is_root=False)
        assert valid is False
        assert "P-384" in msg
    
    def test_validity_period_end_entity_valid(self, policy):
        """Test validity 365 days for end-entity - should pass."""
        valid, msg = policy.check_validity_period(365, is_ca=False, is_root=False)
        assert valid is True
    
    def test_validity_period_end_entity_invalid(self, policy):
        """Test validity 400 days for end-entity - should fail."""
        valid, msg = policy.check_validity_period(400, is_ca=False, is_root=False)
        assert valid is False
        assert "exceeds" in msg
    
    def test_validity_period_root_valid(self, policy):
        """Test validity 3650 days for root - should pass."""
        valid, msg = policy.check_validity_period(3650, is_ca=True, is_root=True)
        assert valid is True
    
    def test_san_types_server_allowed(self, policy):
        """Test allowed SAN types for server template."""
        san_list = [(SANType.DNS, "example.com"), (SANType.IP, "192.168.1.1")]
        valid, msg = policy.check_san_types(san_list, TemplateType.SERVER)
        assert valid is True
    
    def test_san_types_server_forbidden(self, policy):
        """Test forbidden SAN types for server template."""
        san_list = [(SANType.EMAIL, "user@example.com")]
        valid, msg = policy.check_san_types(san_list, TemplateType.SERVER)
        assert valid is False
        assert "email" in msg
    
    def test_san_types_client_allowed(self, policy):
        """Test allowed SAN types for client template."""
        san_list = [(SANType.EMAIL, "user@example.com"), (SANType.DNS, "client.example.com")]
        valid, msg = policy.check_san_types(san_list, TemplateType.CLIENT)
        assert valid is True
    
    def test_san_types_code_signing_forbidden(self, policy):
        """Test forbidden SAN types for code_signing template."""
        san_list = [(SANType.EMAIL, "user@example.com")]
        valid, msg = policy.check_san_types(san_list, TemplateType.CODE_SIGNING)
        assert valid is False
    
    def test_wildcard_rejection(self, policy):
        """Test wildcard SAN rejection."""
        policy.config.allow_wildcards = False
        san_list = [(SANType.DNS, "*.example.com")]
        valid, msg = policy.check_wildcard_san(san_list)
        assert valid is False
        assert "wildcard" in msg.lower()
    
    def test_wildcard_allowed(self, policy):
        """Test wildcard SAN allowed when configured."""
        policy.config.allow_wildcards = True
        san_list = [(SANType.DNS, "*.example.com")]
        valid, msg = policy.check_wildcard_san(san_list)
        assert valid is True