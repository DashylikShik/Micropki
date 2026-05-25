"""Security policy enforcement for MicroPKI."""
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import rsa, ec


class TemplateType(Enum):
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code_signing"


@dataclass
class PolicyConfig:
    rsa_root_min: int = 4096
    rsa_intermediate_min: int = 3072
    rsa_end_entity_min: int = 2048
    ecc_root_min: int = 384
    ecc_intermediate_min: int = 384
    ecc_end_entity_min: int = 256
    root_max_validity: int = 3650
    intermediate_max_validity: int = 1825
    end_entity_max_validity: int = 365
    allow_wildcards: bool = False
    allowed_san_types: dict = None
    
    def __post_init__(self):
        if self.allowed_san_types is None:
            self.allowed_san_types = {
                TemplateType.SERVER: {'dns', 'ip'},
                TemplateType.CLIENT: {'email', 'dns'},
                TemplateType.CODE_SIGNING: {'dns', 'uri'}
            }


class PolicyEnforcer:
    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()
    
    def check_key_size(self, key, is_ca: bool = False, is_root: bool = False) -> Tuple[bool, str]:
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            key_size = key.key_size if hasattr(key, 'key_size') else key.public_key().key_size
            if is_root:
                min_size = self.config.rsa_root_min
            elif is_ca:
                min_size = self.config.rsa_intermediate_min
            else:
                min_size = self.config.rsa_end_entity_min
            if key_size < min_size:
                return False, f"RSA key size {key_size} below minimum {min_size}"
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            curve_name = key.curve.name if hasattr(key, 'curve') else key.public_key().curve.name
            if is_root or is_ca:
                if 'secp384r1' not in curve_name:
                    return False, f"CA requires P-384 curve, got {curve_name}"
            else:
                if 'secp256r1' not in curve_name and 'secp384r1' not in curve_name:
                    return False, f"End-entity requires P-256 or P-384, got {curve_name}"
        return True, ""
    
    def check_validity_period(self, validity_days: int, is_ca: bool = False, is_root: bool = False) -> Tuple[bool, str]:
        if is_root:
            max_days = self.config.root_max_validity
        elif is_ca:
            max_days = self.config.intermediate_max_validity
        else:
            max_days = self.config.end_entity_max_validity
        if validity_days > max_days:
            return False, f"Validity {validity_days} days exceeds max {max_days}"
        if validity_days <= 0:
            return False, "Validity must be positive"
        return True, ""
    
    def check_san_types(self, san_list: List[Tuple], template: TemplateType) -> Tuple[bool, str]:
        allowed = self.config.allowed_san_types.get(template, set())
        for san_type, _ in san_list:
            if san_type.value not in allowed:
                return False, f"SAN type '{san_type.value}' not allowed for {template.value}"
        return True, ""
    
    def check_wildcard_san(self, san_list: List[Tuple]) -> Tuple[bool, str]:
        if self.config.allow_wildcards:
            return True, ""
        for san_type, value in san_list:
            if san_type.value == 'dns' and '*' in value:
                return False, f"Wildcard SAN '{value}' not allowed"
        return True, ""
    
    def check_signature_algorithm(self, signature_algorithm_oid) -> Tuple[bool, str]:
        """Check if signature algorithm meets security requirements (POL-6)."""
        algo_str = str(signature_algorithm_oid).lower()
        # SHA-1 is forbidden
        if 'sha1' in algo_str:
            return False, "SHA-1 signature algorithm is forbidden. Use SHA-256 or stronger."
        return True, ""
    
    def enforce_issuance_policy(self, public_key, validity_days: int, template: TemplateType,
                                 san_list: List[Tuple], is_ca: bool = False, is_root: bool = False) -> Tuple[bool, str]:
        valid, msg = self.check_key_size(public_key, is_ca, is_root)
        if not valid:
            return False, f"Key size violation: {msg}"
        valid, msg = self.check_validity_period(validity_days, is_ca, is_root)
        if not valid:
            return False, f"Validity violation: {msg}"
        if not is_ca:
            valid, msg = self.check_san_types(san_list, template)
            if not valid:
                return False, f"SAN violation: {msg}"
            valid, msg = self.check_wildcard_san(san_list)
            if not valid:
                return False, f"Wildcard violation: {msg}"
        return True, ""


_policy_enforcer: Optional[PolicyEnforcer] = None


def init_policy_enforcer(config: Optional[PolicyConfig] = None) -> PolicyEnforcer:
    global _policy_enforcer
    _policy_enforcer = PolicyEnforcer(config)
    return _policy_enforcer


def get_policy_enforcer() -> Optional[PolicyEnforcer]:
    return _policy_enforcer