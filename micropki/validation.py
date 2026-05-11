"""Certificate path validation engine for MicroPKI."""
import datetime
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


class ValidationStatus(Enum):
    """Validation status for certificates."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ValidationStep:
    """Single validation step result."""
    name: str
    status: ValidationStatus
    message: Optional[str] = None
    details: Optional[Dict] = None


@dataclass
class ValidationResult:
    """Complete validation result."""
    overall_status: ValidationStatus
    steps: List[ValidationStep] = field(default_factory=list)
    chain: List[x509.Certificate] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'overall_status': self.overall_status.value,
            'steps': [
                {
                    'name': s.name,
                    'status': s.status.value,
                    'message': s.message,
                    'details': s.details
                }
                for s in self.steps
            ],
            'errors': self.errors
        }


class PathValidator:
    """Certificate path validator implementing RFC 5280 simplified validation."""
    
    def __init__(self, validation_time: Optional[datetime.datetime] = None):
        """
        Initialize validator.
        
        Args:
            validation_time: Time to validate against (default: current time)
        """
        self.validation_time = validation_time or datetime.datetime.now(datetime.timezone.utc)
        self.logger = None
    
    def set_logger(self, logger):
        """Set logger for validation output."""
        self.logger = logger
    
    def build_chain(
        self,
        leaf_cert: x509.Certificate,
        untrusted_certs: List[x509.Certificate],
        trusted_certs: List[x509.Certificate]
    ) -> Tuple[List[x509.Certificate], List[str]]:
        """
        Build certificate chain from leaf to trusted root.
        
        Args:
            leaf_cert: Leaf certificate
            untrusted_certs: List of intermediate certificates
            trusted_certs: List of trusted root certificates
            
        Returns:
            Tuple of (chain, errors)
        """
        chain = [leaf_cert]
        errors = []
        
        current_cert = leaf_cert
        max_depth = 10
        
        for _ in range(max_depth):
            # Find issuer of current certificate
            issuer = None
            
            # First check untrusted certs
            for cert in untrusted_certs:
                if cert.subject == current_cert.issuer:
                    issuer = cert
                    break
            
            # Then check trusted roots
            if not issuer:
                for cert in trusted_certs:
                    if cert.subject == current_cert.issuer:
                        issuer = cert
                        break
            
            if not issuer:
                errors.append(f"Cannot find issuer for: {current_cert.subject}")
                break
            
            chain.append(issuer)
            
            # Stop if we reached a trusted root
            if issuer in trusted_certs:
                break
            
            current_cert = issuer
        else:
            errors.append("Chain too long or circular")
        
        if self.logger:
            self.logger.info(f"Built chain with {len(chain)} certificates")
        
        return chain, errors
    
    def validate_signature(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate
    ) -> Tuple[bool, str]:
        """
        Validate certificate signature using issuer's public key.
        
        Args:
            cert: Certificate to validate
            issuer: Issuer certificate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            public_key = issuer.public_key()
            signature = cert.signature
            tbs_bytes = cert.tbs_certificate_bytes
            hash_algo = cert.signature_hash_algorithm
            
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    tbs_bytes,
                    padding.PKCS1v15(),
                    hash_algo
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    tbs_bytes,
                    ec.ECDSA(hash_algo)
                )
            else:
                return False, f"Unsupported key type: {type(public_key)}"
            
            return True, ""
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"
    
    def validate_validity_period(self, cert: x509.Certificate) -> Tuple[bool, str]:
        """
        Validate certificate validity period.
        
        Args:
            cert: Certificate to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        if self.validation_time < not_before:
            return False, f"Certificate not yet valid (valid from {not_before})"
        
        if self.validation_time > not_after:
            return False, f"Certificate expired (valid until {not_after})"
        
        return True, ""
    
    def validate_basic_constraints(
        self,
        cert: x509.Certificate,
        is_ca: bool
    ) -> Tuple[bool, str]:
        """
        Validate Basic Constraints extension.
        
        Args:
            cert: Certificate to validate
            is_ca: Whether this certificate is expected to be a CA
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca_cert = bc.value.ca
            
            if is_ca and not is_ca_cert:
                return False, "Expected CA certificate but CA=FALSE"
            
            if not is_ca and is_ca_cert:
                return False, "Expected end-entity certificate but CA=TRUE"
            
            return True, ""
        except x509.ExtensionNotFound:
            if is_ca:
                return False, "CA certificate missing Basic Constraints"
            # End-entity without Basic Constraints is acceptable
            return True, ""
    
    def validate_key_usage(
        self,
        cert: x509.Certificate,
        required_usage: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """
        Validate Key Usage extension.
        
        Args:
            cert: Certificate to validate
            required_usage: List of required key usage flags
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            
            if required_usage:
                for usage in required_usage:
                    if not getattr(ku.value, usage, False):
                        return False, f"Missing required Key Usage: {usage}"
            
            return True, ""
        except x509.ExtensionNotFound:
            # Key Usage is not critical, can be absent
            return True, ""
    
    def validate_extended_key_usage(
        self,
        cert: x509.Certificate,
        expected_purpose: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validate Extended Key Usage extension.
        
        Args:
            cert: Certificate to validate
            expected_purpose: Expected EKU (server, client, code_signing)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not expected_purpose:
            return True, ""
        
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            
            purpose_map = {
                'server': ExtendedKeyUsageOID.SERVER_AUTH,
                'client': ExtendedKeyUsageOID.CLIENT_AUTH,
                'code_signing': ExtendedKeyUsageOID.CODE_SIGNING,
            }
            
            expected_oid = purpose_map.get(expected_purpose)
            if expected_oid and expected_oid not in eku.value:
                return False, f"Missing expected Extended Key Usage: {expected_purpose}"
            
            return True, ""
        except x509.ExtensionNotFound:
            if expected_purpose:
                return False, f"Missing Extended Key Usage extension (expected {expected_purpose})"
            return True, ""
    
    def validate_certificate(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate,
        is_ca: bool = False,
        expected_ku: Optional[List[str]] = None,
        expected_eku: Optional[str] = None
    ) -> List[ValidationStep]:
        """
        Perform all validation checks on a single certificate.
        
        Args:
            cert: Certificate to validate
            issuer: Issuer certificate
            is_ca: Whether this is a CA certificate
            expected_ku: Expected Key Usage flags
            expected_eku: Expected Extended Key Usage
            
        Returns:
            List of validation steps
        """
        steps = []
        
        # Signature
        valid, msg = self.validate_signature(cert, issuer)
        steps.append(ValidationStep(
            name="Signature",
            status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
            message=msg if not valid else None
        ))
        
        # Validity period
        valid, msg = self.validate_validity_period(cert)
        steps.append(ValidationStep(
            name="Validity Period",
            status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
            message=msg if not valid else None
        ))
        
        # Basic Constraints
        valid, msg = self.validate_basic_constraints(cert, is_ca)
        steps.append(ValidationStep(
            name="Basic Constraints",
            status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
            message=msg if not valid else None
        ))
        
        # Key Usage
        valid, msg = self.validate_key_usage(cert, expected_ku)
        steps.append(ValidationStep(
            name="Key Usage",
            status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
            message=msg if not valid else None
        ))
        
        # Extended Key Usage
        valid, msg = self.validate_extended_key_usage(cert, expected_eku)
        steps.append(ValidationStep(
            name="Extended Key Usage",
            status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
            message=msg if not valid else None
        ))
        
        return steps
    
    def validate_chain(
        self,
        leaf_cert: x509.Certificate,
        untrusted_certs: List[x509.Certificate],
        trusted_certs: List[x509.Certificate],
        expected_eku: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate complete certificate chain.
        
        Args:
            leaf_cert: Leaf certificate
            untrusted_certs: Intermediate certificates
            trusted_certs: Trusted root certificates
            expected_eku: Expected EKU for leaf certificate
            
        Returns:
            ValidationResult object
        """
        result = ValidationResult(overall_status=ValidationStatus.PASSED)
        
        # Build chain
        chain, errors = self.build_chain(leaf_cert, untrusted_certs, trusted_certs)
        result.chain = chain
        
        if errors:
            result.overall_status = ValidationStatus.FAILED
            result.errors.extend(errors)
            return result
        
        # Validate each certificate in chain
        for i, cert in enumerate(chain):
            is_leaf = (i == 0)
            is_root = (i == len(chain) - 1)
            issuer = chain[i + 1] if i + 1 < len(chain) else None
            
            if is_root:
                # Root certificate - only validate validity period
                valid, msg = self.validate_validity_period(cert)
                step = ValidationStep(
                    name=f"Certificate {i+1}: {cert.subject}",
                    status=ValidationStatus.PASSED if valid else ValidationStatus.FAILED,
                    message=msg if not valid else None
                )
                result.steps.append(step)
                if not valid:
                    result.overall_status = ValidationStatus.FAILED
            else:
                # Validate against issuer
                steps = self.validate_certificate(
                    cert=cert,
                    issuer=issuer,
                    is_ca=(not is_leaf),
                    expected_eku=(expected_eku if is_leaf else None)
                )
                
                for step in steps:
                    step.name = f"Cert {i+1}: {step.name}"
                    result.steps.append(step)
                    if step.status == ValidationStatus.FAILED:
                        result.overall_status = ValidationStatus.FAILED
        
        return result