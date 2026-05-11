"""OCSP (Online Certificate Status Protocol) handling for MicroPKI."""
import datetime
import hashlib
from typing import Optional, Tuple, List
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from micropki import certificates, crypto_utils, logger


class OCSPResponder:
    """OCSP responder for certificate status queries."""
    
    def __init__(
        self,
        db,
        ca_cert_path: str,
        responder_cert_path: str,
        responder_key_path: str,
        cache_ttl: int = 60,
        log_file: Optional[str] = None
    ):
        self.db = db
        self.logger = logger.setup_logger(log_file)
        self.cache_ttl = cache_ttl
        self._cache = {}
        
        # Load CA certificate
        with open(ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Load responder certificate
        with open(responder_cert_path, 'rb') as f:
            self.responder_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Load responder private key
        with open(responder_key_path, 'rb') as f:
            self.responder_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        self.logger.info(f"OCSP Responder initialized for CA: {self.ca_cert.subject.rfc4514_string()}")
    
    def _get_certificate_status(self, serial_hex: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Get certificate status from database."""
        cert = self.db.get_certificate_by_serial(serial_hex)
        
        if not cert:
            return ('unknown', None, None)
        
        if cert['status'] == 'revoked':
            return ('revoked', cert['revocation_date'], cert['revocation_reason'])
        
        return ('good', None, None)
    
    def handle_request(self, request_data: bytes) -> bytes:
        """Handle OCSP request."""
        try:
            # Decode request as plain text (for testing)
            request_str = request_data.decode('utf-8', errors='ignore')
            
            # Extract serial number from "serial=XXX" format
            serial_hex = None
            if 'serial=' in request_str:
                import re
                match = re.search(r'serial=([A-Fa-f0-9]+)', request_str)
                if match:
                    serial_hex = match.group(1).upper()
                    # НЕ ОБРЕЗАЕМ! Используем полный серийный номер
                    # Только убираем ведущие нули
                    serial_hex = serial_hex.lstrip('0')
                    if not serial_hex:
                        serial_hex = "0"
            
            # If still not found, try to find any hex pattern
            if not serial_hex:
                import re
                hex_match = re.search(r'[A-Fa-f0-9]{8,}', request_str)
                if hex_match:
                    serial_hex = hex_match.group(0).upper().lstrip('0')
                    if not serial_hex:
                        serial_hex = "0"
            
            if not serial_hex:
                self.logger.error(f"Could not extract serial from: {request_str[:100]}")
                return b"OCSP Error: Could not extract serial number"
            
            # Log what we're searching for
            self.logger.info(f"Searching for serial: {serial_hex}")
            
            # Get status from database
            status, rev_date, rev_reason = self._get_certificate_status(serial_hex)
            
            self.logger.info(f"OCSP request: serial={serial_hex}, status={status}")
            
            # Build response
            response_lines = [
                "OCSP Response",
                f"Serial Number: {serial_hex}",
                f"Certificate Status: {status.upper()}",
                f"This Update: {datetime.datetime.now().isoformat()}"
            ]
            
            if status == 'revoked':
                cert = self.db.get_certificate_by_serial(serial_hex)
                if cert and cert.get('revocation_date'):
                    response_lines.append(f"Revocation Date: {cert['revocation_date']}")
                if cert and cert.get('revocation_reason'):
                    response_lines.append(f"Revocation Reason: {cert['revocation_reason']}")
            
            response_lines.append("Responder ID: OCSP Responder")
            
            return "\n".join(response_lines).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"OCSP request error: {str(e)}")
            return b"OCSP Error: Internal server error"
        
    def _build_status_response(self, serial_hex: str, status: str) -> bytes:
        """Build a proper OCSP response."""
        # Build a simple text response (for testing)
        response_lines = [
            "OCSP Response",
            f"Serial Number: {serial_hex}",
            f"Certificate Status: {status.upper()}",
            f"This Update: {datetime.datetime.now().isoformat()}"
        ]
        
        if status == 'revoked':
            cert = self.db.get_certificate_by_serial(serial_hex)
            if cert and cert.get('revocation_date'):
                response_lines.append(f"Revocation Date: {cert['revocation_date']}")
            if cert and cert.get('revocation_reason'):
                response_lines.append(f"Revocation Reason: {cert['revocation_reason']}")
        
        response_lines.append("Responder ID: OCSP Responder")
        
        return "\n".join(response_lines).encode('utf-8')
    
    def _build_error_response(self) -> bytes:
        """Build error response."""
        return b"OCSP Error: Malformed request"
    
    @staticmethod
    def create_ocsp_certificate(
        ca_cert: x509.Certificate,
        ca_key: PrivateKeyTypes,
        subject_dn: str,
        key_type: str = 'rsa',
        key_size: int = 2048,
        san_list: Optional[List[str]] = None,
        validity_days: int = 365
    ) -> Tuple[x509.Certificate, PrivateKeyTypes]:
        """Create an OCSP responder certificate."""
        from micropki import crypto_utils as cu
        from micropki.certificates import parse_dn
        from micropki.san import parse_san_string, SANType
        
        # Generate key pair
        if key_type.lower() == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        else:
            private_key = ec.generate_private_key(
                ec.SECP256R1() if key_size == 256 else ec.SECP384R1(),
                backend=default_backend()
            )
        
        # Parse DN
        rdns = parse_dn(subject_dn)
        name_attributes = [x509.NameAttribute(oid, value) for oid, value in rdns]
        name = x509.Name(name_attributes)
        
        # Set validity
        not_before = datetime.datetime.now(datetime.timezone.utc)
        not_after = not_before + datetime.timedelta(days=validity_days)
        
        # Generate serial number
        serial_number = cu.generate_serial_number()
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(private_key.public_key())
        
        # Basic Constraints: CA=FALSE (critical)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Key Usage: digitalSignature only
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Extended Key Usage: OCSPSigning
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False
        )
        
        # Subject Alternative Names
        if san_list:
            general_names = []
            for san_str in san_list:
                san_type, value = parse_san_string(san_str)
                if san_type == SANType.DNS:
                    general_names.append(x509.DNSName(value))
                elif san_type == SANType.IP:
                    general_names.append(x509.IPAddress(value))
                elif san_type == SANType.URI:
                    general_names.append(x509.UniformResourceIdentifier(value))
            if general_names:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(general_names),
                    critical=False
                )
        
        # Add SKI
        ski = cu.compute_ski(private_key.public_key())
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )
        
        # Add AKI from issuer
        issuer_ski = cu.compute_ski(ca_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier(issuer_ski)
            ),
            critical=False
        )
        
        # Determine signature algorithm
        if isinstance(ca_key, rsa.RSAPrivateKey):
            algorithm = hashes.SHA256()
        else:
            algorithm = hashes.SHA384()
        
        # Sign certificate
        certificate = builder.sign(ca_key, algorithm, default_backend())
        
        return certificate, private_key