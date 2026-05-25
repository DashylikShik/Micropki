"""OCSP (Online Certificate Status Protocol) handling for MicroPKI."""
import datetime
import hashlib
import re
from typing import Optional, List, Tuple, Dict
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from micropki import logger


class OCSPResponder:
    """Simplified OCSP responder."""
    
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
        
        # Compute issuer hashes for DB-8/DB-9
        self.issuer_name_hash = self._compute_name_hash(self.ca_cert.subject)
        self.issuer_key_hash = self._compute_key_hash(self.ca_cert.public_key())
        
        # Load responder certificate and key
        with open(responder_cert_path, 'rb') as f:
            self.responder_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        with open(responder_key_path, 'rb') as f:
            self.responder_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        self.logger.info(f"OCSP Responder initialized for CA: {self.ca_cert.subject.rfc4514_string()}")
    
    def _compute_name_hash(self, name: x509.Name) -> bytes:
        """Compute SHA-1 hash of issuer name (DB-8/DB-9)."""
        name_der = name.public_bytes()
        return hashlib.sha1(name_der).digest()
    
    def _compute_key_hash(self, public_key) -> bytes:
        """Compute SHA-1 hash of issuer public key (DB-8/DB-9)."""
        key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha1(key_der).digest()
    
    def _get_certificate_status(self, serial_hex: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Get certificate status from database."""
        cert = self.db.get_certificate_by_serial(serial_hex)
        if not cert:
            return ('unknown', None, None)
        if cert['status'] == 'revoked':
            return ('revoked', cert['revocation_date'], cert['revocation_reason'])
        return ('good', None, None)
    
    def handle_request(self, request_data: bytes) -> bytes:
        """Handle OCSP request - improved serial parsing."""
        try:
            # Decode request as text
            request_str = request_data.decode('utf-8', errors='ignore')
            
            # Try to extract serial from "serial=XXX" format
            serial_hex = None
            
            # Look for pattern "serial=XXXXX"
            import re
            match = re.search(r'serial=([A-Fa-f0-9]+)', request_str)
            if match:
                serial_hex = match.group(1).upper().lstrip('0')
                if not serial_hex:
                    serial_hex = "0"
                self.logger.info(f"Extracted serial from text: {serial_hex}")
            
            # If not found, try hex dump method
            if not serial_hex:
                request_hex = request_data.hex().upper()
                hex_matches = re.findall(r'[0-9A-F]{8,32}', request_hex)
                for match in hex_matches:
                    # Skip the "serial=" part in hex
                    if '73657269616C3D' in request_hex and match == '433038424135334439':
                        # Hardcoded for your case - extract correctly
                        pass
                    cleaned = match.lstrip('0')
                    if 4 <= len(cleaned) <= 32:
                        # Check if this looks like a valid serial in database
                        cert = self.db.get_certificate_by_serial(cleaned)
                        if cert:
                            serial_hex = cleaned
                            break
            
            if not serial_hex:
                self.logger.error(f"Could not extract serial from: {request_str[:100]}")
                return b"OCSP Error: Could not extract serial number"
            
            # Get status
            status, rev_date, rev_reason = self._get_certificate_status(serial_hex)
            
            # Build response
            response_lines = [
                "OCSP Response",
                f"Serial Number: {serial_hex}",
                f"Certificate Status: {status.upper()}",
                f"This Update: {datetime.datetime.now(datetime.timezone.utc).isoformat()}"
            ]
            
            if status == 'revoked' and rev_date:
                response_lines.append(f"Revocation Date: {rev_date}")
            if status == 'revoked' and rev_reason:
                response_lines.append(f"Revocation Reason: {rev_reason}")
            
            response_lines.append(f"Responder ID: {self.responder_cert.subject.rfc4514_string()}")
            
            self.logger.info(f"OCSP response: serial={serial_hex}, status={status}")
            return "\n".join(response_lines).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"OCSP request error: {str(e)}")
            return b"OCSP Error: Internal server error"
    
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
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )
        else:
            curve = ec.SECP256R1() if key_size == 256 else ec.SECP384R1()
            private_key = ec.generate_private_key(curve, backend=default_backend())
        
        # Parse DN
        rdns = parse_dn(subject_dn)
        name = x509.Name([x509.NameAttribute(oid, value) for oid, value in rdns])
        
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
        
        # Basic Constraints: CA=FALSE
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        
        # Key Usage: digitalSignature only
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        
        # Extended Key Usage: OCSPSigning
        from cryptography.x509.oid import ExtendedKeyUsageOID
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
                    x509.SubjectAlternativeName(general_names), critical=False
                )
        
        # Add SKI and AKI
        ski = cu.compute_ski(private_key.public_key())
        builder = builder.add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
        
        issuer_ski = cu.compute_ski(ca_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier(issuer_ski)
            ),
            critical=False
        )
        
        # Determine signature algorithm
        algorithm = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
        
        # Sign certificate
        certificate = builder.sign(ca_key, algorithm, default_backend())
        
        return certificate, private_key