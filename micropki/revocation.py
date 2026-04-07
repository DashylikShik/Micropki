"""Certificate revocation handling for MicroPKI."""
from enum import IntEnum
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ReasonFlags

from micropki import certificates, crypto_utils, logger


class RevocationReason(IntEnum):
    """RFC 5280 CRL reason codes."""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


REASON_MAP = {
    'unspecified': RevocationReason.UNSPECIFIED,
    'keycompromise': RevocationReason.KEY_COMPROMISE,
    'cacompromise': RevocationReason.CA_COMPROMISE,
    'affiliationchanged': RevocationReason.AFFILIATION_CHANGED,
    'superseded': RevocationReason.SUPERSEDED,
    'cessationofoperation': RevocationReason.CESSATION_OF_OPERATION,
    'certificatehold': RevocationReason.CERTIFICATE_HOLD,
    'removefromcrl': RevocationReason.REMOVE_FROM_CRL,
    'privilegewithdrawn': RevocationReason.PRIVILEGE_WITHDRAWN,
    'aacompromise': RevocationReason.AA_COMPROMISE,
}


def get_reason_code(reason_str: str) -> int:
    """
    Convert reason string to RFC 5280 reason code.
    
    Args:
        reason_str: Human-readable reason (case-insensitive)
        
    Returns:
        Integer reason code
        
    Raises:
        ValueError: If reason is not supported
    """
    key = reason_str.lower().replace(' ', '').replace('_', '')
    if key not in REASON_MAP:
        supported = ', '.join(REASON_MAP.keys())
        raise ValueError(f"Unsupported revocation reason: {reason_str}. Supported: {supported}")
    return REASON_MAP[key].value


def get_reason_string(reason_code: int) -> str:
    """Convert reason code to string."""
    for name, value in REASON_MAP.items():
        if value.value == reason_code:
            return name
    return 'unspecified'


def create_revoked_certificate_entry(
    serial_hex: str,
    revocation_date: datetime,
    reason_code: Optional[int] = None
) -> x509.RevokedCertificate:
    """
    Create a RevokedCertificate entry for CRL.
    
    Args:
        serial_hex: Serial number in hex
        revocation_date: Date of revocation
        reason_code: Optional reason code
        
    Returns:
        RevokedCertificate object
    """
    serial_int = int(serial_hex, 16)
    
    builder = x509.RevokedCertificateBuilder()
    builder = builder.serial_number(serial_int)
    builder = builder.revocation_date(revocation_date)
    
    if reason_code is not None:
        # Map reason code to ReasonFlags
        reason_map = {
            0: ReasonFlags.unspecified,
            1: ReasonFlags.key_compromise,
            2: ReasonFlags.ca_compromise,
            3: ReasonFlags.affiliation_changed,
            4: ReasonFlags.superseded,
            5: ReasonFlags.cessation_of_operation,
            6: ReasonFlags.certificate_hold,
            8: ReasonFlags.remove_from_crl,
            9: ReasonFlags.privilege_withdrawn,
            10: ReasonFlags.aa_compromise,
        }
        reason_flag = reason_map.get(reason_code, ReasonFlags.unspecified)
        builder = builder.add_extension(
            x509.CRLReason(reason_flag),
            critical=False
        )
    
    return builder.build(default_backend())


class CRLGenerator:
    """Certificate Revocation List generator."""
    
    def __init__(self, db, ca_cert_path: str, ca_key_path: str, ca_passphrase: bytes, log_file: Optional[str] = None):
        """
        Initialize CRL generator.
        
        Args:
            db: CertificateDatabase instance
            ca_cert_path: Path to CA certificate
            ca_key_path: Path to CA private key
            ca_passphrase: Passphrase for CA private key
            log_file: Optional log file path
        """
        self.db = db
        self.logger = logger.setup_logger(log_file)
        
        # Load CA certificate
        with open(ca_cert_path, 'rb') as f:
            self.ca_cert = certificates.load_certificate(f.read())
        
        # Load CA private key
        with open(ca_key_path, 'rb') as f:
            key_data = f.read()
        
        self.ca_key = serialization.load_pem_private_key(
            key_data,
            password=ca_passphrase,
            backend=default_backend()
        )
    
    def get_crl_number(self, ca_subject: str) -> int:
        """Get current CRL number from database."""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
                (ca_subject,)
            )
            row = cursor.fetchone()
            if row:
                return row['crl_number']
            return 0
    
    def update_crl_metadata(self, ca_subject: str, crl_number: int, next_update: datetime, crl_path: str) -> None:
        """Update CRL metadata in database."""
        with self.db._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ca_subject,
                crl_number,
                datetime.now(timezone.utc).isoformat(),
                next_update.isoformat(),
                crl_path
            ))
    
    def generate_crl(
        self,
        ca_subject: str,
        next_update_days: int = 7,
        out_file: Optional[str] = None
    ) -> bytes:
        """
        Generate a CRL for the CA.
        
        Args:
            ca_subject: Subject DN of the CA
            next_update_days: Days until next CRL update
            out_file: Output file path (optional)
            
        Returns:
            PEM-encoded CRL
        """
        self.logger.info(f"Generating CRL for CA: {ca_subject}")
        
        # Get revoked certificates from database
        revoked_certs = self.db.get_revoked_certificates()
        self.logger.info(f"Found {len(revoked_certs)} revoked certificates")
        
        # Build list of revoked certificates
        revoked_entries = []
        for cert in revoked_certs:
            revocation_date = datetime.fromisoformat(cert['revocation_date'])
            reason_code = None
            if cert['revocation_reason']:
                try:
                    reason_code = get_reason_code(cert['revocation_reason'])
                except ValueError:
                    self.logger.warning(f"Unknown reason: {cert['revocation_reason']}, using unspecified")
                    reason_code = 0
            
            entry = create_revoked_certificate_entry(
                serial_hex=cert['serial_hex'],
                revocation_date=revocation_date,
                reason_code=reason_code
            )
            revoked_entries.append(entry)
            self.logger.info(f"  Added revoked cert: {cert['serial_hex']}")
        
        # Get current CRL number
        crl_number = self.get_crl_number(ca_subject) + 1
        
        # Set dates
        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=next_update_days)
        
        # Build CRL
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)
        
        # Add revoked certificates
        for entry in revoked_entries:
            builder = builder.add_revoked_certificate(entry)
        
        # Add CRL number extension
        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )
        
        # Add Authority Key Identifier
        try:
            aki_ext = self.ca_cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            builder = builder.add_extension(aki_ext.value, critical=False)
        except x509.ExtensionNotFound:
            # Compute AKI from CA public key
            ski = crypto_utils.compute_ski(self.ca_cert.public_key())
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier(ski)
            )
            builder = builder.add_extension(aki, critical=False)
        
        # Determine signature algorithm
        if isinstance(self.ca_key, rsa.RSAPrivateKey):
            algorithm = hashes.SHA256()
        else:
            algorithm = hashes.SHA384()
        
        # Sign CRL
        crl = builder.sign(
            private_key=self.ca_key,
            algorithm=algorithm,
            backend=default_backend()
        )
        
        # Convert to PEM
        crl_pem = crl.public_bytes(Encoding.PEM)
        
        # Save to file if path provided
        if out_file:
            # Ensure directory exists
            import os
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            with open(out_file, 'wb') as f:
                f.write(crl_pem)
            self.logger.info(f"CRL saved to {out_file}")
        
        # Update metadata
        self.update_crl_metadata(ca_subject, crl_number, next_update, out_file or "")
        
        self.logger.info(f"CRL generated: {len(revoked_entries)} revoked certs, "
                        f"CRL number {crl_number}, next update {next_update.isoformat()}")
        
        return crl_pem