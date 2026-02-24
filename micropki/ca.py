"""Certificate Authority operations for MicroPKI."""
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from micropki import crypto_utils, certificates, logger
from cryptography.hazmat.primitives.asymmetric import rsa, ec

class CertificateAuthority:
    """Certificate Authority implementation."""
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize Certificate Authority.
        
        Args:
            log_file: Optional path to log file
        """
        self.logger = logger.setup_logger(log_file)
        self.private_key: Optional[PrivateKeyTypes] = None
        self.certificate: Optional[x509.Certificate] = None
    
    def init_root_ca(
        self,
        subject: str,
        key_type: str,
        key_size: int,
        passphrase_file: str,
        out_dir: str,
        validity_days: int
    ) -> None:
        """
        Initialize a self-signed Root CA.
        
        Args:
            subject: Distinguished Name
            key_type: 'rsa' or 'ecc'
            key_size: Key size in bits
            passphrase_file: Path to passphrase file
            out_dir: Output directory
            validity_days: Validity period in days
            
        Raises:
            Exception: If any step fails
        """
        self.logger.info("Starting Root CA initialization")
        
        try:
            # Create output directories
            private_dir = os.path.join(out_dir, 'private')
            certs_dir = os.path.join(out_dir, 'certs')
            
            # Create directories with appropriate permissions
            os.makedirs(private_dir, mode=0o700, exist_ok=True)
            os.makedirs(certs_dir, exist_ok=True)
            
            self.logger.info(f"Created directories: {private_dir}, {certs_dir}")
            
            # Read passphrase
            self.logger.info("Reading passphrase from file")
            if not os.path.exists(passphrase_file):
                raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")
            
            with open(passphrase_file, 'rb') as f:
                passphrase = f.read().strip()  # Strip trailing newline
            
            if not passphrase:
                raise ValueError("Passphrase cannot be empty")
            
            # Generate key pair
            self.logger.info(f"Generating {key_type.upper()}-{key_size} key pair")
            if key_type.lower() == 'rsa':
                self.private_key = crypto_utils.generate_rsa_key(key_size)
            else:  # ecc
                self.private_key = crypto_utils.generate_ecc_key(key_size)
            self.logger.info("Key generation completed")
            
            # Create self-signed certificate
            self.logger.info("Creating self-signed certificate")
            self.certificate = certificates.create_self_signed_certificate(
                private_key=self.private_key,
                subject_dn=subject,
                validity_days=validity_days
            )
            self.logger.info("Certificate signing completed")
            
            # Save encrypted private key
            key_path = os.path.join(private_dir, 'ca.key.pem')
            self.logger.info(f"Saving encrypted private key to {key_path}")
            
            encrypted_key = crypto_utils.encrypt_private_key(self.private_key, passphrase)
            with open(key_path, 'wb') as f:
                f.write(encrypted_key)
            
            # Try to set strict permissions on key file (Unix-like systems)
            try:
                os.chmod(key_path, 0o600)
            except (OSError, AttributeError):
                self.logger.warning("Could not set file permissions (Windows system)")
            
            # Save certificate
            cert_path = os.path.join(certs_dir, 'ca.cert.pem')
            self.logger.info(f"Saving certificate to {cert_path}")
            
            cert_pem = certificates.certificate_to_pem(self.certificate)
            with open(cert_path, 'wb') as f:
                f.write(cert_pem)
            
            # Create policy document
            self._create_policy_document(out_dir, subject, key_type, key_size, validity_days)
            
            self.logger.info("Root CA initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Root CA: {str(e)}")
            raise
    
    def _create_policy_document(
        self,
        out_dir: str,
        subject: str,
        key_type: str,
        key_size: int,
        validity_days: int
    ) -> None:
        """
        Create certificate policy document.
        
        Args:
            out_dir: Output directory
            subject: Subject DN
            key_type: Key type
            key_size: Key size
            validity_days: Validity period
        """
        policy_path = os.path.join(out_dir, 'policy.txt')
        self.logger.info(f"Creating policy document at {policy_path}")
        
        with open(policy_path, 'w', encoding='utf-8') as f:
            f.write("MICROPKI CERTIFICATE POLICY DOCUMENT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Policy Version: 1.0\n")
            f.write(f"Creation Date: {self.certificate.not_valid_before_utc.isoformat()}\n\n")
            
            f.write("CERTIFICATE AUTHORITY INFORMATION\n")
            f.write("-" * 30 + "\n")
            f.write(f"CA Name (Subject DN): {subject}\n")
            f.write(f"Certificate Serial Number: 0x{self.certificate.serial_number:X}\n")
            f.write(f"Valid From: {self.certificate.not_valid_before_utc.isoformat()}\n")
            f.write(f"Valid Until: {self.certificate.not_valid_after_utc.isoformat()}\n")
            f.write(f"Validity Period: {validity_days} days\n\n")
            
            f.write("CRYPTOGRAPHIC PARAMETERS\n")
            f.write("-" * 30 + "\n")
            f.write(f"Key Algorithm: {key_type.upper()}\n")
            f.write(f"Key Size: {key_size} bits\n")
            if key_type.lower() == 'rsa':
                f.write(f"Signature Algorithm: SHA-256 with RSA\n")
            else:
                f.write(f"Signature Algorithm: SHA-384 with ECDSA (P-384 curve)\n")
            f.write(f"Certificate Version: X.509 v3\n\n")
            
            f.write("CERTIFICATE PURPOSE\n")
            f.write("-" * 30 + "\n")
            f.write("Root CA for MicroPKI demonstration and testing.\n")
            f.write("This CA is intended for educational and development\n")
            f.write("purposes only. Not for production use.\n\n")
            
            f.write("CERTIFICATE EXTENSIONS\n")
            f.write("-" * 30 + "\n")
            f.write("Basic Constraints: CA=TRUE (Critical)\n")
            f.write("Key Usage: keyCertSign, cRLSign (Critical)\n")
            f.write("Subject Key Identifier: Present\n")
            f.write("Authority Key Identifier: Present\n")
        
        self.logger.info("Policy document created")
    
    def verify(self, cert_path: str) -> bool:
        """
        Verify a certificate.
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            True if verification succeeds
        """
        self.logger.info(f"Verifying certificate: {cert_path}")
        
        try:
            with open(cert_path, 'rb') as f:
                cert_pem = f.read()
            
            cert = certificates.load_certificate(cert_pem)
            
            if certificates.verify_certificate(cert):
                self.logger.info("Certificate verification successful")
                return True
            else:
                self.logger.error("Certificate verification failed")
                return False
        except Exception as e:
            self.logger.error(f"Verification error: {str(e)}")
            return False
    
    def verify_key_match(self, key_path: str, passphrase: bytes, cert_path: str) -> bool:
        """
        Verify that private key matches certificate.
        
        Args:
            key_path: Path to encrypted private key
            passphrase: Passphrase to decrypt key
            cert_path: Path to certificate
            
        Returns:
            True if key matches certificate
        """
        self.logger.info(f"Verifying key-certificate match")
        
        try:
            # Load certificate
            with open(cert_path, 'rb') as f:
                cert = certificates.load_certificate(f.read())
            
            # Load and decrypt private key
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=passphrase,
                backend=default_backend()
            )
            
            # Compare public keys
            cert_public = cert.public_key()
            key_public = private_key.public_key()
            
            # Simple comparison of public numbers
            if isinstance(private_key, rsa.RSAPrivateKey):
                cert_numbers = cert_public.public_numbers()
                key_numbers = key_public.public_numbers()
                match = (cert_numbers.n == key_numbers.n and 
                        cert_numbers.e == key_numbers.e)
            else:  # ECC
                cert_numbers = cert_public.public_numbers()
                key_numbers = key_public.public_numbers()
                match = (cert_numbers.x == key_numbers.x and 
                        cert_numbers.y == key_numbers.y and
                        cert_numbers.curve.name == key_numbers.curve.name)
            
            if match:
                self.logger.info("Key and certificate match")
                return True
            else:
                self.logger.error("Key does not match certificate")
                return False
                
        except Exception as e:
            self.logger.error(f"Key-certificate verification error: {str(e)}")
            return False