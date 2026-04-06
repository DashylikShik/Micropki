"""Certificate Authority operations for MicroPKI."""
import os
import datetime
from typing import List, Tuple, Optional as OptionalType

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from micropki import crypto_utils, certificates, logger


class CertificateAuthority:
    """Certificate Authority implementation."""
    
    def __init__(self, log_file: OptionalType[str] = None, db_path: OptionalType[str] = None):
        """
        Initialize Certificate Authority.
        
        Args:
            log_file: Optional path to log file
            db_path: Optional path to SQLite database for certificate storage
        """
        self.logger = logger.setup_logger(log_file)
        self.private_key: OptionalType[PrivateKeyTypes] = None
        self.certificate: OptionalType[x509.Certificate] = None
        self.db_path = db_path
        self.db = None
        
        if db_path:
            from micropki.database import CertificateDatabase
            self.db = CertificateDatabase(db_path, log_file)
    
    def _insert_certificate_to_db(
        self,
        cert: x509.Certificate,
        cert_pem: str,
        subject: str,
        issuer: str,
        status: str = 'valid'
    ) -> None:
        """
        Insert certificate into database if configured.
        
        Args:
            cert: Certificate object
            cert_pem: PEM-encoded certificate
            subject: Subject DN
            issuer: Issuer DN
            status: Certificate status ('valid', 'revoked', 'expired')
        """
        if not self.db:
            return
        
        serial_hex = hex(cert.serial_number)[2:].upper()
        
        cert_data = {
            'serial_hex': serial_hex,
            'serial_int': cert.serial_number,
            'subject': subject,
            'issuer': issuer,
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'cert_pem': cert_pem,
            'status': status
        }
        
        self.db.insert_certificate(cert_data)
        self.logger.info(f"Certificate inserted into database: serial={serial_hex}")
    
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
                passphrase = f.read().strip()
            
            if not passphrase:
                raise ValueError("Passphrase cannot be empty")
            
            # Generate key pair
            self.logger.info(f"Generating {key_type.upper()}-{key_size} key pair")
            if key_type.lower() == 'rsa':
                self.private_key = crypto_utils.generate_rsa_key(key_size)
            else:
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
            
            try:
                os.chmod(key_path, 0o600)
            except (OSError, AttributeError):
                self.logger.warning("Could not set file permissions (Windows system)")
            
            # Save certificate
            cert_path = os.path.join(certs_dir, 'ca.cert.pem')
            self.logger.info(f"Saving certificate to {cert_path}")
            
            cert_pem = certificates.certificate_to_pem(self.certificate)
            cert_pem_str = cert_pem.decode('utf-8')
            with open(cert_path, 'wb') as f:
                f.write(cert_pem)
            
            # Insert into database if configured
            self._insert_certificate_to_db(
                cert=self.certificate,
                cert_pem=cert_pem_str,
                subject=subject,
                issuer=subject,  # Self-signed
                status='valid'
            )
            
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
        """Create certificate policy document."""
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
        """Verify a certificate."""
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
        """Verify that private key matches certificate."""
        self.logger.info(f"Verifying key-certificate match")
        
        try:
            with open(cert_path, 'rb') as f:
                cert = certificates.load_certificate(f.read())
            
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=passphrase,
                backend=default_backend()
            )
            
            cert_public = cert.public_key()
            key_public = private_key.public_key()
            
            if isinstance(private_key, rsa.RSAPrivateKey):
                cert_numbers = cert_public.public_numbers()
                key_numbers = key_public.public_numbers()
                match = (cert_numbers.n == key_numbers.n and 
                        cert_numbers.e == key_numbers.e)
            else:
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
    
    # ============= SPRINT 2: INTERMEDIATE CA METHODS =============
    
    def issue_intermediate_ca(
        self,
        root_cert_path: str,
        root_key_path: str,
        root_passphrase_file: str,
        subject: str,
        key_type: str,
        key_size: int,
        intermediate_passphrase_file: str,
        out_dir: str,
        validity_days: int,
        pathlen: int = 0
    ) -> None:
        """Issue an Intermediate CA certificate signed by Root CA."""
        self.logger.info("Starting Intermediate CA issuance")
        
        try:
            from micropki import csr as csr_module
            
            private_dir = os.path.join(out_dir, 'private')
            certs_dir = os.path.join(out_dir, 'certs')
            csrs_dir = os.path.join(out_dir, 'csrs')
            
            os.makedirs(private_dir, mode=0o700, exist_ok=True)
            os.makedirs(certs_dir, exist_ok=True)
            os.makedirs(csrs_dir, exist_ok=True)
            
            # Load Root CA certificate
            self.logger.info(f"Loading Root CA certificate: {root_cert_path}")
            with open(root_cert_path, 'rb') as f:
                root_cert = certificates.load_certificate(f.read())
            
            # Load Root CA private key
            self.logger.info(f"Loading Root CA private key: {root_key_path}")
            with open(root_key_path, 'rb') as f:
                root_key_data = f.read()
            
            with open(root_passphrase_file, 'rb') as f:
                root_passphrase = f.read().strip()
            
            root_private_key = serialization.load_pem_private_key(
                root_key_data,
                password=root_passphrase,
                backend=default_backend()
            )
            
            # Generate Intermediate CA key pair
            self.logger.info(f"Generating Intermediate CA {key_type.upper()}-{key_size} key pair")
            if key_type.lower() == 'rsa':
                intermediate_private_key = crypto_utils.generate_rsa_key(key_size)
            else:
                intermediate_private_key = crypto_utils.generate_ecc_key(key_size)
            
            # Read Intermediate CA passphrase
            with open(intermediate_passphrase_file, 'rb') as f:
                intermediate_passphrase = f.read().strip()
            
            # Create Intermediate CA CSR with extensions
            self.logger.info("Creating Intermediate CA CSR")
            extensions = csr_module.create_intermediate_ca_extensions(pathlen)
            intermediate_csr = csr_module.generate_csr(
                private_key=intermediate_private_key,
                subject_dn=subject,
                extensions=extensions
            )
            
            # Save CSR for audit
            csr_path = os.path.join(csrs_dir, 'intermediate.csr.pem')
            with open(csr_path, 'wb') as f:
                f.write(csr_module.csr_to_pem(intermediate_csr))
            self.logger.info(f"CSR saved to {csr_path}")
            
            # Create Intermediate CA certificate
            self.logger.info("Signing Intermediate CA certificate with Root CA")
            intermediate_cert = self._sign_csr_with_ca(
                csr=intermediate_csr,
                issuer_cert=root_cert,
                issuer_key=root_private_key,
                validity_days=validity_days,
                is_ca=True,
                pathlen=pathlen
            )
            
            # Save encrypted Intermediate CA private key
            key_path = os.path.join(private_dir, 'intermediate.key.pem')
            self.logger.info(f"Saving encrypted Intermediate CA key to {key_path}")
            
            encrypted_key = crypto_utils.encrypt_private_key(
                intermediate_private_key,
                intermediate_passphrase
            )
            with open(key_path, 'wb') as f:
                f.write(encrypted_key)
            
            try:
                os.chmod(key_path, 0o600)
            except (OSError, AttributeError):
                self.logger.warning("Could not set file permissions (Windows system)")
            
            # Save Intermediate CA certificate
            cert_path = os.path.join(certs_dir, 'intermediate.cert.pem')
            self.logger.info(f"Saving Intermediate CA certificate to {cert_path}")
            
            cert_pem = certificates.certificate_to_pem(intermediate_cert)
            cert_pem_str = cert_pem.decode('utf-8')
            with open(cert_path, 'wb') as f:
                f.write(cert_pem)
            
            # Insert into database if configured
            self._insert_certificate_to_db(
                cert=intermediate_cert,
                cert_pem=cert_pem_str,
                subject=subject,
                issuer=root_cert.subject.rfc4514_string(),
                status='valid'
            )
            
            # Update policy document
            self._update_policy_with_intermediate(out_dir, subject, key_type, key_size, 
                                                   validity_days, pathlen, root_cert.subject)
            
            self.logger.info("Intermediate CA issuance completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to issue Intermediate CA: {str(e)}")
            raise
    
    def issue_certificate(
        self,
        ca_cert_path: str,
        ca_key_path: str,
        ca_passphrase_file: str,
        template_name: str,
        subject: str,
        san_list: List[str],
        out_dir: str,
        validity_days: int = 365,
        csr_path: OptionalType[str] = None
    ) -> None:
        """Issue an end-entity certificate."""
        self.logger.info(f"Starting certificate issuance (template: {template_name})")
        
        try:
            from micropki import san as san_module
            from micropki import templates
            
            # Используем out_dir как конечную директорию (НЕ добавляем подпапку)
            output_dir = out_dir
            os.makedirs(output_dir, exist_ok=True)
            
            # Parse SANs
            parsed_sans = []
            for san_str in san_list:
                san_type, value = san_module.parse_san_string(san_str)
                parsed_sans.append((san_type, value))
            
            # Get template and validate SANs
            template = templates.get_template(template_name)
            is_valid, error = template.validate_san(parsed_sans)
            if not is_valid:
                raise ValueError(f"SAN validation failed: {error}")
            
            # Load CA certificate
            self.logger.info(f"Loading CA certificate: {ca_cert_path}")
            with open(ca_cert_path, 'rb') as f:
                ca_cert = certificates.load_certificate(f.read())
            
            # Load CA private key
            self.logger.info(f"Loading CA private key: {ca_key_path}")
            with open(ca_key_path, 'rb') as f:
                ca_key_data = f.read()
            
            with open(ca_passphrase_file, 'rb') as f:
                ca_passphrase = f.read().strip()
            
            ca_private_key = serialization.load_pem_private_key(
                ca_key_data,
                password=ca_passphrase,
                backend=default_backend()
            )
            
            # Get or generate end-entity key pair
            if csr_path:
                from micropki import csr as csr_module
                
                self.logger.info(f"Loading external CSR: {csr_path}")
                with open(csr_path, 'rb') as f:
                    csr_pem = f.read()
                csr = csr_module.load_csr(csr_pem)
                
                if not csr_module.verify_csr_signature(csr):
                    raise ValueError("CSR signature verification failed")
                
                end_entity_public_key = csr.public_key()
                end_entity_private_key = None
                parsed_subject = subject
            else:
                self.logger.info("Generating end-entity key pair (RSA-2048)")
                end_entity_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                end_entity_public_key = end_entity_private_key.public_key()
                parsed_subject = subject
            
            # Create certificate extensions from template
            extensions = template.get_extensions(parsed_sans)
            
            # Generate unique serial number using database if available
            if self.db:
                from micropki.serial import SerialGenerator
                serial_gen = SerialGenerator(self.db_path)
                serial_int, serial_hex = serial_gen.generate_serial()
                serial_number = serial_int
            else:
                serial_number = crypto_utils.generate_serial_number()
            
            # Create certificate
            self.logger.info("Creating end-entity certificate")
            cert = self._create_certificate(
                public_key=end_entity_public_key,
                subject_dn=parsed_subject,
                issuer_cert=ca_cert,
                issuer_key=ca_private_key,
                serial_number=serial_number,
                validity_days=validity_days,
                extensions=extensions
            )
            
            # Determine filename
            filename = self._get_cert_filename(parsed_subject, parsed_sans)
            
            # Save certificate directly in output_dir
            cert_path = os.path.join(output_dir, f"{filename}.cert.pem")
            with open(cert_path, 'wb') as f:
                f.write(certificates.certificate_to_pem(cert))
            self.logger.info(f"Certificate saved to {cert_path}")
            
            # Save private key if generated
            if end_entity_private_key:
                key_path = os.path.join(output_dir, f"{filename}.key.pem")
                self.logger.info(f"Saving private key to {key_path}")
                
                key_pem = end_entity_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(key_path, 'wb') as f:
                    f.write(key_pem)
                
                try:
                    os.chmod(key_path, 0o600)
                except (OSError, AttributeError):
                    self.logger.warning("Could not set file permissions (Windows system)")
                
                self.logger.warning("Private key stored unencrypted! Handle with care.")
            
            # Insert into database if configured
            if self.db:
                # Read the certificate PEM
                with open(cert_path, 'rb') as f:
                    cert_pem = f.read()
                cert_pem_str = cert_pem.decode('utf-8')
                
                self._insert_certificate_to_db(
                    cert=cert,
                    cert_pem=cert_pem_str,
                    subject=parsed_subject,
                    issuer=ca_cert.subject.rfc4514_string(),
                    status='valid'
                )
            
            self.logger.info(f"Certificate issued: serial={hex(serial_number)}, "
                           f"subject={parsed_subject}, template={template_name}, "
                           f"sans={san_list}")
            
        except Exception as e:
            self.logger.error(f"Failed to issue certificate: {str(e)}")
            raise
    
    def _sign_csr_with_ca(
        self,
        csr: x509.CertificateSigningRequest,
        issuer_cert: x509.Certificate,
        issuer_key: PrivateKeyTypes,
        validity_days: int,
        is_ca: bool = False,
        pathlen: OptionalType[int] = None
    ) -> x509.Certificate:
        """Sign a CSR with a CA certificate."""
        
        # Generate unique serial number using database if available
        if self.db:
            from micropki.serial import SerialGenerator
            serial_gen = SerialGenerator(self.db_path)
            serial_int, serial_hex = serial_gen.generate_serial()
            serial_number = serial_int
        else:
            serial_number = crypto_utils.generate_serial_number()
        
        not_before = datetime.datetime.now(datetime.timezone.utc)
        not_after = not_before + datetime.timedelta(days=validity_days)
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(csr.public_key())
        
        # Track which extensions we've added
        added_oids = set()
        
        # Add extensions from CSR
        for ext in csr.extensions:
            if is_ca and ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                continue
            builder = builder.add_extension(ext.value, ext.critical)
            added_oids.add(ext.oid)
        
        # Add CA-specific extensions if needed
        if is_ca:
            if ExtensionOID.BASIC_CONSTRAINTS not in added_oids:
                basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
                builder = builder.add_extension(basic_constraints, critical=True)
            
            if ExtensionOID.KEY_USAGE not in added_oids:
                key_usage = x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                )
                builder = builder.add_extension(key_usage, critical=True)
        
        # Add SKI if not present
        if ExtensionOID.SUBJECT_KEY_IDENTIFIER not in added_oids:
            ski = crypto_utils.compute_ski(csr.public_key())
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier(ski),
                critical=False
            )
        
        # Add AKI if not present
        if ExtensionOID.AUTHORITY_KEY_IDENTIFIER not in added_oids:
            issuer_ski = crypto_utils.compute_ski(issuer_key.public_key())
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    x509.SubjectKeyIdentifier(issuer_ski)
                ),
                critical=False
            )
        
        if isinstance(issuer_key, rsa.RSAPrivateKey):
            algorithm = hashes.SHA256()
        else:
            algorithm = hashes.SHA384()
        
        return builder.sign(issuer_key, algorithm, default_backend())
    
    def _create_certificate(
        self,
        public_key: PublicKeyTypes,
        subject_dn: str,
        issuer_cert: x509.Certificate,
        issuer_key: PrivateKeyTypes,
        serial_number: int,
        validity_days: int,
        extensions: List[x509.Extension]
    ) -> x509.Certificate:
        """Create a certificate from components."""
        
        rdns = certificates.parse_dn(subject_dn)
        name_attributes = [x509.NameAttribute(oid, value) for oid, value in rdns]
        name = x509.Name(name_attributes)
        
        not_before = datetime.datetime.now(datetime.timezone.utc)
        not_after = not_before + datetime.timedelta(days=validity_days)
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(public_key)
        
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
        
        ski = crypto_utils.compute_ski(public_key)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )
        
        issuer_ski = crypto_utils.compute_ski(issuer_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier(issuer_ski)
            ),
            critical=False
        )
        
        if isinstance(issuer_key, rsa.RSAPrivateKey):
            algorithm = hashes.SHA256()
        else:
            algorithm = hashes.SHA384()
        
        return builder.sign(issuer_key, algorithm, default_backend())
    
    def _update_policy_with_intermediate(
        self,
        out_dir: str,
        subject: str,
        key_type: str,
        key_size: int,
        validity_days: int,
        pathlen: int,
        issuer_subject: x509.Name
    ) -> None:
        """Update policy document with Intermediate CA information."""
        policy_path = os.path.join(out_dir, 'policy.txt')
        
        with open(policy_path, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "=" * 50 + "\n")
            f.write("INTERMEDIATE CERTIFICATE AUTHORITY\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"CA Name (Subject DN): {subject}\n")
            f.write(f"Issuer (Root CA): {issuer_subject.rfc4514_string()}\n")
            f.write(f"Path Length Constraint: {pathlen}\n")
            f.write(f"Key Algorithm: {key_type.upper()}\n")
            f.write(f"Key Size: {key_size} bits\n")
            f.write(f"Validity Period: {validity_days} days\n")
            f.write(f"Creation Date: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
        
        self.logger.info("Policy document updated with Intermediate CA info")
    
    def _get_cert_filename(self, subject_dn: str, san_list: List[Tuple]) -> str:
        """Generate filename from subject or SAN."""
        from micropki import san as san_module
        
        for part in subject_dn.split(','):
            if 'CN=' in part:
                cn = part.split('=')[1].strip()
                cn = cn.replace(' ', '_').replace('/', '_').replace('\\', '_')
                if cn:
                    return cn
        
        for san_type, value in san_list:
            if san_type == san_module.SANType.DNS:
                return value
        
        return "cert"
    
    def verify_chain(
        self,
        leaf_path: str,
        intermediate_path: OptionalType[str],
        root_path: str
    ) -> Tuple[bool, List[str]]:
        """Verify certificate chain."""
        self.logger.info("Verifying certificate chain")
        
        try:
            from micropki import chain
            
            with open(leaf_path, 'rb') as f:
                leaf = certificates.load_certificate(f.read())
            
            with open(root_path, 'rb') as f:
                root = certificates.load_certificate(f.read())
            
            intermediate = None
            if intermediate_path:
                with open(intermediate_path, 'rb') as f:
                    intermediate = certificates.load_certificate(f.read())
            
            is_valid, errors = chain.validate_certificate_chain(leaf, intermediate, root)
            
            if is_valid:
                self.logger.info("Certificate chain is valid")
            else:
                for err in errors:
                    self.logger.error(err)
            
            return is_valid, errors
            
        except Exception as e:
            self.logger.error(f"Chain verification error: {str(e)}")
            return False, [str(e)]