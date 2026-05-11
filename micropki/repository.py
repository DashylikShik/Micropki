"""HTTP Repository server for MicroPKI certificates."""
from flask import Flask, request, Response
import os
import threading
from typing import Optional
from datetime import datetime

from micropki import logger
from micropki.database import CertificateDatabase


class RepositoryServer:
    """HTTP server for serving certificates and CRL."""
    
    def __init__(
        self,
        db_path: str,
        cert_dir: str,
        host: str = '127.0.0.1',
        port: int = 8080,
        log_file: Optional[str] = None
    ):
        """
        Initialize repository server.
        
        Args:
            db_path: Path to SQLite database
            cert_dir: Directory containing PEM certificates
            host: Bind address
            port: TCP port
            log_file: Optional log file
        """
        self.db_path = db_path
        self.cert_dir = cert_dir
        self.host = host
        self.port = port
        self.logger = logger.setup_logger(log_file)
        self.app = Flask('micropki-repo')
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Setup Flask routes."""
        
        @self.app.route('/certificate/<serial>', methods=['GET'])
        def get_certificate(serial: str):
            """GET /certificate/<serial> - return certificate PEM."""
            self._log_request()
            
            # Validate hex format
            try:
                int(serial, 16)
            except ValueError:
                return Response(
                    f"Invalid serial number format: {serial}. Expected hexadecimal.",
                    status=400,
                    mimetype='text/plain'
                )
            
            serial = serial.upper()
            db = CertificateDatabase(self.db_path)
            
            cert_data = db.get_certificate_by_serial(serial)
            
            if cert_data:
                return Response(
                    cert_data['cert_pem'],
                    status=200,
                    mimetype='application/x-pem-file'
                )
            else:
                return Response(
                    f"Certificate with serial {serial} not found.",
                    status=404,
                    mimetype='text/plain'
                )
        
        @self.app.route('/ca/<level>', methods=['GET'])
        def get_ca(level: str):
            """GET /ca/root or /ca/intermediate - return CA certificate."""
            self._log_request()
            
            if level == 'root':
                cert_path = os.path.join(self.cert_dir, 'ca.cert.pem')
            elif level == 'intermediate':
                cert_path = os.path.join(self.cert_dir, 'intermediate.cert.pem')
            else:
                return Response(
                    f"Invalid CA level: {level}. Use 'root' or 'intermediate'.",
                    status=400,
                    mimetype='text/plain'
                )
            
            if os.path.exists(cert_path):
                with open(cert_path, 'r', encoding='utf-8') as f:
                    cert_pem = f.read()
                return Response(
                    cert_pem,
                    status=200,
                    mimetype='application/x-pem-file'
                )
            else:
                return Response(
                    f"CA certificate not found: {cert_path}",
                    status=404,
                    mimetype='text/plain'
                )
        
        @self.app.route('/crl', methods=['GET'])
        def get_crl():
            """GET /crl - return CRL (default intermediate, or specify ?ca=root)."""
            self._log_request()
            
            ca_level = request.args.get('ca', 'intermediate')
            
            if ca_level == 'root':
                crl_path = os.path.join(self.cert_dir, '..', 'crl', 'root.crl.pem')
            elif ca_level == 'intermediate':
                crl_path = os.path.join(self.cert_dir, '..', 'crl', 'intermediate.crl.pem')
            else:
                return Response(
                    f"Invalid CA level: {ca_level}. Use 'root' or 'intermediate'.",
                    status=400,
                    mimetype='text/plain'
                )
            
            # Also try direct path in crl directory
            if not os.path.exists(crl_path):
                alt_path = os.path.join(os.path.dirname(self.cert_dir), 'crl', f'{ca_level}.crl.pem')
                if os.path.exists(alt_path):
                    crl_path = alt_path
            
            if os.path.exists(crl_path):
                with open(crl_path, 'rb') as f:
                    crl_data = f.read()
                return Response(
                    crl_data,
                    status=200,
                    mimetype='application/pkix-crl'
                )
            else:
                return Response(
                    f"CRL not found for {ca_level} CA",
                    status=404,
                    mimetype='text/plain'
                )
        
        @self.app.route('/crl/<ca>.crl', methods=['GET'])
        def get_crl_file(ca):
            """GET /crl/root.crl or /crl/intermediate.crl - return CRL file."""
            self._log_request()
            
            if ca not in ['root', 'intermediate']:
                return Response("Invalid CA. Use 'root' or 'intermediate'", status=400)
            
            crl_path = os.path.join(os.path.dirname(self.cert_dir), 'crl', f'{ca}.crl.pem')
            
            if os.path.exists(crl_path):
                with open(crl_path, 'rb') as f:
                    crl_data = f.read()
                return Response(
                    crl_data,
                    status=200,
                    mimetype='application/pkix-crl'
                )
            else:
                return Response(f"CRL not found", status=404)
        
        @self.app.route('/request-cert', methods=['POST'])
        def request_cert():
            """POST /request-cert - submit CSR and receive signed certificate."""
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            template = request.args.get('template', 'server')
            
            self.logger.info(f"[HTTP] Certificate request from {client_ip}, template={template}")
            
            # Get CSR data
            csr_data = request.get_data()
            if not csr_data:
                return Response("Bad Request: No CSR data", status=400)
            
            try:
                # Parse CSR
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import serialization, hashes
                from cryptography.hazmat.primitives.asymmetric import rsa, ec
                
                # Try to load as PEM first
                try:
                    csr = x509.load_pem_x509_csr(csr_data, default_backend())
                except Exception:
                    # Try as DER
                    csr = x509.load_der_x509_csr(csr_data, default_backend())
                
                self.logger.info(f"CSR loaded: subject={csr.subject}")
                
                # Simplified verification - just check that CSR has a public key
                try:
                    public_key = csr.public_key()
                    if public_key is None:
                        raise ValueError("No public key in CSR")
                    self.logger.info(f"CSR public key OK, type: {type(public_key).__name__}")
                except Exception as e:
                    self.logger.error(f"CSR public key error: {e}")
                    return Response("Bad Request: Invalid CSR - no valid public key", status=400)
                
                # Extract subject from CSR
                subject_dn = csr.subject.rfc4514_string()
                if not subject_dn:
                    subject_dn = str(csr.subject)
                
                # Extract SANs from CSR
                san_list = []
                for ext in csr.extensions:
                    if ext.oid.dotted_string == '2.5.29.17':  # SubjectAlternativeName
                        for name in ext.value:
                            if isinstance(name, x509.DNSName):
                                san_list.append(f"dns:{name.value}")
                            elif isinstance(name, x509.IPAddress):
                                san_list.append(f"ip:{name.value}")
                            elif isinstance(name, x509.RFC822Name):
                                san_list.append(f"email:{name.value}")
                            elif isinstance(name, x509.UniformResourceIdentifier):
                                san_list.append(f"uri:{name.value}")
                
                self.logger.info(f"CSR processed: subject={subject_dn}, sans={san_list}")
                
                # For server template, require at least one SAN
                if template == 'server' and not san_list:
                    return Response("Bad Request: Server certificate requires at least one SAN", status=400)
                
                # Load CA certificate and key - используем правильные пути
                ca_cert_path = os.path.join(self.cert_dir, 'intermediate.cert.pem')
                if not os.path.exists(ca_cert_path):
                    ca_cert_path = os.path.join(self.cert_dir, 'ca.cert.pem')
                
                ca_key_path = ca_cert_path.replace('certs', 'private').replace('.cert.pem', '.key.pem')
                
                # Правильные пути к файлам паролей
                project_root = os.path.dirname(os.path.dirname(self.cert_dir))
                ca_pass_file = os.path.join(project_root, 'secrets', 'intermediate.pass')
                if not os.path.exists(ca_pass_file):
                    ca_pass_file = os.path.join(project_root, 'secrets', 'ca.pass')
                
                self.logger.info(f"CA cert path: {ca_cert_path}")
                self.logger.info(f"CA key path: {ca_key_path}")
                self.logger.info(f"CA pass file: {ca_pass_file}")
                
                # Check if files exist
                if not os.path.exists(ca_cert_path):
                    return Response(f"CA certificate not found: {ca_cert_path}", status=500)
                if not os.path.exists(ca_key_path):
                    return Response(f"CA key not found: {ca_key_path}", status=500)
                if not os.path.exists(ca_pass_file):
                    return Response(f"CA passphrase file not found: {ca_pass_file}", status=500)
                
                # Read CA passphrase
                with open(ca_pass_file, 'rb') as f:
                    ca_passphrase = f.read().strip()
                
                # Load CA certificate and key
                with open(ca_cert_path, 'rb') as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                with open(ca_key_path, 'rb') as f:
                    ca_key_data = f.read()
                
                ca_private_key = serialization.load_pem_private_key(
                    ca_key_data,
                    password=ca_passphrase,
                    backend=default_backend()
                )
                
                # Generate serial number
                from micropki import crypto_utils
                serial_number = crypto_utils.generate_serial_number()
                
                # Set validity
                from datetime import datetime, timezone, timedelta
                not_before = datetime.now(timezone.utc)
                not_after = not_before + timedelta(days=365)
                
                # Build certificate
                builder = x509.CertificateBuilder()
                builder = builder.subject_name(csr.subject)
                builder = builder.issuer_name(ca_cert.subject)
                builder = builder.not_valid_before(not_before)
                builder = builder.not_valid_after(not_after)
                builder = builder.serial_number(serial_number)
                builder = builder.public_key(csr.public_key())
                
                # Add Basic Constraints
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True
                )
                
                # Add Key Usage based on template
                from cryptography.x509.oid import ExtendedKeyUsageOID
                
                if template == 'server':
                    key_usage = x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=True, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False,
                        crl_sign=False, encipher_only=False, decipher_only=False
                    )
                    builder = builder.add_extension(key_usage, critical=True)
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                        critical=False
                    )
                elif template == 'client':
                    key_usage = x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=True, key_cert_sign=False,
                        crl_sign=False, encipher_only=False, decipher_only=False
                    )
                    builder = builder.add_extension(key_usage, critical=True)
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False
                    )
                else:  # code_signing
                    key_usage = x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False,
                        crl_sign=False, encipher_only=False, decipher_only=False
                    )
                    builder = builder.add_extension(key_usage, critical=True)
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
                        critical=False
                    )
                
                # Add SAN extension if present
                if san_list:
                    from micropki.san import parse_san_string, SANType, create_san_extension
                    parsed_sans = []
                    for san_str in san_list:
                        san_type, value = parse_san_string(san_str)
                        parsed_sans.append((san_type, value))
                    san_ext = create_san_extension(parsed_sans)
                    builder = builder.add_extension(san_ext.value, critical=False)
                
                # Add SKI
                from micropki import crypto_utils as cu
                ski = cu.compute_ski(csr.public_key())
                builder = builder.add_extension(
                    x509.SubjectKeyIdentifier(ski),
                    critical=False
                )
                
                # Add AKI
                issuer_ski = cu.compute_ski(ca_private_key.public_key())
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                        x509.SubjectKeyIdentifier(issuer_ski)
                    ),
                    critical=False
                )
                
                # Determine signature algorithm
                if isinstance(ca_private_key, rsa.RSAPrivateKey):
                    algorithm = hashes.SHA256()
                else:
                    algorithm = hashes.SHA384()
                
                # Sign certificate
                cert = builder.sign(ca_private_key, algorithm, default_backend())
                
                # Convert to PEM
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                
                # Generate filename from subject CN
                cert_filename = None
                for attr in csr.subject:
                    if attr.oid._name == 'commonName':
                        cn = attr.value.replace(' ', '_').replace('*', 'wildcard')
                        cert_filename = f"{cn}.cert.pem"
                        break
                
                if not cert_filename:
                    cert_filename = f"issued_{datetime.now().strftime('%Y%m%d%H%M%S')}.cert.pem"
                
                cert_path = os.path.join(self.cert_dir, cert_filename)
                with open(cert_path, 'wb') as f:
                    f.write(cert_pem)
                
                # Insert into database
                db = CertificateDatabase(self.db_path)
                cert_data = {
                    'serial_hex': hex(serial_number)[2:].upper(),
                    'serial_int': serial_number,
                    'subject': subject_dn,
                    'issuer': ca_cert.subject.rfc4514_string(),
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'cert_pem': cert_pem.decode('utf-8'),
                    'status': 'valid'
                }
                db.insert_certificate(cert_data)
                
                self.logger.info(f"Certificate issued via API: serial={hex(serial_number)}, template={template}, file={cert_filename}")
                
                # Return the issued certificate
                return Response(
                    cert_pem,
                    status=201,
                    mimetype='application/x-pem-file'
                )
                
            except Exception as e:
                self.logger.error(f"Certificate request error: {str(e)}")
                import traceback
                traceback.print_exc()
                return Response(f"Internal Server Error: {str(e)}", status=500)
        
        @self.app.route('/health', methods=['GET'])
        def health():
            """GET /health - health check endpoint."""
            return Response("OK", status=200, mimetype='text/plain')
        
        @self.app.errorhandler(404)
        def not_found(e):
            return Response("Not Found", status=404, mimetype='text/plain')
        
        @self.app.errorhandler(405)
        def method_not_allowed(e):
            return Response("Method Not Allowed", status=405, mimetype='text/plain')
    
    def _log_request(self) -> None:
        """Log incoming HTTP request."""
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        self.logger.info(f"[HTTP] {request.method} {request.path} from {client_ip}")
    
    def start(self) -> None:
        """Start the HTTP server."""
        self.logger.info(f"Starting repository server on {self.host}:{self.port}")
        self.logger.info(f"  Database: {self.db_path}")
        self.logger.info(f"  Certificate directory: {self.cert_dir}")
        
        # Run Flask
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
    
    def start_in_thread(self) -> threading.Thread:
        """Start server in a background thread."""
        thread = threading.Thread(target=self.start, daemon=True)
        thread.start()
        return thread


def create_test_server(db_path: str, cert_dir: str, port: int = 8081):
    """Create a test server instance (for testing)."""
    return RepositoryServer(db_path, cert_dir, '127.0.0.1', port)