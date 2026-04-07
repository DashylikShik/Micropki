"""HTTP Repository server for MicroPKI certificates."""
from flask import Flask, request, Response
import os
import threading
from typing import Optional

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