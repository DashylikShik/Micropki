"""OCSP Responder HTTP server for MicroPKI."""
from flask import Flask, request, Response
import os
import threading
import time
from typing import Optional

from micropki import logger
from micropki.database import CertificateDatabase
from micropki.ocsp import OCSPResponder


class OCSPResponderServer:
    """HTTP server for OCSP responses."""
    
    def __init__(
        self,
        db_path: str,
        ca_cert_path: str,
        responder_cert_path: str,
        responder_key_path: str,
        host: str = '127.0.0.1',
        port: int = 8081,
        cache_ttl: int = 60,
        log_file: Optional[str] = None
    ):
        """
        Initialize OCSP responder server.
        
        Args:
            db_path: Path to SQLite database
            ca_cert_path: Path to CA certificate (issuer)
            responder_cert_path: Path to OCSP responder certificate
            responder_key_path: Path to OCSP responder private key
            host: Bind address
            port: TCP port
            cache_ttl: Cache TTL in seconds
            log_file: Optional log file
        """
        self.db_path = db_path
        self.ca_cert_path = ca_cert_path
        self.responder_cert_path = responder_cert_path
        self.responder_key_path = responder_key_path
        self.host = host
        self.port = port
        self.cache_ttl = cache_ttl
        self.logger = logger.setup_logger(log_file)
        self.app = Flask('micropki-ocsp')
        self.responder = None
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/ocsp', methods=['POST'])
        def handle_ocsp():
            """POST /ocsp - handle OCSP request."""
            start_time = time.time()
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            
            request_data = request.get_data()
            if not request_data:
                self.logger.warning("Empty OCSP request")
                return Response("Bad Request: Empty request", status=400)
            
            # Initialize responder if needed
            if not self.responder:
                db = CertificateDatabase(self.db_path, None)
                self.responder = OCSPResponder(
                    db=db,
                    ca_cert_path=self.ca_cert_path,
                    responder_cert_path=self.responder_cert_path,
                    responder_key_path=self.responder_key_path,
                    cache_ttl=self.cache_ttl,
                    log_file=None
                )
            
            try:
                response_data = self.responder.handle_request(request_data)
                elapsed_ms = (time.time() - start_time) * 1000
                self.logger.info(f"OCSP request from {client_ip} processed in {elapsed_ms:.2f}ms")
                return Response(
                    response_data,
                    status=200,
                    mimetype='application/ocsp-response'
                )
            except Exception as e:
                self.logger.error(f"OCSP request error: {str(e)}")
                return Response("Internal Server Error", status=500)
        
        @self.app.route('/health', methods=['GET'])
        def health():
            """GET /health - health check."""
            return Response("OK", status=200)
        
        @self.app.route('/metrics', methods=['GET'])
        def metrics():
            """GET /metrics - basic metrics."""
            return Response("OK", status=200)
    
    def start(self):
        """Start the OCSP responder server."""
        self.logger.info(f"Starting OCSP responder on {self.host}:{self.port}")
        self.logger.info(f"  Database: {self.db_path}")
        self.logger.info(f"  CA certificate: {self.ca_cert_path}")
        self.logger.info(f"  Responder certificate: {self.responder_cert_path}")
        self.logger.info(f"  Cache TTL: {self.cache_ttl} seconds")
        
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
    
    def start_in_thread(self) -> threading.Thread:
        """Start server in background thread."""
        thread = threading.Thread(target=self.start, daemon=True)
        thread.start()
        return thread


def create_ocsp_test_server(
    db_path: str,
    ca_cert_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    port: int = 8082
) -> OCSPResponderServer:
    """Create test OCSP server instance."""
    return OCSPResponderServer(
        db_path=db_path,
        ca_cert_path=ca_cert_path,
        responder_cert_path=responder_cert_path,
        responder_key_path=responder_key_path,
        host='127.0.0.1',
        port=port,
        cache_ttl=10
    )