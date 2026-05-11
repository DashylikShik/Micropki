"""OCSP Responder HTTP server for MicroPKI."""
from flask import Flask, request, Response
import time
import threading
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
        @self.app.route('/ocsp', methods=['POST'])
        def handle_ocsp():
            start_time = time.time()
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            
            request_data = request.get_data()
            if not request_data:
                return Response("Bad Request: Empty request", status=400)
            
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
                return Response(response_data, status=200, mimetype='application/ocsp-response')
            except Exception as e:
                self.logger.error(f"OCSP request error: {str(e)}")
                return Response("Internal Server Error", status=500)
        
        @self.app.route('/health', methods=['GET'])
        def health():
            return Response("OK", status=200)
    
    def start(self):
        self.logger.info(f"Starting OCSP responder on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)