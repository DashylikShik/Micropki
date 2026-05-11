"""Client tools for MicroPKI."""
import os
import json
import urllib.request
import urllib.parse
from typing import Optional, List
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from micropki import certificates, logger
from micropki.san import parse_san_string, SANType
from micropki.validation import PathValidator, ValidationStatus
from micropki.revocation_check import RevocationChecker, RevocationStatus


class Client:
    """Client operations for certificate management."""
    
    def __init__(self, log_file: Optional[str] = None):
        """Initialize client."""
        self.logger = logger.setup_logger(log_file)
    
    def generate_csr(
        self,
        subject: str,
        key_type: str = 'rsa',
        key_size: int = 2048,
        san_list: Optional[List[str]] = None,
        out_key: Optional[str] = None,
        out_csr: Optional[str] = None
    ) -> tuple:
        """
        Generate private key and CSR.
        
        Args:
            subject: Distinguished Name
            key_type: 'rsa' or 'ecc'
            key_size: Key size
            san_list: List of SAN strings
            out_key: Output file for private key
            out_csr: Output file for CSR
            
        Returns:
            Tuple of (private_key, csr)
        """
        self.logger.info(f"Generating CSR with subject: {subject}")
        
        # Generate key pair
        if key_type.lower() == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        else:
            curve = ec.SECP256R1() if key_size == 256 else ec.SECP384R1()
            private_key = ec.generate_private_key(curve, backend=default_backend())
        
        # Parse DN
        rdns = certificates.parse_dn(subject)
        name_attributes = [x509.NameAttribute(oid, value) for oid, value in rdns]
        name = x509.Name(name_attributes)
        
        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(name)
        
        # Add SAN extension if provided
        if san_list:
            from micropki.san import create_san_extension
            parsed_sans = []
            for san_str in san_list:
                san_type, value = parse_san_string(san_str)
                parsed_sans.append((san_type, value))
            san_ext = create_san_extension(parsed_sans)
            builder = builder.add_extension(san_ext.value, critical=False)
        
        # Sign CSR
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        # Save private key
        if out_key:
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(out_key, 'wb') as f:
                f.write(key_pem)
            try:
                os.chmod(out_key, 0o600)
            except:
                pass
            self.logger.warning(f"Private key saved (unencrypted): {out_key}")
        
        # Save CSR
        if out_csr:
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            with open(out_csr, 'wb') as f:
                f.write(csr_pem)
            self.logger.info(f"CSR saved: {out_csr}")
        
        return private_key, csr
    
    def request_certificate(
        self,
        csr_path: str,
        template: str,
        ca_url: str,
        out_cert: str,
        api_key: Optional[str] = None
    ) -> x509.Certificate:
        """
        Request certificate from CA via HTTP API.
        
        Args:
            csr_path: Path to CSR file
            template: Certificate template ('server', 'client', 'code_signing')
            ca_url: CA base URL (e.g., http://localhost:8080)
            out_cert: Output file for certificate
            api_key: Optional API key for authentication
            
        Returns:
            Issued certificate
        """
        self.logger.info(f"Requesting certificate from {ca_url}")
        
        # Read CSR
        with open(csr_path, 'rb') as f:
            csr_data = f.read()
        
        # Build URL with template parameter
        url = f"{ca_url.rstrip('/')}/request-cert?template={template}"
        
        # Create request
        req = urllib.request.Request(
            url,
            data=csr_data,
            method='POST'
        )
        
        # Set correct Content-Type
        req.add_header('Content-Type', 'application/x-pem-file')
        req.add_header('Accept', 'application/x-pem-file')
        
        if api_key:
            req.add_header('X-API-Key', api_key)
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                cert_data = response.read()
            
            # Verify we got certificate data
            if not cert_data or not cert_data.startswith(b'-----BEGIN CERTIFICATE-----'):
                self.logger.error(f"Invalid response (not a certificate): {cert_data[:100] if cert_data else 'empty'}")
                raise ValueError("Server did not return a valid certificate")
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Save certificate
            with open(out_cert, 'wb') as f:
                f.write(cert_data)
            self.logger.info(f"Certificate saved: {out_cert}")
            
            return cert
            
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='ignore')
            self.logger.error(f"HTTP Error {e.code}: {e.reason}")
            self.logger.error(f"Response body: {error_body[:500]}")
            raise Exception(f"HTTP Error {e.code}: {e.reason} - {error_body[:200]}")
        except Exception as e:
            self.logger.error(f"Certificate request failed: {str(e)}")
            raise
    
    def validate_certificate(
        self,
        cert_path: str,
        untrusted_paths: Optional[List[str]] = None,
        trusted_paths: Optional[List[str]] = None,
        crl_source: Optional[str] = None,
        ocsp_enabled: bool = False,
        expected_eku: Optional[str] = None
    ) -> dict:
        """
        Validate certificate chain.
        
        Args:
            cert_path: Path to leaf certificate
            untrusted_paths: Paths to intermediate certificates
            trusted_paths: Paths to trusted root certificates
            crl_source: CRL file or URL
            ocsp_enabled: Whether to check OCSP
            expected_eku: Expected Extended Key Usage
            
        Returns:
            Validation result dictionary
        """
        self.logger.info(f"Validating certificate: {cert_path}")
        
        # Load certificates
        with open(cert_path, 'rb') as f:
            leaf = certificates.load_certificate(f.read())
        
        untrusted = []
        if untrusted_paths:
            for path in untrusted_paths:
                with open(path, 'rb') as f:
                    untrusted.append(certificates.load_certificate(f.read()))
        
        trusted = []
        if trusted_paths:
            for path in trusted_paths:
                with open(path, 'rb') as f:
                    trusted.append(certificates.load_certificate(f.read()))
        
        # Validate chain
        validator = PathValidator()
        validator.set_logger(self.logger)
        result = validator.validate_chain(leaf, untrusted, trusted, expected_eku)
        
        # Check revocation if requested
        if crl_source or ocsp_enabled:
            if len(result.chain) >= 2:
                issuer = result.chain[1]
                checker = RevocationChecker()
                status, rev_date, rev_reason, method = checker.check_status(
                    leaf, issuer, crl_source, None if not ocsp_enabled else None
                )
                
                result.steps.append(
                    ValidationStep(
                        name="Revocation Check",
                        status=ValidationStatus.PASSED if status == RevocationStatus.GOOD else ValidationStatus.FAILED,
                        message=f"Status: {status.value} (checked via {method})"
                    )
                )
                if status == RevocationStatus.REVOKED:
                    result.overall_status = ValidationStatus.FAILED
        
        return result.to_dict()
    
    def check_revocation_status(
        self,
        cert_path: str,
        issuer_path: str,
        crl_source: Optional[str] = None,
        ocsp_url: Optional[str] = None
    ) -> dict:
        """
        Check certificate revocation status.
        
        Args:
            cert_path: Path to certificate
            issuer_path: Path to issuer certificate
            crl_source: CRL file or URL (if provided, use CRL)
            ocsp_url: OCSP responder URL (if provided, use OCSP)
            
        Returns:
            Status dictionary
        """
        self.logger.info(f"Checking revocation status for: {cert_path}")
        
        with open(cert_path, 'rb') as f:
            cert = certificates.load_certificate(f.read())
        
        with open(issuer_path, 'rb') as f:
            issuer = certificates.load_certificate(f.read())
        
        checker = RevocationChecker()
        
        # If CRL source is explicitly provided, use CRL directly
        if crl_source:
            self.logger.info(f"Using CRL source: {crl_source}")
            status, rev_date, rev_reason = checker.check_crl(cert, issuer, crl_source)
            method_used = "CRL (explicit)"
        elif ocsp_url:
            self.logger.info(f"Using OCSP URL: {ocsp_url}")
            status, rev_date, rev_reason = checker.check_ocsp(cert, issuer, ocsp_url)
            method_used = "OCSP (explicit)"
        else:
            # Auto-detect: try OCSP first, fallback to CRL
            self.logger.info("Auto-detecting revocation method (OCSP first, then CRL)")
            status, rev_date, rev_reason, method_used = checker.check_status(
                cert, issuer, crl_source, ocsp_url, prefer_ocsp=True
            )
        
        result = {
            'status': status.value,
            'method': method_used if 'method_used' in dir() else (crl_source and "CRL" or "OCSP"),
            'serial': hex(cert.serial_number)[2:].upper(),
            'subject': cert.subject.rfc4514_string(),
        }
        
        if rev_date:
            result['revocation_date'] = rev_date
        if rev_reason:
            result['revocation_reason'] = rev_reason
        
        return result