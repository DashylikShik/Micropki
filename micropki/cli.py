"""Command-line interface for MicroPKI."""
import argparse
import sys
import os
import json

from micropki.ca import CertificateAuthority


def validate_key_arguments(args):
    """
    Validate key type and size arguments.
    
    Args:
        args: Parsed arguments
        
    Raises:
        argparse.ArgumentTypeError: If validation fails
    """
    key_type = args.key_type.lower()
    key_size = args.key_size
    
    if key_type == 'rsa':
        if key_size != 4096:
            raise argparse.ArgumentTypeError(
                f"RSA key size must be 4096 bits, got {key_size}"
            )
    elif key_type == 'ecc':
        if key_size != 384:
            raise argparse.ArgumentTypeError(
                f"ECC key size must be 384 bits (P-384 curve), got {key_size}"
            )
    else:
        raise argparse.ArgumentTypeError(
            f"Key type must be 'rsa' or 'ecc', got {key_type}"
        )


def positive_int(value):
    """Validate positive integer argument."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer: {value}")
    
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"Value must be positive: {value}")
    
    return ivalue


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MicroPKI - A minimal Public Key Infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Root CA (Sprint 1)
  micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 \\
    --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 7300

  # Intermediate CA (Sprint 2)
  micropki ca issue-intermediate \\
    --root-cert ./pki/certs/ca.cert.pem \\
    --root-key ./pki/private/ca.key.pem \\
    --root-pass-file ./secrets/ca.pass \\
    --subject "CN=Intermediate CA" \\
    --key-type rsa --key-size 4096 \\
    --passphrase-file ./secrets/intermediate.pass \\
    --out-dir ./pki --validity-days 365 --pathlen 0

  # Server Certificate (Sprint 2)
  micropki ca issue-cert \\
    --ca-cert ./pki/certs/intermediate.cert.pem \\
    --ca-key ./pki/private/intermediate.key.pem \\
    --ca-pass-file ./secrets/intermediate.pass \\
    --template server \\
    --subject "CN=example.com" \\
    --san dns:example.com --san dns:www.example.com \\
    --out-dir ./pki/certs --validity-days 365

  # Verify Chain (Sprint 2)
  micropki ca verify-chain \\
    --leaf ./pki/certs/example.com.cert.pem \\
    --intermediate ./pki/certs/intermediate.cert.pem \\
    --root ./pki/certs/ca.cert.pem

  # Database init (Sprint 3)
  micropki db init --db-path ./pki/micropki.db

  # List certificates (Sprint 3)
  micropki ca list-certs --status valid --format table

  # Show certificate by serial (Sprint 3)
  micropki ca show-cert 2A7F...

  # Start repository server (Sprint 3)
  micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs

  # Revoke certificate (Sprint 4)
  micropki ca revoke 2A7F... --reason keyCompromise

  # Generate CRL (Sprint 4)
  micropki ca gen-crl --ca intermediate --next-update 7

  # Issue OCSP responder certificate (Sprint 5)
  micropki ca issue-ocsp-cert \\
    --ca-cert ./pki/certs/intermediate.cert.pem \\
    --ca-key ./pki/private/intermediate.key.pem \\
    --ca-pass-file ./secrets/intermediate.pass \\
    --subject "CN=OCSP Responder" \\
    --san dns:ocsp.example.com

  # Start OCSP responder (Sprint 5)
  micropki ocsp serve \\
    --responder-cert ./pki/certs/ocsp_responder.cert.pem \\
    --responder-key ./pki/certs/ocsp_responder.key.pem \\
    --ca-cert ./pki/certs/intermediate.cert.pem

  # Generate CSR (Sprint 6)
  micropki client gen-csr --subject "CN=app.example.com" --key-type rsa --key-size 2048 \\
    --san dns:app.example.com --out-key ./app.key.pem --out-csr ./app.csr.pem

  # Request certificate from CA (Sprint 6)
  micropki client request-cert --csr ./app.csr.pem --template server \\
    --ca-url http://localhost:8080 --out-cert ./app.cert.pem

  # Validate certificate chain (Sprint 6)
  micropki client validate --cert ./app.cert.pem \\
    --untrusted ./pki/certs/intermediate.cert.pem --trusted ./pki/certs/ca.cert.pem

  # Check revocation status (Sprint 6)
  micropki client check-status --cert ./app.cert.pem --ca-cert ./pki/certs/intermediate.cert.pem
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True
    
    # DATABASE COMMANDS (SPRINT 3)
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command', help='DB commands')
    db_subparsers.required = True
    
    # db init command
    init_db_parser = db_subparsers.add_parser('init', help='Initialize certificate database')
    init_db_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database file path (default: ./pki/micropki.db)')
    init_db_parser.add_argument('--force', action='store_true', help='Force recreate database (drop existing tables)')
    init_db_parser.add_argument('--log-file', help='Optional path to log file')
    
    # REPOSITORY COMMANDS (SPRINT 3)
    repo_parser = subparsers.add_parser('repo', help='Repository server operations')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', help='Repo commands')
    repo_subparsers.required = True
    
    # repo serve command
    serve_parser = repo_subparsers.add_parser('serve', help='Start repository HTTP server')
    serve_parser.add_argument('--host', default='127.0.0.1', help='Bind address (default: 127.0.0.1)')
    serve_parser.add_argument('--port', type=int, default=8080, help='TCP port (default: 8080)')
    serve_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database file path (default: ./pki/micropki.db)')
    serve_parser.add_argument('--cert-dir', default='./pki/certs', help='Certificate directory (default: ./pki/certs)')
    serve_parser.add_argument('--log-file', help='Optional path to log file')
    
    # OCSP COMMANDS (SPRINT 5)
    ocsp_parser = subparsers.add_parser('ocsp', help='OCSP responder operations')
    ocsp_subparsers = ocsp_parser.add_subparsers(dest='ocsp_command', help='OCSP commands')
    ocsp_subparsers.required = True
    
    # ocsp serve command
    ocsp_serve_parser = ocsp_subparsers.add_parser('serve', help='Start OCSP responder server')
    ocsp_serve_parser.add_argument('--host', default='127.0.0.1', help='Bind address (default: 127.0.0.1)')
    ocsp_serve_parser.add_argument('--port', type=int, default=8081, help='TCP port (default: 8081)')
    ocsp_serve_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database file path')
    ocsp_serve_parser.add_argument('--responder-cert', required=True, help='OCSP responder certificate (PEM)')
    ocsp_serve_parser.add_argument('--responder-key', required=True, help='OCSP responder private key (PEM, unencrypted)')
    ocsp_serve_parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate (PEM)')
    ocsp_serve_parser.add_argument('--cache-ttl', type=int, default=60, help='Cache TTL in seconds (default: 60)')
    ocsp_serve_parser.add_argument('--log-file', help='Optional path to log file')
    
    # CLIENT COMMANDS (SPRINT 6)
    client_parser = subparsers.add_parser('client', help='Client operations')
    client_subparsers = client_parser.add_subparsers(dest='client_command', help='Client commands')
    client_subparsers.required = True
    
    # client gen-csr command
    gen_csr_parser = client_subparsers.add_parser('gen-csr', help='Generate private key and CSR')
    gen_csr_parser.add_argument('--subject', required=True, help='Distinguished Name')
    gen_csr_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ecc'])
    gen_csr_parser.add_argument('--key-size', type=int, default=2048, help='Key size (RSA: 2048/4096, ECC: 256/384)')
    gen_csr_parser.add_argument('--san', action='append', default=[], help='SAN (dns:example.com)')
    gen_csr_parser.add_argument('--out-key', default='./key.pem', help='Output private key file')
    gen_csr_parser.add_argument('--out-csr', default='./request.csr.pem', help='Output CSR file')
    gen_csr_parser.add_argument('--log-file', help='Optional log file')
    
    # client request-cert command
    request_cert_parser = client_subparsers.add_parser('request-cert', help='Request certificate from CA')
    request_cert_parser.add_argument('--csr', required=True, help='CSR file path')
    request_cert_parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    request_cert_parser.add_argument('--ca-url', default='http://localhost:8080', help='CA repository URL')
    request_cert_parser.add_argument('--out-cert', default='./cert.pem', help='Output certificate file')
    request_cert_parser.add_argument('--api-key', help='API key for authentication')
    request_cert_parser.add_argument('--log-file', help='Optional log file')
    
    # client validate command
    validate_parser = client_subparsers.add_parser('validate', help='Validate certificate chain')
    validate_parser.add_argument('--cert', required=True, help='Leaf certificate file')
    validate_parser.add_argument('--untrusted', action='append', default=[], help='Intermediate certificate file(s)')
    validate_parser.add_argument('--trusted', action='append', default=[], help='Trusted root certificate file(s)')
    validate_parser.add_argument('--crl', help='CRL file or URL for revocation check')
    validate_parser.add_argument('--ocsp', action='store_true', help='Enable OCSP revocation check')
    validate_parser.add_argument('--format', default='text', choices=['text', 'json'], help='Output format')
    validate_parser.add_argument('--log-file', help='Optional log file')
    
    # client check-status command
    check_status_parser = client_subparsers.add_parser('check-status', help='Check certificate revocation status')
    check_status_parser.add_argument('--cert', required=True, help='Certificate file')
    check_status_parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate file')
    check_status_parser.add_argument('--crl', help='CRL file or URL')
    check_status_parser.add_argument('--ocsp-url', help='OCSP responder URL')
    check_status_parser.add_argument('--format', default='text', choices=['text', 'json'], help='Output format')
    check_status_parser.add_argument('--log-file', help='Optional log file')
    
    # CA COMMANDS
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA commands')
    ca_subparsers.required = True
    
    # SPRINT 1 COMMANDS
    
    # ca init command
    init_parser = ca_subparsers.add_parser('init', help='Initialize a self-signed Root CA')
    init_parser.add_argument(
        '--subject',
        required=True,
        help='Distinguished Name (e.g., "/CN=My Root CA" or "CN=My Root CA,O=Demo,C=US")'
    )
    init_parser.add_argument(
        '--key-type',
        required=True,
        choices=['rsa', 'ecc'],
        help='Key type: rsa or ecc'
    )
    init_parser.add_argument(
        '--key-size',
        required=True,
        type=int,
        help='Key size in bits (4096 for RSA, 384 for ECC)'
    )
    init_parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing the passphrase for private key encryption'
    )
    init_parser.add_argument(
        '--out-dir',
        default='./pki',
        help='Output directory (default: ./pki)'
    )
    init_parser.add_argument(
        '--validity-days',
        default=3650,
        type=positive_int,
        help='Validity period in days (default: 3650 ≈ 10 years)'
    )
    init_parser.add_argument(
        '--log-file',
        help='Optional path to log file (if omitted, logs go to stderr)'
    )
    init_parser.add_argument(
        '--force',
        action='store_true',
        help='Force overwrite existing files without asking'
    )
    init_parser.add_argument(
        '--db-path',
        default='./pki/micropki.db',
        help='Database file path for storing certificate records (default: ./pki/micropki.db)'
    )
    
    # ca verify command
    verify_parser = ca_subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument(
        '--cert',
        required=True,
        help='Path to certificate file to verify'
    )
    verify_parser.add_argument(
        '--log-file',
        help='Optional path to log file'
    )
    
    # ca verify-key command
    verify_key_parser = ca_subparsers.add_parser('verify-key', help='Verify key matches certificate')
    verify_key_parser.add_argument(
        '--key',
        required=True,
        help='Path to encrypted private key file'
    )
    verify_key_parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing the passphrase'
    )
    verify_key_parser.add_argument(
        '--cert',
        required=True,
        help='Path to certificate file'
    )
    verify_key_parser.add_argument(
        '--log-file',
        help='Optional path to log file'
    )
    
    # SPRINT 2 COMMANDS
    
    # ca issue-intermediate command
    intermediate_parser = ca_subparsers.add_parser(
        'issue-intermediate',
        help='Issue an Intermediate CA certificate signed by Root CA'
    )
    intermediate_parser.add_argument('--root-cert', required=True, help='Root CA certificate (PEM)')
    intermediate_parser.add_argument('--root-key', required=True, help='Root CA encrypted private key')
    intermediate_parser.add_argument('--root-pass-file', required=True, help='Root CA passphrase file')
    intermediate_parser.add_argument('--subject', required=True, help='Intermediate CA Distinguished Name')
    intermediate_parser.add_argument('--key-type', required=True, choices=['rsa', 'ecc'])
    intermediate_parser.add_argument('--key-size', required=True, type=int)
    intermediate_parser.add_argument('--passphrase-file', required=True, help='Intermediate CA passphrase file')
    intermediate_parser.add_argument('--out-dir', default='./pki')
    intermediate_parser.add_argument('--validity-days', default=1825, type=positive_int, 
                                      help='Validity in days (default: 1825 ≈ 5 years)')
    intermediate_parser.add_argument('--pathlen', default=0, type=int, 
                                      help='Path length constraint (default: 0)')
    intermediate_parser.add_argument('--log-file')
    intermediate_parser.add_argument('--db-path', default='./pki/micropki.db',
                                      help='Database file path for storing certificate records (default: ./pki/micropki.db)')
    
    # ca issue-cert command
    issue_parser = ca_subparsers.add_parser(
        'issue-cert',
        help='Issue an end-entity certificate'
    )
    issue_parser.add_argument('--ca-cert', required=True, help='CA certificate (PEM)')
    issue_parser.add_argument('--ca-key', required=True, help='CA encrypted private key')
    issue_parser.add_argument('--ca-pass-file', required=True, help='CA passphrase file')
    issue_parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    issue_parser.add_argument('--subject', required=True, help='Distinguished Name')
    issue_parser.add_argument('--san', action='append', default=[], 
                               help='SAN (e.g., dns:example.com). Can be repeated.')
    issue_parser.add_argument('--out-dir', default='./pki/certs')
    issue_parser.add_argument('--validity-days', default=365, type=positive_int)
    issue_parser.add_argument('--csr', help='Optional external CSR file')
    issue_parser.add_argument('--log-file')
    issue_parser.add_argument('--db-path', default='./pki/micropki.db',
                               help='Database file path for storing certificate records (default: ./pki/micropki.db)')
    
    # ca verify-chain command
    chain_parser = ca_subparsers.add_parser(
        'verify-chain',
        help='Verify certificate chain'
    )
    chain_parser.add_argument('--leaf', required=True, help='Leaf certificate')
    chain_parser.add_argument('--intermediate', help='Intermediate certificate')
    chain_parser.add_argument('--root', required=True, help='Root certificate')
    chain_parser.add_argument('--log-file')
    
    # SPRINT 3 COMMANDS
    
    # ca list-certs command
    list_parser = ca_subparsers.add_parser('list-certs', help='List certificates in database')
    list_parser.add_argument('--status', choices=['valid', 'revoked', 'expired'], 
                              help='Filter by status')
    list_parser.add_argument('--format', default='table', choices=['table', 'json', 'csv'], 
                              help='Output format (default: table)')
    list_parser.add_argument('--limit', type=int, default=50, 
                              help='Maximum number of certificates (default: 50)')
    list_parser.add_argument('--db-path', default='./pki/micropki.db', 
                              help='Database file path (default: ./pki/micropki.db)')
    list_parser.add_argument('--log-file', help='Optional path to log file')
    
    # ca show-cert command
    show_parser = ca_subparsers.add_parser('show-cert', help='Show certificate by serial number')
    show_parser.add_argument('serial', help='Certificate serial number (hex)')
    show_parser.add_argument('--db-path', default='./pki/micropki.db', 
                              help='Database file path (default: ./pki/micropki.db)')
    show_parser.add_argument('--log-file', help='Optional path to log file')
    
    # SPRINT 4 COMMANDS
    
    # ca revoke command
    revoke_parser = ca_subparsers.add_parser('revoke', help='Revoke a certificate')
    revoke_parser.add_argument('serial', help='Certificate serial number (hex)')
    revoke_parser.add_argument('--reason', default='unspecified',
                                choices=['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                                        'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
                                        'privilegeWithdrawn', 'aACompromise'],
                                help='Revocation reason (default: unspecified)')
    revoke_parser.add_argument('--force', action='store_true', help='Skip confirmation prompts')
    revoke_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database file path')
    revoke_parser.add_argument('--log-file', help='Optional path to log file')
    
    # ca gen-crl command
    gen_crl_parser = ca_subparsers.add_parser('gen-crl', help='Generate Certificate Revocation List')
    gen_crl_parser.add_argument('--ca', required=True, choices=['root', 'intermediate'],
                                 help='CA to generate CRL for (root or intermediate)')
    gen_crl_parser.add_argument('--next-update', type=int, default=7,
                                 help='Days until next CRL update (default: 7)')
    gen_crl_parser.add_argument('--out-file', help='Output file path (optional)')
    gen_crl_parser.add_argument('--out-dir', default='./pki', help='Output directory')
    gen_crl_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database file path')
    gen_crl_parser.add_argument('--log-file', help='Optional path to log file')
    
    # SPRINT 5 COMMANDS
    
    # ca issue-ocsp-cert command
    ocsp_cert_parser = ca_subparsers.add_parser(
        'issue-ocsp-cert',
        help='Issue an OCSP responder certificate'
    )
    ocsp_cert_parser.add_argument('--ca-cert', required=True, help='CA certificate (PEM)')
    ocsp_cert_parser.add_argument('--ca-key', required=True, help='CA encrypted private key')
    ocsp_cert_parser.add_argument('--ca-pass-file', required=True, help='CA passphrase file')
    ocsp_cert_parser.add_argument('--subject', required=True, help='OCSP responder Distinguished Name')
    ocsp_cert_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ecc'],
                                   help='Key type (default: rsa)')
    ocsp_cert_parser.add_argument('--key-size', type=int, default=2048,
                                   help='Key size (RSA: 2048+, ECC: 256/384) (default: 2048)')
    ocsp_cert_parser.add_argument('--san', action='append', default=[],
                                   help='SAN (e.g., dns:ocsp.example.com)')
    ocsp_cert_parser.add_argument('--out-dir', default='./pki/certs',
                                   help='Output directory (default: ./pki/certs)')
    ocsp_cert_parser.add_argument('--validity-days', type=int, default=365,
                                   help='Validity period in days (default: 365)')
    ocsp_cert_parser.add_argument('--log-file', help='Optional path to log file')
    ocsp_cert_parser.add_argument('--db-path', default='./pki/micropki.db',
                                   help='Database file path (default: ./pki/micropki.db)')
    
    args = parser.parse_args()
    
    try:
        # SPRINT 3: DB COMMANDS
        if args.command == 'db':
            from micropki.database import CertificateDatabase
            
            if args.db_command == 'init':
                db = CertificateDatabase(args.db_path, getattr(args, 'log_file', None))
                db.init_schema(force=args.force)
                print(f"[OK] Database initialized successfully: {args.db_path}")
        
        # SPRINT 3: REPOSITORY COMMANDS
        elif args.command == 'repo':
            from micropki.repository import RepositoryServer
            
            if args.repo_command == 'serve':
                server = RepositoryServer(
                    db_path=args.db_path,
                    cert_dir=args.cert_dir,
                    host=args.host,
                    port=args.port,
                    log_file=args.log_file
                )
                print(f"[INFO] Starting repository server on {args.host}:{args.port}")
                print(f"[INFO] Database: {args.db_path}")
                print(f"[INFO] Certificate directory: {args.cert_dir}")
                print("[INFO] Press Ctrl+C to stop")
                try:
                    server.start()
                except KeyboardInterrupt:
                    print("\n[INFO] Server stopped")
        
        # SPRINT 5: OCSP COMMANDS
        elif args.command == 'ocsp':
            from micropki.ocsp_responder import OCSPResponderServer
            
            if args.ocsp_command == 'serve':
                server = OCSPResponderServer(
                    db_path=args.db_path,
                    ca_cert_path=args.ca_cert,
                    responder_cert_path=args.responder_cert,
                    responder_key_path=args.responder_key,
                    host=args.host,
                    port=args.port,
                    cache_ttl=args.cache_ttl,
                    log_file=args.log_file
                )
                print(f"[INFO] Starting OCSP responder on {args.host}:{args.port}")
                print(f"[INFO] Database: {args.db_path}")
                print(f"[INFO] CA certificate: {args.ca_cert}")
                print(f"[INFO] Responder certificate: {args.responder_cert}")
                print("[INFO] Press Ctrl+C to stop")
                try:
                    server.start()
                except KeyboardInterrupt:
                    print("\n[INFO] OCSP server stopped")
        
        # SPRINT 6: CLIENT COMMANDS
        elif args.command == 'client':
            from micropki.client import Client
            
            client = Client(log_file=getattr(args, 'log_file', None))
            
            if args.client_command == 'gen-csr':
                # Generate CSR
                client.generate_csr(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    san_list=args.san,
                    out_key=args.out_key,
                    out_csr=args.out_csr
                )
                print(f"[OK] CSR generated successfully")
                print(f"  Private key: {args.out_key} (UNENCRYPTED - handle with care)")
                print(f"  CSR: {args.out_csr}")
            
            elif args.client_command == 'request-cert':
                # Request certificate from CA
                cert = client.request_certificate(
                    csr_path=args.csr,
                    template=args.template,
                    ca_url=args.ca_url,
                    out_cert=args.out_cert,
                    api_key=args.api_key
                )
                print(f"[OK] Certificate issued successfully")
                print(f"  Certificate: {args.out_cert}")
                print(f"  Subject: {cert.subject.rfc4514_string()}")
                print(f"  Serial: {hex(cert.serial_number)[2:].upper()}")
            
            elif args.client_command == 'validate':
                # Validate certificate chain
                result = client.validate_certificate(
                    cert_path=args.cert,
                    untrusted_paths=args.untrusted if args.untrusted else None,
                    trusted_paths=args.trusted if args.trusted else None,
                    crl_source=args.crl,
                    ocsp_enabled=args.ocsp
                )
                
                if args.format == 'json':
                    print(json.dumps(result, indent=2))
                else:
                    print(f"\nCertificate Validation Result")
                    print("=" * 50)
                    print(f"Overall Status: {result['overall_status'].upper()}")
                    print("\nValidation Steps:")
                    for step in result['steps']:
                        status_icon = "✅" if step['status'] == 'passed' else "❌"
                        print(f"  {status_icon} {step['name']}: {step['status']}")
                        if step.get('message'):
                            print(f"      {step['message']}")
                
                if result['overall_status'] != 'passed':
                    sys.exit(1)
            
            elif args.client_command == 'check-status':
                # Check revocation status
                result = client.check_revocation_status(
                    cert_path=args.cert,
                    issuer_path=args.ca_cert,
                    crl_source=args.crl,
                    ocsp_url=args.ocsp_url
                )
                
                if args.format == 'json':
                    print(json.dumps(result, indent=2))
                else:
                    print(f"\nRevocation Status Check")
                    print("=" * 50)
                    print(f"Certificate: {result['subject']}")
                    print(f"Serial: {result['serial']}")
                    print(f"Status: {result['status'].upper()}")
                    print(f"Method: {result['method']}")
                    if result.get('revocation_date'):
                        print(f"Revocation Date: {result['revocation_date']}")
                    if result.get('revocation_reason'):
                        print(f"Revocation Reason: {result['revocation_reason']}")
        
        # CA COMMANDS
        elif args.command == 'ca':
            # Create CA instance with database support if db_path provided
            db_path = getattr(args, 'db_path', None)
            ca = CertificateAuthority(log_file=getattr(args, 'log_file', None), db_path=db_path)
            
            # SPRINT 1 COMMANDS HANDLERS
            
            if args.ca_command == 'init':
                # Validate key arguments
                validate_key_arguments(args)
                
                # Validate passphrase file exists
                if not os.path.exists(args.passphrase_file):
                    print(f"Error: Passphrase file not found: {args.passphrase_file}", file=sys.stderr)
                    sys.exit(1)
                
                # Check if files already exist
                private_key_path = os.path.join(args.out_dir, 'private', 'ca.key.pem')
                cert_path = os.path.join(args.out_dir, 'certs', 'ca.cert.pem')
                
                files_to_overwrite = []
                if os.path.exists(private_key_path):
                    files_to_overwrite.append(private_key_path)
                if os.path.exists(cert_path):
                    files_to_overwrite.append(cert_path)
                
                # If files exist and --force not used, ask for confirmation
                if files_to_overwrite and not args.force:
                    print("[WARNING] The following files already exist:", file=sys.stderr)
                    for f in files_to_overwrite:
                        print(f"  - {f}", file=sys.stderr)
                    print()
                    
                    response = input("Do you want to overwrite these files? (y/N): ").strip().lower()
                    
                    if response != 'y' and response != 'yes':
                        print("[CANCELLED] Operation cancelled.", file=sys.stderr)
                        sys.exit(0)
                    else:
                        print("Proceeding with overwrite...")
                
                # Initialize Root CA
                ca.init_root_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days
                )
                
                print(f"[OK] Root CA initialized successfully in {args.out_dir}")
                
            elif args.ca_command == 'verify':
                # Verify certificate
                if not os.path.exists(args.cert):
                    print(f"Error: Certificate file not found: {args.cert}", file=sys.stderr)
                    sys.exit(1)
                
                if ca.verify(args.cert):
                    print(f"[OK] Certificate verification successful: {args.cert}")
                else:
                    print(f"[FAILED] Certificate verification failed: {args.cert}", file=sys.stderr)
                    sys.exit(1)
            
            elif args.ca_command == 'verify-key':
                # Verify key matches certificate
                if not os.path.exists(args.key):
                    print(f"Error: Key file not found: {args.key}", file=sys.stderr)
                    sys.exit(1)
                if not os.path.exists(args.cert):
                    print(f"Error: Certificate file not found: {args.cert}", file=sys.stderr)
                    sys.exit(1)
                if not os.path.exists(args.passphrase_file):
                    print(f"Error: Passphrase file not found: {args.passphrase_file}", file=sys.stderr)
                    sys.exit(1)
                
                # Read passphrase
                with open(args.passphrase_file, 'rb') as f:
                    passphrase = f.read().strip()
                
                if ca.verify_key_match(args.key, passphrase, args.cert):
                    print(f"[OK] Key matches certificate")
                else:
                    print(f"[FAILED] Key does not match certificate", file=sys.stderr)
                    sys.exit(1)
            
            # SPRINT 2 COMMANDS HANDLERS
            
            elif args.ca_command == 'issue-intermediate':
                # Validate key arguments
                validate_key_arguments(args)
                
                # Check files exist
                for f in [args.root_cert, args.root_key, args.root_pass_file]:
                    if not os.path.exists(f):
                        print(f"[ERROR] File not found: {f}", file=sys.stderr)
                        sys.exit(1)
                
                # Check passphrase file
                if not os.path.exists(args.passphrase_file):
                    print(f"[ERROR] Passphrase file not found: {args.passphrase_file}", file=sys.stderr)
                    sys.exit(1)
                
                # Issue Intermediate CA
                ca.issue_intermediate_ca(
                    root_cert_path=args.root_cert,
                    root_key_path=args.root_key,
                    root_passphrase_file=args.root_pass_file,
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    intermediate_passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen
                )
                
                print(f"[OK] Intermediate CA issued successfully in {args.out_dir}")
            
            elif args.ca_command == 'issue-cert':
                # Validate template and SANs
                if args.template == 'server' and not args.san:
                    print("[ERROR] Server certificate must have at least one SAN", file=sys.stderr)
                    sys.exit(1)
                
                # Check files exist
                for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                    if not os.path.exists(f):
                        print(f"[ERROR] File not found: {f}", file=sys.stderr)
                        sys.exit(1)
                
                if args.csr and not os.path.exists(args.csr):
                    print(f"[ERROR] CSR file not found: {args.csr}", file=sys.stderr)
                    sys.exit(1)
                
                # Issue certificate
                ca.issue_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_passphrase_file=args.ca_pass_file,
                    template_name=args.template,
                    subject=args.subject,
                    san_list=args.san,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    csr_path=args.csr
                )
                
                print(f"[OK] Certificate issued successfully")
            
            elif args.ca_command == 'verify-chain':
                # Verify chain
                is_valid, errors = ca.verify_chain(
                    leaf_path=args.leaf,
                    intermediate_path=args.intermediate,
                    root_path=args.root
                )
                
                if is_valid:
                    print("[OK] Certificate chain is valid")
                else:
                    print("[FAILED] Certificate chain validation failed:", file=sys.stderr)
                    for err in errors:
                        print(f"  - {err}", file=sys.stderr)
                    sys.exit(1)
            
            # SPRINT 3 COMMANDS HANDLERS
            
            elif args.ca_command == 'list-certs':
                from micropki.database import CertificateDatabase
                
                db = CertificateDatabase(args.db_path, getattr(args, 'log_file', None))
                db.update_expired_status()
                
                certs = db.list_certificates(status=args.status, limit=args.limit)
                
                if args.format == 'json':
                    import json
                    output = []
                    for cert in certs:
                        output.append({
                            'serial': cert['serial_hex'],
                            'subject': cert['subject'],
                            'issuer': cert['issuer'],
                            'not_before': cert['not_before'],
                            'not_after': cert['not_after'],
                            'status': cert['status']
                        })
                    print(json.dumps(output, indent=2))
                
                elif args.format == 'csv':
                    print("SERIAL,SUBJECT,ISSUER,NOT_BEFORE,NOT_AFTER,STATUS")
                    for cert in certs:
                        print(f"{cert['serial_hex']},{cert['subject']},{cert['issuer']},"
                              f"{cert['not_before']},{cert['not_after']},{cert['status']}")
                
                else:
                    print(f"{'SERIAL':<20} {'SUBJECT':<35} {'STATUS':<10} {'EXPIRES':<20}")
                    print("=" * 100)
                    for cert in certs:
                        serial = cert['serial_hex'][:18] + "..." if len(cert['serial_hex']) > 18 else cert['serial_hex']
                        subject = cert['subject'][:32] + "..." if len(cert['subject']) > 32 else cert['subject']
                        expires = cert['not_after'][:10]
                        print(f"{serial:<20} {subject:<35} {cert['status']:<10} {expires:<20}")
                    print(f"Total: {len(certs)} certificates")
            
            elif args.ca_command == 'show-cert':
                from micropki.database import CertificateDatabase
                
                db = CertificateDatabase(args.db_path, getattr(args, 'log_file', None))
                cert = db.get_certificate_by_serial(args.serial)
                
                if cert:
                    print(cert['cert_pem'])
                else:
                    print(f"[ERROR] Certificate with serial {args.serial} not found", file=sys.stderr)
                    sys.exit(1)
            
            # SPRINT 4 COMMANDS HANDLERS
            
            elif args.ca_command == 'revoke':
                from micropki.database import CertificateDatabase
                from micropki.revocation import get_reason_code
                
                db = CertificateDatabase(args.db_path, getattr(args, 'log_file', None))
                
                cert = db.get_certificate_by_serial(args.serial)
                if not cert:
                    print(f"[ERROR] Certificate with serial {args.serial} not found", file=sys.stderr)
                    sys.exit(1)
                
                if cert['status'] == 'revoked':
                    print(f"[WARNING] Certificate {args.serial} is already revoked", file=sys.stderr)
                    sys.exit(0)
                
                if not args.force:
                    print(f"Certificate to revoke:")
                    print(f"  Serial: {cert['serial_hex']}")
                    print(f"  Subject: {cert['subject']}")
                    print(f"  Issuer: {cert['issuer']}")
                    print(f"  Reason: {args.reason}")
                    print()
                    response = input("Are you sure you want to revoke this certificate? (y/N): ").strip().lower()
                    if response != 'y' and response != 'yes':
                        print("[CANCELLED] Revocation cancelled.")
                        sys.exit(0)
                
                try:
                    reason_code = get_reason_code(args.reason)
                    success = db.revoke_certificate(args.serial, args.reason)
                    if success:
                        print(f"[OK] Certificate {args.serial} revoked successfully (reason: {args.reason})")
                    else:
                        print(f"[ERROR] Failed to revoke certificate", file=sys.stderr)
                        sys.exit(1)
                except ValueError as e:
                    print(f"[ERROR] {str(e)}", file=sys.stderr)
                    sys.exit(1)
            
            elif args.ca_command == 'gen-crl':
                from micropki.database import CertificateDatabase
                from micropki.revocation import CRLGenerator
                from micropki import certificates
                
                if args.ca == 'root':
                    ca_cert_path = os.path.join(args.out_dir, 'certs', 'ca.cert.pem')
                    ca_key_path = os.path.join(args.out_dir, 'private', 'ca.key.pem')
                    ca_pass_file = os.path.join(os.path.dirname(args.out_dir), 'secrets', 'ca.pass')
                    default_out = os.path.join(args.out_dir, 'crl', 'root.crl.pem')
                else:
                    ca_cert_path = os.path.join(args.out_dir, 'certs', 'intermediate.cert.pem')
                    ca_key_path = os.path.join(args.out_dir, 'private', 'intermediate.key.pem')
                    ca_pass_file = os.path.join(os.path.dirname(args.out_dir), 'secrets', 'intermediate.pass')
                    default_out = os.path.join(args.out_dir, 'crl', 'intermediate.crl.pem')
                
                if not os.path.exists(ca_cert_path):
                    print(f"[ERROR] CA certificate not found: {ca_cert_path}", file=sys.stderr)
                    sys.exit(1)
                if not os.path.exists(ca_key_path):
                    print(f"[ERROR] CA private key not found: {ca_key_path}", file=sys.stderr)
                    sys.exit(1)
                if not os.path.exists(ca_pass_file):
                    print(f"[ERROR] CA passphrase file not found: {ca_pass_file}", file=sys.stderr)
                    sys.exit(1)
                
                crl_dir = os.path.join(args.out_dir, 'crl')
                os.makedirs(crl_dir, exist_ok=True)
                
                with open(ca_pass_file, 'rb') as f:
                    ca_passphrase = f.read().strip()
                
                with open(ca_cert_path, 'rb') as f:
                    ca_cert = certificates.load_certificate(f.read())
                ca_subject_dn = ca_cert.subject.rfc4514_string()
                
                db = CertificateDatabase(args.db_path, getattr(args, 'log_file', None))
                crl_gen = CRLGenerator(
                    db=db,
                    ca_cert_path=ca_cert_path,
                    ca_key_path=ca_key_path,
                    ca_passphrase=ca_passphrase,
                    log_file=getattr(args, 'log_file', None)
                )
                
                out_file = args.out_file if args.out_file else default_out
                
                crl_gen.generate_crl(
                    ca_subject=ca_subject_dn,
                    next_update_days=args.next_update,
                    out_file=out_file
                )
                
                print(f"[OK] CRL generated for {args.ca} CA")
                print(f"  File: {out_file}")
                print(f"  Next update: {args.next_update} days")
            
            # SPRINT 5 COMMANDS HANDLERS
            
            elif args.ca_command == 'issue-ocsp-cert':
                # Validate key size for OCSP
                if args.key_type == 'rsa' and args.key_size < 2048:
                    print(f"[WARNING] RSA key size {args.key_size} is less than recommended 2048", file=sys.stderr)
                
                # Check files exist
                for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                    if not os.path.exists(f):
                        print(f"[ERROR] File not found: {f}", file=sys.stderr)
                        sys.exit(1)
                
                # Issue OCSP certificate
                ca.issue_ocsp_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_passphrase_file=args.ca_pass_file,
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    san_list=args.san,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days
                )
    
    except Exception as e:
        print(f"[ERROR] {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()