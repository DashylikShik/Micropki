"""Command-line interface for MicroPKI."""
import argparse
import sys
import os

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
  micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 \\
    --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 7300 \\
    --log-file ./logs/ca-init.log
  
  micropki ca verify --cert ./pki/certs/ca.cert.pem
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True
    
    # CA commands
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA commands')
    ca_subparsers.required = True
    
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
    
    # ca verify-key command (for TEST-2 and TEST-3)
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
    
    args = parser.parse_args()
    
    try:
        if args.command == 'ca':
            ca = CertificateAuthority(log_file=getattr(args, 'log_file', None))
            
            if args.ca_command == 'init':
                # Validate key arguments
                validate_key_arguments(args)
                
                # Validate passphrase file exists
                if not os.path.exists(args.passphrase_file):
                    print(f"Error: Passphrase file not found: {args.passphrase_file}", file=sys.stderr)
                    sys.exit(1)
                
                # Check if output directory exists and has files (optional --force)
                if os.path.exists(args.out_dir):
                    private_key_path = os.path.join(args.out_dir, 'private', 'ca.key.pem')
                    cert_path = os.path.join(args.out_dir, 'certs', 'ca.cert.pem')
                    
                    if os.path.exists(private_key_path) or os.path.exists(cert_path):
                        print(f"Warning: Output directory {args.out_dir} already contains CA files.", file=sys.stderr)
                        print("Use --force to overwrite (not implemented in Sprint 1)", file=sys.stderr)
                        # В Sprint 1 просто продолжаем (overwrite)
                
                # Initialize Root CA
                ca.init_root_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days
                )
                
                print(f" Root CA initialized successfully in {args.out_dir}")
                
            elif args.ca_command == 'verify':
                # Verify certificate
                if not os.path.exists(args.cert):
                    print(f"Error: Certificate file not found: {args.cert}", file=sys.stderr)
                    sys.exit(1)
                
                if ca.verify(args.cert):
                    print(f" Certificate verification successful: {args.cert}")
                else:
                    print(f" Certificate verification failed: {args.cert}", file=sys.stderr)
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
                    print(f" Key matches certificate")
                else:
                    print(f" Key does not match certificate", file=sys.stderr)
                    sys.exit(1)
    
    except Exception as e:
        print(f" Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()