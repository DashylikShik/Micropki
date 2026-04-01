"""Subject Alternative Name (SAN) handling for MicroPKI."""
import ipaddress
from typing import List, Tuple, Optional
from enum import Enum

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


class SANType(Enum):
    """Types of Subject Alternative Names."""
    DNS = "dns"
    IP = "ip"
    EMAIL = "email"
    URI = "uri"


class SANParseError(Exception):
    """Error parsing SAN string."""
    pass


def parse_san_string(san_str: str) -> Tuple[SANType, str]:
    """
    Parse SAN string in format "type:value".
    
    Args:
        san_str: String like "dns:example.com" or "ip:192.168.1.1"
        
    Returns:
        Tuple of (SANType, value)
        
    Raises:
        SANParseError: If format is invalid
    """
    if ':' not in san_str:
        raise SANParseError(f"Invalid SAN format: {san_str}. Expected 'type:value'")
    
    type_part, value = san_str.split(':', 1)
    type_part = type_part.lower().strip()
    
    if type_part == 'dns':
        return (SANType.DNS, value)
    elif type_part == 'ip':
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise SANParseError(f"Invalid IP address: {value}")
        return (SANType.IP, value)
    elif type_part == 'email':
        if '@' not in value:
            raise SANParseError(f"Invalid email address: {value}")
        return (SANType.EMAIL, value)
    elif type_part == 'uri':
        return (SANType.URI, value)
    else:
        raise SANParseError(f"Unknown SAN type: {type_part}. Expected: dns, ip, email, uri")


def create_san_extension(san_list: List[Tuple[SANType, str]]) -> x509.Extension:
    """
    Create SubjectAlternativeName extension from list of SANs.
    
    Args:
        san_list: List of (SANType, value) tuples
        
    Returns:
        SubjectAlternativeName extension
    """
    general_names = []
    
    for san_type, value in san_list:
        if san_type == SANType.DNS:
            general_names.append(x509.DNSName(value))
        elif san_type == SANType.IP:
            general_names.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif san_type == SANType.EMAIL:
            general_names.append(x509.RFC822Name(value))
        elif san_type == SANType.URI:
            general_names.append(x509.UniformResourceIdentifier(value))
    
    return x509.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        critical=False,
        value=x509.SubjectAlternativeName(general_names)
    )


def validate_san_for_template(
    san_list: List[Tuple[SANType, str]],
    template: str
) -> Tuple[bool, Optional[str]]:
    """
    Validate SAN list for a given certificate template.
    
    Args:
        san_list: List of SANs
        template: 'server', 'client', or 'code_signing'
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not san_list:
        if template == 'server':
            return (False, "Server certificate must have at least one DNS or IP SAN")
        return (True, None)
    
    for san_type, value in san_list:
        if template == 'server':
            if san_type not in [SANType.DNS, SANType.IP]:
                return (False, f"Server certificate cannot have {san_type.value} SAN")
        
        elif template == 'client':
            if san_type not in [SANType.EMAIL, SANType.DNS]:
                return (False, f"Client certificate cannot have {san_type.value} SAN")
        
        elif template == 'code_signing':
            if san_type not in [SANType.DNS, SANType.URI]:
                return (False, f"Code signing certificate cannot have {san_type.value} SAN")
    
    return (True, None)