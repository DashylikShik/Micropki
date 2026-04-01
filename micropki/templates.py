"""Certificate templates for MicroPKI."""
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from micropki import san as san_module


class CertificateTemplate:
    """Base class for certificate templates."""
    
    def __init__(self, name: str):
        self.name = name
    
    def get_extensions(
        self,
        san_list: List[Tuple[san_module.SANType, str]]
    ) -> List[x509.Extension]:
        """Get extensions for this template."""
        raise NotImplementedError
    
    def validate_san(self, san_list: List[Tuple[san_module.SANType, str]]) -> Tuple[bool, Optional[str]]:
        """Validate SAN for this template."""
        return san_module.validate_san_for_template(san_list, self.name)


class ServerTemplate(CertificateTemplate):
    """Server certificate template."""
    
    def __init__(self):
        super().__init__("server")
    
    def get_extensions(
        self,
        san_list: List[Tuple[san_module.SANType, str]]
    ) -> List[x509.Extension]:
        extensions = []
        
        # Basic Constraints: CA=FALSE (critical)
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=basic_constraints
            )
        )
        
        # Key Usage: digitalSignature, keyEncipherment (critical)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=True,
                value=key_usage
            )
        )
        
        # Extended Key Usage: serverAuth
        extended_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.EXTENDED_KEY_USAGE,
                critical=False,
                value=extended_key_usage
            )
        )
        
        # Subject Alternative Name (if provided)
        if san_list:
            extensions.append(san_module.create_san_extension(san_list))
        
        return extensions


class ClientTemplate(CertificateTemplate):
    """Client certificate template."""
    
    def __init__(self):
        super().__init__("client")
    
    def get_extensions(
        self,
        san_list: List[Tuple[san_module.SANType, str]]
    ) -> List[x509.Extension]:
        extensions = []
        
        # Basic Constraints: CA=FALSE (critical)
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=basic_constraints
            )
        )
        
        # Key Usage: digitalSignature (critical)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=True,
                value=key_usage
            )
        )
        
        # Extended Key Usage: clientAuth
        extended_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.EXTENDED_KEY_USAGE,
                critical=False,
                value=extended_key_usage
            )
        )
        
        # Subject Alternative Name (if provided)
        if san_list:
            extensions.append(san_module.create_san_extension(san_list))
        
        return extensions


class CodeSigningTemplate(CertificateTemplate):
    """Code signing certificate template."""
    
    def __init__(self):
        super().__init__("code_signing")
    
    def get_extensions(
        self,
        san_list: List[Tuple[san_module.SANType, str]]
    ) -> List[x509.Extension]:
        extensions = []
        
        # Basic Constraints: CA=FALSE (critical)
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=basic_constraints
            )
        )
        
        # Key Usage: digitalSignature (critical)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=True,
                value=key_usage
            )
        )
        
        # Extended Key Usage: codeSigning
        extended_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.EXTENDED_KEY_USAGE,
                critical=False,
                value=extended_key_usage
            )
        )
        
        # Subject Alternative Name (if provided - optional for code signing)
        if san_list:
            extensions.append(san_module.create_san_extension(san_list))
        
        return extensions


def get_template(template_name: str) -> CertificateTemplate:
    """Get certificate template by name."""
    templates = {
        'server': ServerTemplate(),
        'client': ClientTemplate(),
        'code_signing': CodeSigningTemplate(),
    }
    
    if template_name not in templates:
        raise ValueError(f"Unknown template: {template_name}. Available: server, client, code_signing")
    
    return templates[template_name]