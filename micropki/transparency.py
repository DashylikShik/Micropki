"""Certificate Transparency simulation log (CTL-2)."""
import os
import hashlib
from datetime import datetime, timezone
from typing import Optional


class CTLog:
    """Certificate Transparency simulation log."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._ensure_file()
    
    def _ensure_file(self):
        """Ensure log file exists."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'a') as f:
                pass
    
    def add_entry(self, serial: str, subject: str, cert_pem: str, issuer: Optional[str] = None) -> bool:
        """Add certificate entry to CT log (CTL-2)."""
        timestamp = datetime.now(timezone.utc).isoformat()
        fingerprint = hashlib.sha256(cert_pem.encode()).hexdigest()
        
        entry = f"{timestamp} | {serial} | {subject} | {fingerprint}"
        if issuer:
            entry += f" | {issuer}"
        
        with open(self.log_path, 'a') as f:
            f.write(entry + '\n')
        return True
    
    def verify_entry(self, serial: str) -> bool:
        """Check if certificate exists in CT log (CTL-2 - audit ct-verify)."""
        if not os.path.exists(self.log_path):
            return False
        with open(self.log_path, 'r') as f:
            return any(serial in line for line in f)
    
    def get_entries(self, limit: int = 100) -> list:
        """Get recent CT log entries."""
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-limit:]]


# Global CT log instance
_ct_log: Optional[CTLog] = None


def init_ct_log(out_dir: str = './pki') -> CTLog:
    """Initialize global CT log."""
    global _ct_log
    audit_dir = os.path.join(out_dir, 'audit')
    log_path = os.path.join(audit_dir, 'ct.log')
    _ct_log = CTLog(log_path)
    return _ct_log


def get_ct_log() -> Optional[CTLog]:
    """Get global CT log."""
    return _ct_log


def ct_add_entry(serial: str, subject: str, cert_pem: str, issuer: Optional[str] = None) -> bool:
    """Add certificate to CT log."""
    if _ct_log:
        return _ct_log.add_entry(serial, subject, cert_pem, issuer)
    return False