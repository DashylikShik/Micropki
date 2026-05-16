"""Audit logging system with cryptographic integrity (hash chaining)."""
import json
import os
import hashlib
import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict

from micropki import logger


@dataclass
class AuditEntry:
    """Audit log entry structure."""
    timestamp: str
    level: str
    operation: str
    status: str
    message: str
    metadata: Dict[str, Any]
    integrity: Dict[str, str]
    
    def to_json(self) -> str:
        """Convert to canonical JSON string (sorted keys)."""
        return json.dumps(asdict(self), separators=(',', ':'), sort_keys=True)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuditEntry':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls(**data)


class AuditLogger:
    """Audit logger with hash chain integrity."""
    
    def __init__(self, log_path: str, chain_path: str, app_logger=None):
        self.log_path = log_path
        self.chain_path = chain_path
        self.logger = app_logger or logger.setup_logger(None)
        self._ensure_directories()
        self._init_if_needed()
    
    def _ensure_directories(self):
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def _get_last_hash(self) -> str:
        if os.path.exists(self.chain_path):
            with open(self.chain_path, 'r') as f:
                content = f.read().strip()
                if content:
                    return content
        return "0" * 64
    
    def _save_last_hash(self, hash_value: str):
        with open(self.chain_path, 'w') as f:
            f.write(hash_value)
    
    def _compute_entry_hash(self, entry_json: str) -> str:
        data = json.loads(entry_json)
        if 'integrity' in data and 'hash' in data['integrity']:
            del data['integrity']['hash']
        canonical = json.dumps(data, separators=(',', ':'), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def _init_if_needed(self):
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            self._create_first_entry()
    
    def _create_first_entry(self):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = AuditEntry(
            timestamp=now,
            level="AUDIT",
            operation="audit_init",
            status="success",
            message="Audit log initialized",
            metadata={},
            integrity={"prev_hash": "0" * 64, "hash": ""}
        )
        entry_json = entry.to_json()
        entry_hash = self._compute_entry_hash(entry_json)
        entry.integrity["hash"] = entry_hash
        final_json = entry.to_json()
        
        with open(self.log_path, 'a') as f:
            f.write(final_json + '\n')
        self._save_last_hash(entry_hash)
        self.logger.info(f"Audit log initialized at {self.log_path}")
    
    def log(self, level: str, operation: str, status: str, message: str, metadata: Dict = None) -> bool:
        try:
            prev_hash = self._get_last_hash()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            entry = AuditEntry(
                timestamp=now,
                level=level,
                operation=operation,
                status=status,
                message=message,
                metadata=metadata or {},
                integrity={"prev_hash": prev_hash, "hash": ""}
            )
            
            entry_json = entry.to_json()
            entry_hash = self._compute_entry_hash(entry_json)
            entry.integrity["hash"] = entry_hash
            final_json = entry.to_json()
            
            with open(self.log_path, 'a') as f:
                f.write(final_json + '\n')
            self._save_last_hash(entry_hash)
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write audit log: {str(e)}")
            return False
    
    def log_audit(self, operation: str, status: str, message: str, metadata: Dict = None) -> bool:
        return self.log("AUDIT", operation, status, message, metadata)
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        errors = []
        if not os.path.exists(self.log_path):
            errors.append("Audit log file not found")
            return False, errors
        
        prev_hash = "0" * 64
        line_num = 0
        
        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                line_num += 1
                try:
                    entry = AuditEntry.from_json(line)
                    if entry.integrity['prev_hash'] != prev_hash:
                        errors.append(f"Line {line_num}: Hash chain broken")
                    
                    entry_copy = entry.to_json()
                    recomputed_hash = self._compute_entry_hash(entry_copy)
                    if recomputed_hash != entry.integrity['hash']:
                        errors.append(f"Line {line_num}: Entry hash mismatch")
                    prev_hash = entry.integrity['hash']
                except Exception as e:
                    errors.append(f"Line {line_num}: Error - {str(e)}")
        
        stored_hash = self._get_last_hash()
        if stored_hash != prev_hash:
            errors.append(f"Chain file hash mismatch")
        
        return len(errors) == 0, errors


_audit_logger: Optional[AuditLogger] = None


def init_audit_logger(out_dir: str = './pki', app_logger=None) -> AuditLogger:
    global _audit_logger
    audit_dir = os.path.join(out_dir, 'audit')
    log_path = os.path.join(audit_dir, 'audit.log')
    chain_path = os.path.join(audit_dir, 'chain.dat')
    _audit_logger = AuditLogger(log_path, chain_path, app_logger)
    return _audit_logger


def get_audit_logger() -> Optional[AuditLogger]:
    return _audit_logger


def audit_log(operation: str, status: str, message: str, metadata: Dict = None) -> bool:
    if _audit_logger:
        return _audit_logger.log_audit(operation, status, message, metadata)
    return False