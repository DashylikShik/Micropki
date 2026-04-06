"""Database handling for MicroPKI certificate storage."""
import sqlite3
import os
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone

from micropki import logger


class CertificateDatabase:
    """SQLite database for storing issued certificates."""
    
    def __init__(self, db_path: str, log_file: Optional[str] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
            log_file: Optional path to log file
        """
        self.db_path = db_path
        self.logger = logger.setup_logger(log_file)
        self._ensure_db_directory()
    
    def _ensure_db_directory(self) -> None:
        """Ensure directory for database exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_schema(self, force: bool = False) -> None:
        """
        Initialize database schema.
        
        Args:
            force: If True, drop existing tables and recreate
        """
        self.logger.info(f"Initializing database schema: {self.db_path}")
        
        with self._get_connection() as conn:
            if force:
                conn.execute("DROP TABLE IF EXISTS certificates")
                conn.execute("DROP TABLE IF EXISTS serial_tracker")
                self.logger.info("Dropped existing tables")
            
            # Certificates table - using TEXT for serial_int to avoid 64-bit overflow
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hex TEXT UNIQUE NOT NULL,
                    serial_int TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revocation_reason TEXT,
                    revocation_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Serial tracker table - using TEXT for serial_int
            conn.execute("""
                CREATE TABLE IF NOT EXISTS serial_tracker (
                    serial_int TEXT PRIMARY KEY,
                    serial_hex TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_not_after ON certificates(not_after)")
            
            self.logger.info("Database schema initialized successfully")

    def insert_certificate(self, cert_data: Dict[str, Any]) -> int:
        """
        Insert a certificate into the database.
        
        Args:
            cert_data: Dictionary with certificate fields:
                - serial_hex: hex string
                - serial_int: integer (will be converted to string for SQLite)
                - subject: DN string
                - issuer: DN string
                - not_before: ISO 8601 string
                - not_after: ISO 8601 string
                - cert_pem: PEM certificate text
                - status: 'valid', 'revoked', 'expired'
        
        Returns:
            Row ID of inserted record
        
        Raises:
            sqlite3.IntegrityError: If duplicate serial number
        """
        now = datetime.now(timezone.utc).isoformat()
        
        # Convert serial_int to string to avoid 64-bit overflow
        serial_int_str = str(cert_data['serial_int'])
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO certificates (
                    serial_hex, serial_int, subject, issuer, not_before, not_after,
                    cert_pem, status, revocation_reason, revocation_date, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cert_data['serial_hex'],
                serial_int_str,
                cert_data['subject'],
                cert_data['issuer'],
                cert_data['not_before'],
                cert_data['not_after'],
                cert_data['cert_pem'],
                cert_data['status'],
                None,  # revocation_reason
                None,  # revocation_date
                now
            ))
            
            self.logger.info(f"Certificate inserted: serial={cert_data['serial_hex']}, "
                        f"subject={cert_data['subject']}")
            return cursor.lastrowid
    
    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve certificate by serial number (hex).
        
        Args:
            serial_hex: Hexadecimal serial number (case-insensitive)
        
        Returns:
            Dictionary with certificate data or None if not found
        """
        serial_hex = serial_hex.upper()
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM certificates WHERE serial_hex = ?
            """, (serial_hex,))
            
            row = cursor.fetchone()
            
            if row:
                self.logger.info(f"Certificate retrieved: serial={serial_hex}")
                return dict(row)
            else:
                self.logger.warning(f"Certificate not found: serial={serial_hex}")
                return None
    
    def list_certificates(
        self,
        status: Optional[str] = None,
        issuer: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List certificates with optional filters.
        
        Args:
            status: Filter by status ('valid', 'revoked', 'expired')
            issuer: Filter by issuer DN
            limit: Maximum number of records
            offset: Number of records to skip
        
        Returns:
            List of certificate dictionaries
        """
        query = "SELECT * FROM certificates"
        params = []
        conditions = []
        
        if status:
            conditions.append("status = ?")
            params.append(status)
        
        if issuer:
            conditions.append("issuer = ?")
            params.append(issuer)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            self.logger.info(f"Listed certificates: {len(rows)} records (status={status})")
            return [dict(row) for row in rows]
    
    def update_certificate_status(
        self,
        serial_hex: str,
        status: str,
        revocation_reason: Optional[str] = None
    ) -> bool:
        """
        Update certificate status (for revocation).
        
        Args:
            serial_hex: Serial number in hex
            status: New status ('valid', 'revoked', 'expired')
            revocation_reason: Optional reason for revocation
        
        Returns:
            True if updated, False if not found
        """
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE certificates 
                SET status = ?, revocation_reason = ?, revocation_date = ?
                WHERE serial_hex = ?
            """, (status, revocation_reason, now, serial_hex.upper()))
            
            if cursor.rowcount > 0:
                self.logger.info(f"Certificate status updated: serial={serial_hex}, status={status}")
                return True
            else:
                self.logger.warning(f"Certificate not found for status update: {serial_hex}")
                return False
    
    def update_expired_status(self) -> int:
        """Update status of expired certificates."""
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE certificates 
                SET status = 'expired'
                WHERE not_after < ? AND status = 'valid'
            """, (now,))
            
            if cursor.rowcount > 0:
                self.logger.info(f"Updated {cursor.rowcount} certificates to expired status")
            
            return cursor.rowcount
    
    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """Get all revoked certificates (for CRL generation)."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT serial_hex, revocation_date, revocation_reason
                FROM certificates
                WHERE status = 'revoked'
                ORDER BY revocation_date DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    
    def count_certificates(self, status: Optional[str] = None) -> int:
        """Count certificates with optional status filter."""
        with self._get_connection() as conn:
            if status:
                cursor = conn.execute("SELECT COUNT(*) as count FROM certificates WHERE status = ?", (status,))
            else:
                cursor = conn.execute("SELECT COUNT(*) as count FROM certificates")
            
            return cursor.fetchone()['count']