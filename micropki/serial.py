"""Unique serial number generator for certificates."""
import os
import sqlite3
from datetime import datetime, timezone


class SerialGenerator:
    """
    Generate unique serial numbers for certificates.
    
    Format: 64-bit composite serial number
    - High 32 bits: Unix timestamp (seconds since 2020-01-01)
    - Low 32 bits: CSPRNG random value
    """
    
    def __init__(self, db_path: str):
        """
        Initialize serial generator.
        
        Args:
            db_path: Path to SQLite database for tracking used serials
        """
        self.db_path = db_path
        self._ensure_table()
    
    def _ensure_table(self) -> None:
        """Ensure serial tracking table exists."""
        import os
        
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            # Use TEXT for serial_int to avoid 64-bit overflow
            conn.execute("""
                CREATE TABLE IF NOT EXISTS serial_tracker (
                    serial_int TEXT PRIMARY KEY,
                    serial_hex TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def generate_serial(self) -> tuple:
        """
        Generate a unique serial number.
        
        Returns:
            Tuple of (serial_int, serial_hex)
        
        Raises:
            RuntimeError: If unable to generate unique serial
        """
        max_attempts = 10
        epoch_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        
        for attempt in range(max_attempts):
            # High 32 bits: timestamp (seconds since 2020-01-01)
            timestamp_seconds = int((datetime.now(timezone.utc) - epoch_start).total_seconds())
            timestamp_part = (timestamp_seconds & 0xFFFFFFFF) << 32
            
            # Low 32 bits: random
            random_part = int.from_bytes(os.urandom(4), byteorder='big') & 0xFFFFFFFF
            
            serial_int = timestamp_part | random_part
            serial_hex = hex(serial_int)[2:].upper().zfill(16)
            
            # Check uniqueness in database
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Convert serial_int to string for storage
                    serial_int_str = str(serial_int)
                    conn.execute("""
                        INSERT INTO serial_tracker (serial_int, serial_hex, created_at)
                        VALUES (?, ?, ?)
                    """, (serial_int_str, serial_hex, datetime.now(timezone.utc).isoformat()))
                    conn.commit()
                    
                    # Success - unique serial
                    return (serial_int, serial_hex)
                    
            except sqlite3.IntegrityError:
                # Duplicate serial - try again
                continue
        
        raise RuntimeError(f"Failed to generate unique serial after {max_attempts} attempts")
    
    def check_serial_exists(self, serial_int: int) -> bool:
        """Check if serial number already exists in database."""
        serial_int_str = str(serial_int)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT 1 FROM serial_tracker WHERE serial_int = ?", (serial_int_str,))
            return cursor.fetchone() is not None
    
    def get_all_serials(self, limit: int = 1000) -> list:
        """Get list of all serial numbers."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT serial_hex, created_at FROM serial_tracker ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [{'serial_hex': row[0], 'created_at': row[1]} for row in cursor.fetchall()]