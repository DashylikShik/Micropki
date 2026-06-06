"""Logging configuration for MicroPKI."""
import logging
import sys
from typing import Optional


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts sensitive information."""
    
    def format(self, record):
        # Redact any potential passphrase in the message
        if hasattr(record, 'msg'):
            msg = str(record.msg)
            # Простое замаскирование информации о пароле
            if 'passphrase' in msg.lower() or 'password' in msg.lower():
                record.msg = '[REDACTED: sensitive information]'
        return super().format(record)


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logger with proper formatting and output destination.
    
    Args:
        log_file: Optional path to log file. If None, logs go to stderr.
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('micropki')
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create formatter with ISO 8601 timestamp
    formatter = RedactingFormatter(
        fmt='%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )
    
    # Create handler
    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger