"""utils.py - Shared utility functions.

Helper utilities for input validation and response formatting.
"""
import re
from datetime import datetime


def sanitize_input(value: str) -> str:
    """Remove potentially dangerous characters from input."""
    return re.sub(r'[^\w\s@.\-]', '', value)


def format_response(data: dict, status: str = "ok") -> dict:
    """Wrap response data in a standard envelope."""
    return {
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data,
    }


def is_valid_hostname(hostname: str) -> bool:
    """Validate that a hostname follows RFC 1123."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, hostname))
