"""Pytest configuration for protocol tests."""

import sys
from pathlib import Path

# Add infrastructure/PrEP to path for protocol imports
prep_path = Path(__file__).parent.parent.parent / "infrastructure" / "PrEP"
if str(prep_path) not in sys.path:
    sys.path.insert(0, str(prep_path))
