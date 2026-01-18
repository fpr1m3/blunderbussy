# Agent Opulence - Parser Package
# Parses raw scan output from various tools into structured JSON

from pathlib import Path

PARSER_DIR = Path(__file__).parent

__all__ = [
    'parse_nmap',
    'parse_nuclei',
    'parse_httpx',
    'parse_subfinder'
]
