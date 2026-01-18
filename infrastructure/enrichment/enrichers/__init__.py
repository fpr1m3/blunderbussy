# Agent Opulence - Enricher Package
# Enriches parsed scan data with additional context

from pathlib import Path

ENRICHER_DIR = Path(__file__).parent

__all__ = [
    'enrich_cves',
    'enrich_services',
    'enrich_web'
]
