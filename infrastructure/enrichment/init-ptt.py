#!/usr/bin/env python3
"""
PTT Initialization Script for Enrichment Pipeline
=================================================
Transforms CAS (context.yaml) into PTT (ptt.yaml) deterministically.

This script is called by the enrichment pipeline after CAS generation
to pre-populate the Pentesting Task Tree before Dame agent starts.

Usage:
    python3 init-ptt.py /artifacts/{target}/context.yaml

Output:
    Creates ptt.yaml in the same directory as context.yaml
    Logs summary of initialization (hosts, services, pending techniques)

Exit Codes:
    0 - Success
    1 - Invalid arguments
    2 - File not found
    3 - PTT initialization failed
    4 - PTT save failed
"""

import sys
import logging
from pathlib import Path

# Import PTT module (available at /app/ptt.py in container)
try:
    from ptt import PTTManager
except ImportError as e:
    print(f"ERROR: Failed to import ptt module: {e}", file=sys.stderr)
    print("Ensure ptt.py is available in PYTHONPATH or /app/", file=sys.stderr)
    sys.exit(3)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("init-ptt")


def validate_cas_path(cas_path: str) -> Path:
    """
    Validate that CAS path exists and is readable.

    Args:
        cas_path: Path to context.yaml file

    Returns:
        Path object if valid

    Raises:
        SystemExit: If path is invalid or file doesn't exist
    """
    path = Path(cas_path)

    if not path.exists():
        logger.error(f"CAS file not found: {cas_path}")
        sys.exit(2)

    if not path.is_file():
        logger.error(f"CAS path is not a file: {cas_path}")
        sys.exit(2)

    if not path.suffix in ['.yaml', '.yml']:
        logger.warning(f"CAS file does not have .yaml/.yml extension: {cas_path}")

    return path


def initialize_ptt(cas_path: Path) -> PTTManager:
    """
    Initialize PTT from CAS file.

    Args:
        cas_path: Path to context.yaml file

    Returns:
        PTTManager instance

    Raises:
        SystemExit: If PTT initialization fails
    """
    try:
        logger.info(f"Initializing PTT from CAS: {cas_path}")
        ptt = PTTManager.from_cas(str(cas_path))
        logger.info("PTT initialization successful")
        return ptt
    except Exception as e:
        logger.error(f"Failed to initialize PTT from CAS: {e}", exc_info=True)
        sys.exit(3)


def save_ptt(ptt: PTTManager, output_path: Path):
    """
    Save PTT to YAML file.

    Args:
        ptt: PTTManager instance
        output_path: Path where ptt.yaml will be saved

    Raises:
        SystemExit: If save operation fails
    """
    try:
        logger.info(f"Saving PTT to: {output_path}")
        ptt.save(str(output_path))
        logger.info("PTT saved successfully")
    except Exception as e:
        logger.error(f"Failed to save PTT: {e}", exc_info=True)
        sys.exit(4)


def log_summary(ptt: PTTManager):
    """
    Log PTT summary statistics.

    Args:
        ptt: PTTManager instance
    """
    try:
        summary = ptt.get_summary()

        logger.info("=" * 60)
        logger.info("PTT INITIALIZATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Platform: {summary.get('platform', 'unknown')}")
        logger.info(f"Status: {summary.get('status', 'unknown')}")
        logger.info(f"Hosts Total: {summary.get('hosts_total', 0)}")
        logger.info(f"Hosts Compromised: {summary.get('hosts_compromised', 0)}")
        logger.info(f"Services Exploited: {summary.get('services_exploited', 0)}")
        logger.info(f"Techniques Attempted: {summary.get('techniques_attempted', 0)}")
        logger.info(f"Techniques Successful: {summary.get('techniques_successful', 0)}")
        logger.info(f"Credentials Found: {summary.get('credentials_found', 0)}")

        # Calculate pending techniques
        pending_techniques = count_pending_techniques(ptt)
        logger.info(f"Techniques Pending: {pending_techniques}")

        access_gained = summary.get('access_gained', [])
        if access_gained:
            logger.info(f"Access Gained: {len(access_gained)} hosts")
            for access in access_gained:
                logger.info(f"  - {access.get('host')}: {access.get('level')} via {access.get('technique')}")

        logger.info("=" * 60)

    except Exception as e:
        logger.warning(f"Failed to generate summary: {e}")


def count_pending_techniques(ptt: PTTManager) -> int:
    """
    Count total pending techniques across all hosts/services.

    Args:
        ptt: PTTManager instance

    Returns:
        Number of pending techniques
    """
    count = 0
    for host in ptt.engagement.hosts:
        for service in host.services:
            for vector in service.vectors:
                for technique in vector.techniques:
                    if technique.status == "pending":
                        count += 1
    return count


def main():
    """Main entry point for PTT initialization."""

    # Parse command line arguments
    if len(sys.argv) != 2:
        print("Usage: python3 init-ptt.py /artifacts/{target}/context.yaml", file=sys.stderr)
        print("", file=sys.stderr)
        print("Transforms CAS (context.yaml) into PTT (ptt.yaml)", file=sys.stderr)
        sys.exit(1)

    cas_path_str = sys.argv[1]

    # Validate CAS path
    cas_path = validate_cas_path(cas_path_str)

    # Determine output path (same directory as CAS, named ptt.yaml)
    output_path = cas_path.parent / "ptt.yaml"

    # Initialize PTT from CAS
    ptt = initialize_ptt(cas_path)

    # Save PTT to file
    save_ptt(ptt, output_path)

    # Log summary
    log_summary(ptt)

    logger.info("PTT initialization completed successfully")
    sys.exit(0)


if __name__ == "__main__":
    main()
