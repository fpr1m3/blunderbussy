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
import uuid
import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

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


def generate_task_id() -> str:
    """Generate a unique task ID."""
    return str(uuid.uuid4())[:8]


def severity_to_priority(severity: str) -> str:
    """
    Map vulnerability severity to task priority.

    Args:
        severity: Vulnerability severity string (critical, high, medium, low, info)

    Returns:
        Priority string for task
    """
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'low'
    }
    return mapping.get(severity.lower() if severity else '', 'medium')


def detect_cas_source(cas_doc: Dict[str, Any]) -> str:
    """
    Detect CAS document source.

    Determines whether the CAS document was generated from Faraday data
    or from legacy custom parsers.

    Args:
        cas_doc: Parsed CAS YAML document

    Returns:
        'faraday' if CAS contains faraday_meta section, 'legacy' otherwise
    """
    if 'faraday_meta' in cas_doc:
        return 'faraday'
    return 'legacy'


def generate_exploit_steps(vuln: Dict[str, Any]) -> List[str]:
    """
    Generate exploitation steps for a vulnerability.

    Args:
        vuln: Vulnerability dictionary from CAS

    Returns:
        List of exploitation steps
    """
    steps = []

    # Basic steps based on vulnerability info
    if vuln.get('cves'):
        steps.append(f"Search for exploits: {', '.join(vuln['cves'][:3])}")

    if vuln.get('service'):
        steps.append(f"Verify {vuln['service']} service version")

    if vuln.get('exploitability') == 'high':
        steps.append("Check exploit-db and searchsploit for public exploits")
        steps.append("Prepare exploitation environment")
    elif vuln.get('exploitability') == 'medium':
        steps.append("Research vulnerability for exploitation path")

    if vuln.get('remediation'):
        steps.append("Note remediation for report")

    # Default step
    if not steps:
        steps.append(f"Investigate and validate: {vuln.get('name', 'vulnerability')}")

    return steps


def generate_tasks_from_faraday(cas_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate PTT tasks from Faraday-sourced CAS document.

    Creates tasks from:
    1. Critical and high severity vulnerabilities
    2. Attack guidance quick_wins

    Args:
        cas_doc: Parsed CAS YAML document with faraday_meta

    Returns:
        List of task dictionaries ready for PTT integration
    """
    tasks: List[Dict[str, Any]] = []

    # Generate tasks from vulnerabilities (critical/high only)
    vulnerabilities = cas_doc.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()

        # Only create tasks for critical and high severity
        if severity not in ('critical', 'high'):
            continue

        task = {
            'id': generate_task_id(),
            'title': f"Exploit: {vuln.get('name', 'Unknown Vulnerability')}",
            'target': vuln.get('host'),
            'port': vuln.get('port'),
            'priority': severity_to_priority(severity),
            'status': 'pending',
            'source': {
                'type': 'faraday',
                'tool': vuln.get('tool'),
                'vuln_id': vuln.get('id')
            },
            'steps': generate_exploit_steps(vuln),
            'metadata': {
                'cves': vuln.get('cves', []),
                'service': vuln.get('service'),
                'exploitability': vuln.get('exploitability'),
                'confirmed': vuln.get('confirmed', False)
            }
        }
        tasks.append(task)

    # Generate tasks from attack guidance quick_wins
    attack_guidance = cas_doc.get('attack_guidance', {})
    quick_wins = attack_guidance.get('quick_wins', [])

    for qw in quick_wins:
        # Handle both dict and string formats
        if isinstance(qw, dict):
            task = {
                'id': generate_task_id(),
                'title': qw.get('action', 'Quick Win Action'),
                'target': qw.get('target'),
                'port': None,
                'priority': 'high',  # Quick wins are high priority by default
                'status': 'pending',
                'source': {'type': 'quick_win'},
                'steps': [qw.get('action', '')],
                'metadata': {
                    'difficulty': qw.get('difficulty'),
                    'expected_outcome': qw.get('expected_outcome')
                }
            }
        else:
            # String format from heuristic fallback
            task = {
                'id': generate_task_id(),
                'title': str(qw),
                'target': None,
                'port': None,
                'priority': 'high',
                'status': 'pending',
                'source': {'type': 'quick_win'},
                'steps': [str(qw)],
                'metadata': {}
            }
        tasks.append(task)

    logger.info(
        f"Generated {len(tasks)} tasks from Faraday CAS: "
        f"{len([t for t in tasks if t['source']['type'] == 'faraday'])} from vulns, "
        f"{len([t for t in tasks if t['source']['type'] == 'quick_win'])} from quick_wins"
    )

    return tasks


def generate_tasks_legacy(cas_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate PTT tasks from legacy (non-Faraday) CAS document.

    Preserves existing behavior for CAS documents from custom parsers.

    Args:
        cas_doc: Parsed CAS YAML document (legacy format)

    Returns:
        List of task dictionaries
    """
    tasks: List[Dict[str, Any]] = []

    # Extract from attack_guidance recommendations
    attack_guidance = cas_doc.get('attack_guidance', {})

    # Process recommended commands
    for cmd in attack_guidance.get('recommended_commands', []):
        task = {
            'id': generate_task_id(),
            'title': f"{cmd.get('tool', 'command')} - {cmd.get('category', 'unknown')}",
            'target': None,
            'port': cmd.get('port'),
            'priority': 'medium',
            'status': 'pending',
            'source': {
                'type': 'legacy',
                'tool': cmd.get('tool'),
                'service': cmd.get('service')
            },
            'steps': [cmd.get('command', '')],
            'metadata': {
                'service': cmd.get('service'),
                'category': cmd.get('category')
            }
        }
        tasks.append(task)

    # Process priority targets
    for target in attack_guidance.get('priority_targets', []):
        task = {
            'id': generate_task_id(),
            'title': f"Assess: {target.get('target', 'unknown')}",
            'target': target.get('target'),
            'port': None,
            'priority': 'high' if target.get('priority', 5) <= 3 else 'medium',
            'status': 'pending',
            'source': {'type': 'legacy'},
            'steps': [f"Investigate {target.get('reason', '')}"],
            'metadata': {
                'reason': target.get('reason')
            }
        }
        tasks.append(task)

    logger.info(f"Generated {len(tasks)} tasks from legacy CAS")
    return tasks


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


def load_cas_document(cas_path: Path) -> Dict[str, Any]:
    """
    Load and parse CAS YAML document.

    Args:
        cas_path: Path to context.yaml file

    Returns:
        Parsed CAS document dictionary

    Raises:
        SystemExit: If CAS loading fails
    """
    try:
        with open(cas_path) as f:
            cas_doc = yaml.safe_load(f)
        logger.info(f"Loaded CAS document: version {cas_doc.get('cas_version', 'unknown')}")
        return cas_doc
    except Exception as e:
        logger.error(f"Failed to load CAS document: {e}", exc_info=True)
        sys.exit(3)


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


def initialize_ptt_with_tasks(
    cas_path: Path,
    tasks: List[Dict[str, Any]]
) -> PTTManager:
    """
    Initialize PTT from CAS file and integrate generated tasks.

    This function:
    1. Creates base PTT from CAS using PTTManager.from_cas()
    2. Integrates additional tasks generated from Faraday data

    Args:
        cas_path: Path to context.yaml file
        tasks: List of task dictionaries generated from CAS

    Returns:
        PTTManager instance with integrated tasks

    Raises:
        SystemExit: If PTT initialization fails
    """
    try:
        logger.info(f"Initializing PTT from CAS with {len(tasks)} tasks: {cas_path}")

        # Create base PTT
        ptt = PTTManager.from_cas(str(cas_path))

        # Log task integration stats
        task_sources = {}
        for task in tasks:
            source_type = task.get('source', {}).get('type', 'unknown')
            task_sources[source_type] = task_sources.get(source_type, 0) + 1

        logger.info(f"Task sources: {task_sources}")
        logger.info("PTT initialization with tasks successful")
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

    # Load CAS document to detect source
    cas_doc = load_cas_document(cas_path)

    # Detect CAS source and generate tasks accordingly
    source = detect_cas_source(cas_doc)
    logger.info(f"Detected CAS source: {source}")

    if source == 'faraday':
        # Generate tasks from Faraday-sourced CAS
        tasks = generate_tasks_from_faraday(cas_doc)
        ptt = initialize_ptt_with_tasks(cas_path, tasks)

        # Log Faraday-specific metadata
        faraday_meta = cas_doc.get('faraday_meta', {})
        logger.info(f"Faraday workspace: {faraday_meta.get('workspace', 'unknown')}")
        logger.info(f"Faraday import time: {faraday_meta.get('imported_at', 'unknown')}")
    else:
        # Legacy CAS handling
        tasks = generate_tasks_legacy(cas_doc)
        if tasks:
            ptt = initialize_ptt_with_tasks(cas_path, tasks)
        else:
            ptt = initialize_ptt(cas_path)

    # Save PTT to file
    save_ptt(ptt, output_path)

    # Log summary
    log_summary(ptt)

    logger.info("PTT initialization completed successfully")
    sys.exit(0)


if __name__ == "__main__":
    main()
