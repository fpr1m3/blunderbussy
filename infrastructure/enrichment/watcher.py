#!/usr/bin/env python3
"""
Agent Opulence - Enrichment Pipeline Watcher
=============================================
Monitors /artifacts/raw/ for new scan files and triggers the enrichment pipeline.
Uses watchdog for cross-platform file system monitoring.

Flow: raw scan -> parser -> enricher -> CAS formatter -> manifest update
"""

import os
import sys
import json
import time
import logging
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/artifacts/logs/enrichment.log')
    ]
)
logger = logging.getLogger('enrichment-watcher')

# Paths
RAW_DIR = Path('/artifacts/raw')
RESULTS_DIR = Path('/artifacts/results')  # AutoRecon output directory
PROCESSED_DIR = Path('/artifacts/processed')
LOGS_DIR = Path('/artifacts/logs')
PARSERS_DIR = Path('/app/parsers')
ENRICHERS_DIR = Path('/app/enrichers')

# File patterns -> parser mapping
PARSER_MAP = {
    'nmap': {
        'patterns': ['nmap*.xml', '*_nmap.xml', '*.nmap.xml'],
        'parser': 'parse-nmap.py',
        'output_type': 'hosts'
    },
    'nuclei': {
        'patterns': ['nuclei*.json', '*_nuclei.json', '*.nuclei.json', 'nuclei*.jsonl'],
        'parser': 'parse-nuclei.py',
        'output_type': 'vulnerabilities'
    },
    'httpx': {
        'patterns': ['httpx*.json', '*_httpx.json', '*.httpx.json', 'httpx*.jsonl'],
        'parser': 'parse-httpx.py',
        'output_type': 'web_services'
    },
    'subfinder': {
        'patterns': ['subfinder*.json', '*_subfinder.json', '*.subfinder.json', 'subfinder*.txt'],
        'parser': 'parse-subfinder.py',
        'output_type': 'subdomains'
    },
    'gobuster': {
        'patterns': ['gobuster*.txt', '*_gobuster.txt', '*.gobuster.txt'],
        'parser': 'parse-gobuster.py',
        'output_type': 'directories'
    },
    'nikto': {
        'patterns': ['nikto*.txt', '*_nikto.txt', '*.nikto.txt', 'nikto*.xml', '*_nikto.xml'],
        'parser': 'parse-nikto.py',
        'output_type': 'web_vulnerabilities'
    },
    'whatweb': {
        'patterns': ['whatweb*.json', '*_whatweb.json', '*.whatweb.json', 'whatweb*.txt', '*_whatweb.txt'],
        'parser': 'parse-whatweb.py',
        'output_type': 'technologies'
    }
}

# AutoRecon file patterns -> parser mapping
# Maps AutoRecon output file patterns to existing parsers
AUTORECON_PARSER_MAP = {
    'nmap': {
        # Use only full TCP scan to avoid duplicate hosts from quick/udp scans
        # The full scan is most comprehensive
        'patterns': ['*_full_tcp_nmap.xml'],
        'parser': 'parse-nmap.py',
        'output_type': 'hosts'
    },
    'nmap_ssh': {
        # SSH-specific nmap scan with script outputs
        'patterns': ['tcp_*_ssh_nmap.xml'],
        'parser': 'parse-nmap.py',
        'output_type': 'ssh_info'
    },
    'feroxbuster': {
        # AutoRecon naming: tcp_80_http_feroxbuster_dirbuster.txt
        'patterns': ['*feroxbuster*.txt'],
        'parser': 'parse-feroxbuster.py',
        'output_type': 'directories'
    },
    'nikto': {
        # AutoRecon naming: tcp_80_http_nikto.txt
        # Single pattern to avoid duplicate matches
        'patterns': ['*_nikto.txt'],
        'parser': 'parse-nikto.py',
        'output_type': 'web_vulnerabilities'
    },
    'whatweb': {
        # AutoRecon naming: tcp_80_http_whatweb.txt
        'patterns': ['*_whatweb.txt'],
        'parser': 'parse-whatweb.py',
        'output_type': 'technologies'
    },
    'enum4linux': {
        'patterns': ['*enum4linux*.txt'],
        'parser': 'parse-enum4linux.py',
        'output_type': 'smb_enum'
    },
    'smbmap': {
        'patterns': ['*smbmap*.txt'],
        'parser': 'parse-smbmap.py',
        'output_type': 'smb_shares'
    },
    'manual_commands': {
        # AutoRecon _manual_commands.txt with attack recommendations
        'patterns': ['_manual_commands.txt'],
        'parser': 'parse-manual-commands.py',
        'output_type': 'recommendations'
    }
}

# Enrichment chain
ENRICHERS = [
    {'script': 'enrich-cves.py', 'input_type': 'vulnerabilities'},
    {'script': 'enrich-services.py', 'input_type': 'hosts'},
    {'script': 'enrich-web.py', 'input_type': 'web_services'}
]


@dataclass
class ProcessingJob:
    """Tracks a file through the enrichment pipeline."""
    file_path: Path
    scan_type: str
    target: str
    session_id: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    parsed_data: Optional[Dict] = None
    enriched_data: Optional[Dict] = None
    cas_path: Optional[Path] = None
    status: str = 'pending'
    errors: list = field(default_factory=list)


class EnrichmentPipeline:
    """Orchestrates the enrichment pipeline for scan files."""

    def __init__(self):
        self.processing_queue: Dict[str, ProcessingJob] = {}
        self.processed_hashes: set = set()
        self._load_processed_hashes()

    def _load_processed_hashes(self):
        """Load previously processed file hashes to avoid reprocessing."""
        hash_file = LOGS_DIR / 'processed_hashes.json'
        if hash_file.exists():
            try:
                with open(hash_file) as f:
                    self.processed_hashes = set(json.load(f))
                logger.info(f"Loaded {len(self.processed_hashes)} processed file hashes")
            except Exception as e:
                logger.warning(f"Failed to load processed hashes: {e}")

    def _save_processed_hash(self, file_hash: str):
        """Save a processed file hash."""
        self.processed_hashes.add(file_hash)
        hash_file = LOGS_DIR / 'processed_hashes.json'
        try:
            with open(hash_file, 'w') as f:
                json.dump(list(self.processed_hashes), f)
        except Exception as e:
            logger.warning(f"Failed to save processed hash: {e}")

    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of file contents."""
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def _detect_scan_type(self, file_path: Path) -> Optional[str]:
        """Detect the scan type based on filename patterns."""
        filename = file_path.name.lower()

        for scan_type, config in PARSER_MAP.items():
            for pattern in config['patterns']:
                # Simple pattern matching (fnmatch-style)
                import fnmatch
                if fnmatch.fnmatch(filename, pattern.lower()):
                    return scan_type

        # Try content-based detection
        try:
            with open(file_path, 'r') as f:
                content = f.read(1000)
                if '<?xml' in content and 'nmap' in content.lower():
                    return 'nmap'
                elif '"template-id"' in content or '"matched-at"' in content:
                    return 'nuclei'
                elif '"url"' in content and '"status_code"' in content:
                    return 'httpx'
        except:
            pass

        return None

    def _extract_target(self, file_path: Path) -> str:
        """Extract target identifier from file path or content."""
        # Try to extract from path: /artifacts/raw/TARGET/file.xml
        parts = file_path.parts
        try:
            raw_idx = parts.index('raw')
            if raw_idx + 1 < len(parts) - 1:
                return parts[raw_idx + 1]
        except ValueError:
            pass

        # Fall back to filename parsing
        stem = file_path.stem
        # Remove common suffixes
        for suffix in ['_nmap', '_nuclei', '_httpx', '_subfinder', '.nmap', '.nuclei', '.httpx']:
            if stem.endswith(suffix):
                stem = stem[:-len(suffix)]

        return stem or 'unknown'

    def _generate_session_id(self, target: str) -> str:
        """Generate a session ID for the target."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        return f"{target}_{timestamp}"

    def process_file(self, file_path: Path) -> Optional[ProcessingJob]:
        """Process a scan file through the enrichment pipeline."""
        file_path = Path(file_path)

        # Skip non-files
        if not file_path.is_file():
            return None

        # Skip already processed files
        try:
            file_hash = self._get_file_hash(file_path)
            if file_hash in self.processed_hashes:
                logger.debug(f"Skipping already processed file: {file_path}")
                return None
        except Exception as e:
            logger.warning(f"Failed to hash file {file_path}: {e}")
            return None

        # Detect scan type
        scan_type = self._detect_scan_type(file_path)
        if not scan_type:
            logger.warning(f"Unknown scan type for file: {file_path}")
            return None

        logger.info(f"Processing {scan_type} scan: {file_path}")

        # Extract target and create job
        target = self._extract_target(file_path)
        session_id = self._generate_session_id(target)

        job = ProcessingJob(
            file_path=file_path,
            scan_type=scan_type,
            target=target,
            session_id=session_id
        )

        try:
            # Step 1: Parse raw scan
            job.status = 'parsing'
            job.parsed_data = self._run_parser(job)

            if not job.parsed_data:
                raise ValueError("Parser returned no data")

            # Step 2: Enrich data
            job.status = 'enriching'
            job.enriched_data = self._run_enrichers(job)

            # Step 3: Format as CAS
            job.status = 'formatting'
            job.cas_path = self._run_cas_formatter(job)

            # Step 4: Update manifest
            job.status = 'updating_manifest'
            self._run_manifest_update(job)

            # Mark as completed
            job.status = 'completed'
            self._save_processed_hash(file_hash)

            logger.info(f"Successfully processed {file_path} -> {job.cas_path}")

        except Exception as e:
            job.status = 'failed'
            job.errors.append(str(e))
            logger.error(f"Failed to process {file_path}: {e}")

        return job

    def _run_parser(self, job: ProcessingJob) -> Dict[str, Any]:
        """Run the appropriate parser for the scan type."""
        config = PARSER_MAP[job.scan_type]
        parser_script = PARSERS_DIR / config['parser']

        if not parser_script.exists():
            raise FileNotFoundError(f"Parser not found: {parser_script}")

        # Run parser
        result = subprocess.run(
            ['python3', str(parser_script), str(job.file_path)],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            raise RuntimeError(f"Parser failed: {result.stderr}")

        return json.loads(result.stdout)

    def _run_enrichers(self, job: ProcessingJob) -> Dict[str, Any]:
        """Run enrichment scripts on parsed data."""
        enriched = job.parsed_data.copy()

        for enricher in ENRICHERS:
            # Check if this enricher applies to our data type
            output_type = PARSER_MAP[job.scan_type]['output_type']
            if enricher['input_type'] != output_type:
                continue

            script_path = ENRICHERS_DIR / enricher['script']
            if not script_path.exists():
                logger.warning(f"Enricher not found: {script_path}")
                continue

            try:
                result = subprocess.run(
                    ['python3', str(script_path)],
                    input=json.dumps(enriched),
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    enriched = json.loads(result.stdout)
                else:
                    logger.warning(f"Enricher {enricher['script']} failed: {result.stderr}")
            except Exception as e:
                logger.warning(f"Enricher {enricher['script']} error: {e}")

        return enriched

    def _run_cas_formatter(self, job: ProcessingJob) -> Path:
        """Format enriched data as CAS YAML."""
        formatter_script = Path('/app/format-cas.py')

        # Ensure target directory exists
        target_dir = Path(f'/artifacts/{job.target}')
        target_dir.mkdir(parents=True, exist_ok=True)

        cas_path = target_dir / 'context.yaml'

        # Prepare input for formatter
        formatter_input = {
            'target': job.target,
            'session_id': job.session_id,
            'scan_type': job.scan_type,
            'data': job.enriched_data,
            'source_file': str(job.file_path),
            'timestamp': datetime.utcnow().isoformat()
        }

        result = subprocess.run(
            ['python3', str(formatter_script), str(cas_path)],
            input=json.dumps(formatter_input),
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError(f"CAS formatter failed: {result.stderr}")

        return cas_path

    def _run_manifest_update(self, job: ProcessingJob):
        """Update the manifest with new findings."""
        manifest_script = Path('/app/update-manifest.py')

        manifest_input = {
            'target': job.target,
            'session_id': job.session_id,
            'scan_type': job.scan_type,
            'cas_path': str(job.cas_path),
            'enriched_data': job.enriched_data,
            'timestamp': datetime.utcnow().isoformat()
        }

        result = subprocess.run(
            ['python3', str(manifest_script)],
            input=json.dumps(manifest_input),
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            logger.warning(f"Manifest update warning: {result.stderr}")


class AutoReconProcessor:
    """Handles batch processing of AutoRecon scan results."""

    def __init__(self, pipeline: EnrichmentPipeline):
        self.pipeline = pipeline
        self.processed_targets: set = set()
        self._load_processed_targets()

    def _load_processed_targets(self):
        """Load previously processed AutoRecon targets."""
        targets_file = LOGS_DIR / 'autorecon_processed.json'
        if targets_file.exists():
            try:
                with open(targets_file) as f:
                    self.processed_targets = set(json.load(f))
                logger.info(f"Loaded {len(self.processed_targets)} processed AutoRecon targets")
            except Exception as e:
                logger.warning(f"Failed to load processed targets: {e}")

    def _save_processed_target(self, target: str):
        """Save a processed AutoRecon target."""
        self.processed_targets.add(target)
        targets_file = LOGS_DIR / 'autorecon_processed.json'
        try:
            with open(targets_file, 'w') as f:
                json.dump(list(self.processed_targets), f)
        except Exception as e:
            logger.warning(f"Failed to save processed target: {e}")

    def is_scan_complete(self, target_dir: Path) -> bool:
        """Check if AutoRecon scan is complete for a target."""
        scans_dir = target_dir / 'scans'
        commands_log = scans_dir / '_commands.log'

        if not commands_log.exists():
            return False

        try:
            with open(commands_log, 'r') as f:
                content = f.read()
                # AutoRecon writes these messages when done
                return 'Finished scanning' in content or 'AutoRecon was interrupted' in content
        except Exception:
            return False

    def find_ready_targets(self) -> list:
        """Find AutoRecon targets that are complete and ready for processing."""
        ready = []

        if not RESULTS_DIR.exists():
            return ready

        for target_dir in RESULTS_DIR.iterdir():
            if not target_dir.is_dir():
                continue

            target = target_dir.name
            if target in self.processed_targets:
                continue

            if self.is_scan_complete(target_dir):
                ready.append(target_dir)

        return ready

    def _detect_scan_type(self, file_path: Path) -> Optional[str]:
        """Detect scan type from AutoRecon output filename."""
        import fnmatch
        filename = file_path.name.lower()

        for scan_type, config in AUTORECON_PARSER_MAP.items():
            for pattern in config['patterns']:
                if fnmatch.fnmatch(filename, pattern.lower()):
                    return scan_type

        return None

    def _collect_scan_files(self, target_dir: Path) -> Dict[str, List[Path]]:
        """Collect all scan files grouped by type."""
        scans_dir = target_dir / 'scans'
        files_by_type: Dict[str, List[Path]] = {}

        if not scans_dir.exists():
            return files_by_type

        for file_path in scans_dir.rglob('*'):
            if not file_path.is_file():
                continue

            # Skip log files and empty files
            if file_path.suffix in ['.log'] or file_path.stat().st_size == 0:
                continue

            scan_type = self._detect_scan_type(file_path)
            if scan_type:
                if scan_type not in files_by_type:
                    files_by_type[scan_type] = []
                files_by_type[scan_type].append(file_path)

        return files_by_type

    def process_target(self, target_dir: Path) -> bool:
        """Process all scan files for an AutoRecon target."""
        target = target_dir.name
        logger.info(f"Processing AutoRecon results for target: {target}")

        # Collect scan files by type
        files_by_type = self._collect_scan_files(target_dir)

        if not files_by_type:
            logger.warning(f"No scan files found for {target}")
            return False

        logger.info(f"Found scan types: {list(files_by_type.keys())}")

        # Merge all parsed and enriched data
        merged_data = {
            'type': 'autorecon',
            'target': target,
            'scan_types': list(files_by_type.keys()),
            'hosts': [],
            'vulnerabilities': [],
            'web_services': [],
            'directories': [],
            'technologies': [],
            'smb_shares': [],
            'smb_enum': [],
            'recommendations': [],
            'ssh_info': [],
            'raw_files': []
        }

        # Process each scan type
        for scan_type, files in files_by_type.items():
            config = AUTORECON_PARSER_MAP.get(scan_type)
            if not config:
                continue

            parser_script = PARSERS_DIR / config['parser']
            if not parser_script.exists():
                logger.warning(f"Parser not found: {parser_script}")
                continue

            for file_path in files:
                try:
                    # Run parser
                    result = subprocess.run(
                        ['python3', str(parser_script), str(file_path)],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )

                    if result.returncode != 0:
                        logger.warning(f"Parser failed for {file_path}: {result.stderr}")
                        continue

                    parsed = json.loads(result.stdout)
                    output_type = config['output_type']

                    # Merge results
                    if output_type == 'hosts' and 'hosts' in parsed:
                        merged_data['hosts'].extend(parsed['hosts'])
                    elif output_type == 'vulnerabilities' and 'vulnerabilities' in parsed:
                        merged_data['vulnerabilities'].extend(parsed['vulnerabilities'])
                    elif output_type == 'directories' and 'findings' in parsed:
                        merged_data['directories'].extend(parsed['findings'])
                    elif output_type == 'technologies' and 'technologies' in parsed:
                        merged_data['technologies'].extend(parsed['technologies'])
                    elif output_type == 'web_vulnerabilities' and 'findings' in parsed:
                        # Inject target info into each finding for CAS formatter
                        target_ip = parsed.get('target', target)
                        for finding in parsed['findings']:
                            finding['target'] = target_ip
                        merged_data['vulnerabilities'].extend(parsed['findings'])
                    elif output_type == 'smb_shares' and 'shares' in parsed:
                        merged_data['smb_shares'].extend(parsed['shares'])
                    elif output_type == 'smb_enum':
                        merged_data['smb_enum'].append(parsed)
                    elif output_type == 'recommendations' and 'recommendations' in parsed:
                        merged_data['recommendations'].extend(parsed['recommendations'])
                    elif output_type == 'ssh_info' and 'hosts' in parsed:
                        # Extract SSH info from nmap hosts
                        for host in parsed['hosts']:
                            for port in host.get('ports', []):
                                if port.get('ssh'):
                                    merged_data['ssh_info'].append({
                                        'host': host.get('ip'),
                                        'port': port.get('port'),
                                        **port['ssh']
                                    })

                    merged_data['raw_files'].append(str(file_path))
                    logger.info(f"Parsed {scan_type}: {file_path.name}")

                except subprocess.TimeoutExpired:
                    logger.error(f"Parser timeout for {file_path}")
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from parser for {file_path}: {e}")
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")

        # Run enrichers on merged data
        enriched_data = self._run_enrichers(merged_data)

        # Format as CAS
        session_id = f"{target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        cas_input = {
            'target': target,
            'session_id': session_id,
            'scan_type': 'autorecon',
            'data': enriched_data,
            'source_file': str(target_dir / 'scans'),
            'timestamp': datetime.utcnow().isoformat()
        }

        # Write CAS
        cas_path = Path(f'/artifacts/{target}/context.yaml')
        cas_path.parent.mkdir(parents=True, exist_ok=True)

        formatter_script = Path('/app/format-cas.py')
        try:
            result = subprocess.run(
                ['python3', str(formatter_script), str(cas_path)],
                input=json.dumps(cas_input),
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f"CAS formatter failed: {result.stderr}")
                return False

            logger.info(f"CAS document written to: {cas_path}")

        except Exception as e:
            logger.error(f"Failed to format CAS: {e}")
            return False

        # Mark as processed
        self._save_processed_target(target)
        logger.info(f"Successfully processed AutoRecon results for {target}")

        return True

    def _run_enrichers(self, data: Dict) -> Dict:
        """Run applicable enrichers on merged data."""
        enriched = data.copy()

        # Map output types to enricher input types
        type_mapping = {
            'hosts': 'hosts',
            'web_services': 'web_services',
            'vulnerabilities': 'vulnerabilities'
        }

        for enricher in ENRICHERS:
            # Check which data types this enricher handles
            for data_key, input_type in type_mapping.items():
                if enricher['input_type'] != input_type:
                    continue

                if not enriched.get(data_key):
                    continue

                script_path = ENRICHERS_DIR / enricher['script']
                if not script_path.exists():
                    continue

                try:
                    # Prepare input for enricher
                    enricher_input = {data_key: enriched[data_key]}

                    result = subprocess.run(
                        ['python3', str(script_path)],
                        input=json.dumps(enricher_input),
                        capture_output=True,
                        text=True,
                        timeout=120
                    )

                    if result.returncode == 0:
                        enricher_output = json.loads(result.stdout)
                        if data_key in enricher_output:
                            enriched[data_key] = enricher_output[data_key]
                        # Merge any additional fields
                        for key, value in enricher_output.items():
                            if key not in enriched:
                                enriched[key] = value
                    else:
                        logger.warning(f"Enricher {enricher['script']} failed: {result.stderr}")

                except Exception as e:
                    logger.warning(f"Enricher {enricher['script']} error: {e}")

        return enriched


class ScanFileHandler(FileSystemEventHandler):
    """Handles file system events for scan files."""

    def __init__(self, pipeline: EnrichmentPipeline):
        self.pipeline = pipeline
        self._debounce = {}  # Prevent duplicate processing
        self._debounce_seconds = 2

    def _should_process(self, file_path: str) -> bool:
        """Check if file should be processed (debounce)."""
        now = time.time()
        last_seen = self._debounce.get(file_path, 0)

        if now - last_seen < self._debounce_seconds:
            return False

        self._debounce[file_path] = now
        return True

    def _wait_for_stable(self, file_path: str, timeout: int = 120) -> bool:
        """Wait for file to stop changing (fully written)."""
        path = Path(file_path)
        stable_count = 0
        last_size = -1
        check_interval = 2  # seconds

        for _ in range(timeout // check_interval):
            if not path.exists():
                return False

            current_size = path.stat().st_size
            if current_size == last_size and current_size > 0:
                stable_count += 1
                if stable_count >= 2:  # Stable for 4+ seconds
                    return True
            else:
                stable_count = 0

            last_size = current_size
            time.sleep(check_interval)

        logger.warning(f"File stability timeout: {file_path}")
        return True  # Process anyway after timeout

    def on_created(self, event):
        if event.is_directory:
            return

        if not self._should_process(event.src_path):
            return

        # Wait for file to be fully written
        if not self._wait_for_stable(event.src_path):
            return

        logger.info(f"New file detected: {event.src_path}")
        self.pipeline.process_file(Path(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return

        if not self._should_process(event.src_path):
            return

        # Only process on modify if file wasn't just created
        time.sleep(0.5)

        logger.debug(f"File modified: {event.src_path}")
        # Don't auto-process on modify to avoid reprocessing


def ensure_directories():
    """Ensure all required directories exist."""
    for directory in [RAW_DIR, RESULTS_DIR, PROCESSED_DIR, LOGS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
    logger.info("Directories verified")


def process_existing_files(pipeline: EnrichmentPipeline):
    """Process any existing unprocessed files."""
    logger.info("Checking for existing unprocessed files...")

    for file_path in RAW_DIR.rglob('*'):
        if file_path.is_file():
            pipeline.process_file(file_path)


def process_autorecon_targets(autorecon_processor: AutoReconProcessor):
    """Process any complete AutoRecon targets."""
    ready_targets = autorecon_processor.find_ready_targets()

    for target_dir in ready_targets:
        logger.info(f"Found complete AutoRecon scan: {target_dir.name}")
        autorecon_processor.process_target(target_dir)


def main():
    """Main entry point for the enrichment watcher."""
    logger.info("=" * 60)
    logger.info("Agent Opulence - Enrichment Pipeline Starting")
    logger.info("=" * 60)

    # Setup
    ensure_directories()
    pipeline = EnrichmentPipeline()
    autorecon_processor = AutoReconProcessor(pipeline)

    # Process existing files first
    process_existing_files(pipeline)

    # Process any existing AutoRecon results
    process_autorecon_targets(autorecon_processor)

    # Start watching for new files in RAW_DIR (legacy pipeline)
    event_handler = ScanFileHandler(pipeline)
    observer = Observer()
    observer.schedule(event_handler, str(RAW_DIR), recursive=True)
    observer.start()

    logger.info(f"Watching for new scans in: {RAW_DIR}")
    logger.info(f"Monitoring AutoRecon results in: {RESULTS_DIR}")

    # Polling interval for AutoRecon completion checks (seconds)
    AUTORECON_POLL_INTERVAL = 30
    last_autorecon_check = time.time()

    try:
        while True:
            time.sleep(1)

            # Periodically check for completed AutoRecon scans
            now = time.time()
            if now - last_autorecon_check >= AUTORECON_POLL_INTERVAL:
                process_autorecon_targets(autorecon_processor)
                last_autorecon_check = now

    except KeyboardInterrupt:
        logger.info("Shutting down...")
        observer.stop()

    observer.join()
    logger.info("Enrichment pipeline stopped")


if __name__ == '__main__':
    main()
