#!/usr/bin/env python3
"""
Faraday-integrated Enrichment Watcher
=====================================
Simplified watcher that delegates parsing to Faraday's 80+ built-in plugins.

Flow:
1. Monitor /artifacts/raw/ and /artifacts/results/ for new files
2. Upload files to Faraday via API (auto-parsed)
3. Query Faraday for results
4. Generate CAS/PTT from Faraday data
"""

import os
import sys
import time
import json
import hashlib
import logging
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from faraday_client import FaradayClient, FaradayConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/artifacts/logs/faraday-watcher.log')
    ]
)
logger = logging.getLogger('faraday-watcher')


def sanitize_workspace_name(name: str) -> str:
    """
    Sanitize a name to be a valid Faraday workspace name.

    Faraday workspace names must be alphanumeric with underscores only.
    This replaces dots, colons, and other invalid characters with underscores.

    Args:
        name: Raw workspace/target name (e.g., "10.129.2.163")

    Returns:
        Sanitized workspace name (e.g., "ws_10_129_2_163")
    """
    import re
    # Replace common invalid characters with underscores
    sanitized = name.replace('.', '_').replace(':', '_').replace('-', '_')
    # Remove any other non-alphanumeric characters except underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', sanitized)
    # Ensure it doesn't start with a number (prefix with 'ws_' if it does)
    if sanitized and sanitized[0].isdigit():
        sanitized = f'ws_{sanitized}'
    return sanitized


@dataclass
class WatcherConfig:
    """
    Watcher configuration from environment.

    Environment Variables:
        FARADAY_URL: Faraday server URL (default: http://faraday-server:5985)
        FARADAY_USER: Faraday username (default: faraday)
        FARADAY_PASSWORD: Faraday password (default: changeme)
        FARADAY_WORKSPACE: Default workspace name (default: pentest)
        RAW_DIR: Directory for raw scan files (default: /artifacts/raw)
        RESULTS_DIR: Directory for scan results (default: /artifacts/results)
        LOGS_DIR: Directory for logs (default: /artifacts/logs)
        POLL_INTERVAL: Seconds between polling cycles (default: 30)
        FILE_STABLE_SECONDS: Wait time for file stability (default: 4)
        AUTORECON_POLL_INTERVAL: Seconds between AutoRecon polls (default: 30)
        GENERATE_CAS: Enable CAS generation (default: true)
        GENERATE_PTT: Enable PTT generation (default: true)
    """
    # Faraday connection
    faraday_url: str = field(default_factory=lambda: os.getenv('FARADAY_URL', 'http://faraday-server:5985'))
    faraday_user: str = field(default_factory=lambda: os.getenv('FARADAY_USER', 'faraday'))
    faraday_password: str = field(default_factory=lambda: os.getenv('FARADAY_PASSWORD', 'changeme'))
    faraday_workspace: str = field(default_factory=lambda: os.getenv('FARADAY_WORKSPACE', 'pentest'))

    # Paths
    raw_dir: Path = field(default_factory=lambda: Path(os.getenv('RAW_DIR', '/artifacts/raw')))
    results_dir: Path = field(default_factory=lambda: Path(os.getenv('RESULTS_DIR', '/artifacts/results')))
    logs_dir: Path = field(default_factory=lambda: Path(os.getenv('LOGS_DIR', '/artifacts/logs')))

    # Behavior
    poll_interval: int = field(default_factory=lambda: int(os.getenv('POLL_INTERVAL', '30')))
    file_stable_seconds: int = field(default_factory=lambda: int(os.getenv('FILE_STABLE_SECONDS', '4')))
    autorecon_poll_interval: int = field(default_factory=lambda: int(os.getenv('AUTORECON_POLL_INTERVAL', '30')))

    # Feature flags
    generate_cas: bool = field(default_factory=lambda: os.getenv('GENERATE_CAS', 'true').lower() == 'true')
    generate_ptt: bool = field(default_factory=lambda: os.getenv('GENERATE_PTT', 'true').lower() == 'true')

    def log_config(self) -> None:
        """Log configuration values (excluding sensitive data)."""
        logger.info(f'Faraday URL: {self.faraday_url}')
        logger.info(f'Faraday User: {self.faraday_user}')
        logger.info(f'Faraday Workspace: {self.faraday_workspace}')
        logger.info(f'Raw Directory: {self.raw_dir}')
        logger.info(f'Results Directory: {self.results_dir}')
        logger.info(f'Logs Directory: {self.logs_dir}')
        logger.info(f'Poll Interval: {self.poll_interval}s')
        logger.info(f'File Stable Seconds: {self.file_stable_seconds}s')
        logger.info(f'AutoRecon Poll Interval: {self.autorecon_poll_interval}s')
        logger.info(f'Generate CAS: {self.generate_cas}')
        logger.info(f'Generate PTT: {self.generate_ptt}')

    def to_faraday_config(self) -> FaradayConfig:
        """Create FaradayConfig from watcher settings."""
        return FaradayConfig(
            url=self.faraday_url,
            username=self.faraday_user,
            password=self.faraday_password
        )


class ProcessedFileTracker:
    """
    Tracks processed files to avoid reprocessing.

    Uses MD5 hashing to detect file content changes. Storage is persisted
    to JSON file for recovery across restarts.

    Attributes:
        storage_path: Path to JSON file for persistence
        processed: Dict mapping file paths to their content hashes
    """

    def __init__(self, storage_path: Path):
        """
        Initialize the tracker.

        Args:
            storage_path: Path to JSON file for persistence
        """
        self.storage_path = storage_path
        self.processed: Dict[str, str] = {}  # path -> hash
        self._load()

    def _load(self) -> None:
        """Load processed files from JSON storage."""
        if self.storage_path.exists():
            try:
                self.processed = json.loads(self.storage_path.read_text())
                logger.info(f'Loaded {len(self.processed)} processed files from {self.storage_path}')
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f'Failed to load processed files: {e}')
                self.processed = {}

    def _save(self) -> None:
        """Persist processed files to JSON storage."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            self.storage_path.write_text(json.dumps(self.processed, indent=2))
        except IOError as e:
            logger.error(f'Failed to save processed files: {e}')

    def get_file_hash(self, file_path: Path) -> str:
        """
        Calculate MD5 hash of file contents.

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded MD5 hash string
        """
        return hashlib.md5(file_path.read_bytes()).hexdigest()

    def is_processed(self, file_path: Path) -> bool:
        """
        Check if file (by content) was already processed.

        Args:
            file_path: Path to file

        Returns:
            True if file content hash is already in processed set
        """
        try:
            file_hash = self.get_file_hash(file_path)
            return file_hash in self.processed.values()
        except IOError:
            return False

    def mark_processed(self, file_path: Path) -> None:
        """
        Mark file as processed.

        Args:
            file_path: Path to file
        """
        try:
            self.processed[str(file_path)] = self.get_file_hash(file_path)
            self._save()
            logger.debug(f'Marked as processed: {file_path}')
        except IOError as e:
            logger.error(f'Failed to mark file as processed: {e}')

    def clear(self, file_path: Path) -> None:
        """
        Remove file from processed list (allows reprocessing).

        Args:
            file_path: Path to file
        """
        if str(file_path) in self.processed:
            del self.processed[str(file_path)]
            self._save()
            logger.debug(f'Cleared from processed: {file_path}')


# Supported file extensions for Faraday upload
SUPPORTED_EXTENSIONS: Set[str] = {'.xml', '.json', '.jsonl', '.txt', '.html'}

# Debounce interval in seconds
DEBOUNCE_SECONDS: float = 2.0


class FaradayScanHandler(FileSystemEventHandler):
    """
    Handles file system events for scan files.

    Uploads new/modified files to Faraday, with debouncing and
    file stability checks to handle slow writes.

    Attributes:
        client: FaradayClient for API calls
        config: WatcherConfig with paths and settings
        tracker: ProcessedFileTracker for deduplication
    """

    def __init__(
        self,
        client: FaradayClient,
        config: WatcherConfig,
        tracker: ProcessedFileTracker
    ):
        """
        Initialize the handler.

        Args:
            client: Authenticated FaradayClient
            config: WatcherConfig with paths and settings
            tracker: ProcessedFileTracker for deduplication
        """
        super().__init__()
        self.client = client
        self.config = config
        self.tracker = tracker
        self._debounce: Dict[str, float] = {}  # path -> last event time
        self._processing: Set[str] = set()  # files currently being processed

    def _should_process(self, file_path: str) -> bool:
        """
        Check if file should be processed (debounce rapid events).

        Args:
            file_path: Path to file as string

        Returns:
            True if enough time has passed since last event for this file
        """
        now = time.time()
        last_event = self._debounce.get(file_path, 0)

        if now - last_event < DEBOUNCE_SECONDS:
            logger.debug(f'Debounced event for {file_path}')
            return False

        self._debounce[file_path] = now
        return True

    def _wait_for_stable(self, file_path: Path) -> bool:
        """
        Wait for file to stop changing (fully written).

        Checks file size every 2 seconds until stable for
        file_stable_seconds duration.

        Args:
            file_path: Path to file

        Returns:
            True if file is stable, False if file disappeared or timeout
        """
        stable_time = self.config.file_stable_seconds
        check_interval = 2.0
        last_size = -1
        stable_since = 0.0

        while True:
            try:
                current_size = file_path.stat().st_size
            except OSError:
                logger.warning(f'File disappeared while waiting: {file_path}')
                return False

            if current_size == last_size:
                if stable_since == 0.0:
                    stable_since = time.time()
                elif time.time() - stable_since >= stable_time:
                    logger.debug(f'File stable: {file_path}')
                    return True
            else:
                stable_since = 0.0
                last_size = current_size

            time.sleep(check_interval)

    def _detect_workspace(self, file_path: Path) -> str:
        """
        Extract workspace name from file path.

        Path patterns:
            /artifacts/raw/TARGET/scan.xml -> TARGET
            /artifacts/results/TARGET/scans/file.xml -> TARGET

        Args:
            file_path: Path to scan file

        Returns:
            Workspace name (target directory) or default workspace
        """
        path_str = str(file_path)

        # Check if in raw directory
        raw_prefix = str(self.config.raw_dir)
        if path_str.startswith(raw_prefix):
            relative = file_path.relative_to(self.config.raw_dir)
            if relative.parts:
                return sanitize_workspace_name(relative.parts[0])

        # Check if in results directory
        results_prefix = str(self.config.results_dir)
        if path_str.startswith(results_prefix):
            relative = file_path.relative_to(self.config.results_dir)
            if relative.parts:
                return sanitize_workspace_name(relative.parts[0])

        # Fallback to default workspace
        return self.config.faraday_workspace

    def _is_supported_file(self, file_path: Path) -> bool:
        """
        Check if file type is supported by Faraday.

        Args:
            file_path: Path to file

        Returns:
            True if file extension is in SUPPORTED_EXTENSIONS
        """
        return file_path.suffix.lower() in SUPPORTED_EXTENSIONS

    def _handle_file_event(self, file_path: Path) -> None:
        """
        Handle a file event (common logic for created/modified).

        Args:
            file_path: Path to the file
        """
        path_str = str(file_path)

        # Skip if already processing
        if path_str in self._processing:
            logger.debug(f'Already processing: {file_path}')
            return

        # Skip unsupported files
        if not self._is_supported_file(file_path):
            logger.debug(f'Unsupported file type: {file_path}')
            return

        # Debounce
        if not self._should_process(path_str):
            return

        # Mark as processing
        self._processing.add(path_str)

        try:
            # Wait for file to stabilize
            if not self._wait_for_stable(file_path):
                return

            # Check if already processed (by content hash)
            if self.tracker.is_processed(file_path):
                logger.debug(f'Already processed (hash match): {file_path}')
                return

            # Process the file
            self.process_file(file_path)

        finally:
            self._processing.discard(path_str)

    def process_file(self, file_path: Path) -> bool:
        """
        Process a scan file: upload to Faraday and generate CAS.

        1. Determine workspace from path
        2. Create workspace if needed
        3. Upload to Faraday
        4. Mark as processed
        5. Trigger CAS generation

        Args:
            file_path: Path to scan file

        Returns:
            True if processing successful, False otherwise
        """
        workspace = self._detect_workspace(file_path)
        logger.info(f'Processing {file_path.name} for workspace {workspace}')

        try:
            # Ensure workspace exists
            if not self.client.workspace_exists(workspace):
                logger.info(f'Creating workspace: {workspace}')
                self.client.create_workspace(workspace)

            # Upload report
            logger.info(f'Uploading {file_path.name} to workspace {workspace}')
            result = self.client.upload_report(workspace, file_path)

            logger.info(
                f'Imported from {file_path.name}: '
                f'{result.get("hosts", 0)} hosts, '
                f'{result.get("vulnerabilities", 0)} vulns'
            )

            # Mark as processed
            self.tracker.mark_processed(file_path)

            # Trigger CAS generation
            if self.config.generate_cas:
                self._generate_cas(workspace)

            return True

        except FileNotFoundError as e:
            logger.error(f'File not found: {e}')
            return False
        except ValueError as e:
            logger.error(f'Workspace error: {e}')
            return False
        except RuntimeError as e:
            logger.error(f'Upload failed: {e}')
            return False
        except Exception as e:
            logger.error(f'Unexpected error processing {file_path}: {e}')
            return False

    def _generate_cas(self, workspace: str, target: Optional[str] = None) -> Optional[Path]:
        """
        Generate CAS YAML from Faraday workspace.

        Queries all data from Faraday workspace, formats it for the CAS
        formatter, and generates context.yaml. Optionally triggers PTT
        initialization.

        Args:
            workspace: Faraday workspace name
            target: Target identifier (defaults to workspace name)

        Returns:
            Path to generated context.yaml, or None if generation failed
        """
        target = target or workspace
        logger.info(f'Generating CAS for workspace {workspace}, target {target}')

        try:
            # Query Faraday for data
            hosts = self.client.get_hosts(workspace)
            vulns = self.client.get_vulnerabilities(workspace)
            services = self.client.get_services(workspace)
            stats = self.client.get_workspace_stats(workspace)

            logger.info(
                f'Fetched from Faraday: {len(hosts)} hosts, '
                f'{len(services)} services, {len(vulns)} vulns'
            )

            # Prepare data for CAS formatter
            cas_input: Dict[str, Any] = {
                'target': target,
                'session_id': f'{target}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}',
                'scan_type': 'faraday',
                'data': {
                    'hosts': hosts,
                    'vulnerabilities': vulns,
                    'services': services,
                    'stats': stats
                },
                'source': f'faraday:{workspace}',
                'timestamp': datetime.utcnow().isoformat()
            }

            # Create target directory
            cas_path = Path(f'/artifacts/{target}/context.yaml')
            cas_path.parent.mkdir(parents=True, exist_ok=True)

            # Call CAS formatter
            result = subprocess.run(
                ['python3', '/app/format-cas.py', str(cas_path)],
                input=json.dumps(cas_input),
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f'CAS formatter failed: {result.stderr}')
                return None

            logger.info(f'Generated CAS: {cas_path}')

            # Trigger PTT initialization
            if self.config.generate_ptt:
                self._init_ptt(cas_path)

            return cas_path

        except subprocess.TimeoutExpired:
            logger.error('CAS formatter timed out')
            return None
        except Exception as e:
            logger.error(f'CAS generation failed: {e}')
            return None

    def _init_ptt(self, cas_path: Path) -> bool:
        """
        Initialize PTT from CAS file.

        Args:
            cas_path: Path to context.yaml

        Returns:
            True if initialization successful
        """
        logger.info(f'Initializing PTT from {cas_path}')

        try:
            result = subprocess.run(
                ['python3', '/app/init-ptt.py', str(cas_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f'PTT initialization failed: {result.stderr}')
                return False

            ptt_path = cas_path.parent / 'ptt.yaml'
            logger.info(f'Initialized PTT: {ptt_path}')
            return True

        except subprocess.TimeoutExpired:
            logger.error('PTT initialization timed out')
            return False
        except Exception as e:
            logger.error(f'PTT initialization failed: {e}')
            return False

    def on_created(self, event: FileSystemEvent) -> None:
        """
        Handle new file creation.

        Args:
            event: File system event
        """
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        logger.debug(f'File created: {file_path}')
        self._handle_file_event(file_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        """
        Handle file modification.

        Args:
            event: File system event
        """
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        logger.debug(f'File modified: {file_path}')
        self._handle_file_event(file_path)


class AutoReconProcessor:
    """
    Handles batch processing of AutoRecon scan results.

    Detects completed AutoRecon scans by checking for completion markers,
    then uploads all scan files to Faraday for parsing.

    Attributes:
        client: FaradayClient for API calls
        config: WatcherConfig with paths and settings
        processed_targets: Set of already-processed target names
    """

    # File extensions to skip during upload
    SKIP_EXTENSIONS: Set[str] = {'.log', '.txt', '.md'}

    def __init__(self, client: FaradayClient, config: WatcherConfig):
        """
        Initialize the processor.

        Args:
            client: Authenticated FaradayClient
            config: WatcherConfig with paths and settings
        """
        self.client = client
        self.config = config
        self.processed_targets: Set[str] = set()
        self._storage_path = config.logs_dir / 'autorecon_processed.json'
        self._load_processed_targets()

    def _load_processed_targets(self) -> None:
        """Load processed targets from JSON storage."""
        if self._storage_path.exists():
            try:
                data = json.loads(self._storage_path.read_text())
                # Handle both old format (list) and new format (dict with 'targets' key)
                if isinstance(data, list):
                    self.processed_targets = set(data)
                else:
                    self.processed_targets = set(data.get('targets', []))
                logger.info(f'Loaded {len(self.processed_targets)} processed AutoRecon targets')
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f'Failed to load processed targets: {e}')
                self.processed_targets = set()

    def _save_processed_target(self, target: str) -> None:
        """Save target to processed list."""
        self.processed_targets.add(target)
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._storage_path.write_text(json.dumps({
                'targets': list(self.processed_targets)
            }, indent=2))
        except IOError as e:
            logger.error(f'Failed to save processed target: {e}')

    def is_scan_complete(self, target_dir: Path) -> bool:
        """
        Check if AutoRecon scan is complete.

        Looks for completion markers in the _commands.log file.

        Args:
            target_dir: Path to target directory (e.g., /artifacts/results/10.0.0.1)

        Returns:
            True if scan is complete (finished or interrupted)
        """
        commands_log = target_dir / 'scans' / '_commands.log'
        if not commands_log.exists():
            return False

        try:
            content = commands_log.read_text()
            return 'Finished scanning' in content or 'AutoRecon was interrupted' in content
        except IOError:
            return False

    def find_ready_targets(self) -> List[Path]:
        """
        Find completed AutoRecon targets not yet processed.

        Scans the results directory for target subdirectories with
        completed scans that haven't been processed yet.

        Returns:
            List of target directory paths ready for processing
        """
        ready = []

        if not self.config.results_dir.exists():
            return ready

        for target_dir in self.config.results_dir.iterdir():
            if not target_dir.is_dir():
                continue

            target_name = target_dir.name

            # Skip already processed
            if target_name in self.processed_targets:
                continue

            # Check if scan is complete
            if self.is_scan_complete(target_dir):
                ready.append(target_dir)
                logger.debug(f'Found ready target: {target_name}')

        return ready

    def process_target(self, target_dir: Path) -> bool:
        """
        Upload all scan files for a target to Faraday.

        Creates a workspace for the target and uploads all supported
        scan files from the scans directory.

        Args:
            target_dir: Path to target directory

        Returns:
            True if processing successful
        """
        target = target_dir.name
        # Make IP addresses workspace-safe
        workspace = sanitize_workspace_name(target)

        logger.info(f'Processing AutoRecon target: {target} -> workspace: {workspace}')

        try:
            # Create workspace
            if not self.client.workspace_exists(workspace):
                self.client.create_workspace(workspace, f'AutoRecon scan of {target}')

            # Find and upload all scan files
            scans_dir = target_dir / 'scans'
            if not scans_dir.exists():
                logger.warning(f'No scans directory for {target}')
                self._save_processed_target(target)
                return False

            uploaded = 0
            failed = 0

            for scan_file in scans_dir.rglob('*'):
                # Skip directories
                if not scan_file.is_file():
                    continue

                # Skip log files and empty files
                if scan_file.suffix.lower() in self.SKIP_EXTENSIONS:
                    continue
                if scan_file.stat().st_size == 0:
                    continue

                # Skip files starting with underscore (internal AutoRecon files)
                if scan_file.name.startswith('_'):
                    continue

                try:
                    self.client.upload_report(workspace, scan_file)
                    uploaded += 1
                except Exception as e:
                    logger.warning(f'Failed to upload {scan_file.name}: {e}')
                    failed += 1

            logger.info(f'Uploaded {uploaded} files for {target} ({failed} failed)')

            # Generate CAS
            if self.config.generate_cas:
                self._generate_cas(workspace, target)

            self._save_processed_target(target)
            return True

        except Exception as e:
            logger.error(f'Failed to process target {target}: {e}')
            return False

    def _generate_cas(self, workspace: str, target: str) -> Optional[Path]:
        """
        Generate CAS for the target.

        Args:
            workspace: Faraday workspace name
            target: Original target name

        Returns:
            Path to generated CAS file, or None if failed
        """
        logger.info(f'Generating CAS for AutoRecon target: {target}')

        try:
            # Query Faraday for data
            hosts = self.client.get_hosts(workspace)
            vulns = self.client.get_vulnerabilities(workspace)
            services = self.client.get_services(workspace)
            stats = self.client.get_workspace_stats(workspace)

            # Prepare data for CAS formatter
            cas_input: Dict[str, Any] = {
                'target': target,
                'session_id': f'{target}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}',
                'scan_type': 'autorecon',
                'data': {
                    'hosts': hosts,
                    'vulnerabilities': vulns,
                    'services': services,
                    'stats': stats
                },
                'source': f'faraday:{workspace}',
                'timestamp': datetime.utcnow().isoformat()
            }

            # Create target directory
            cas_path = Path(f'/artifacts/{target}/context.yaml')
            cas_path.parent.mkdir(parents=True, exist_ok=True)

            # Call CAS formatter
            result = subprocess.run(
                ['python3', '/app/format-cas.py', str(cas_path)],
                input=json.dumps(cas_input),
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f'CAS formatter failed: {result.stderr}')
                return None

            logger.info(f'Generated CAS: {cas_path}')

            # Trigger PTT initialization
            if self.config.generate_ptt:
                self._init_ptt(cas_path)

            return cas_path

        except Exception as e:
            logger.error(f'CAS generation failed for {target}: {e}')
            return None

    def _init_ptt(self, cas_path: Path) -> bool:
        """Initialize PTT from CAS file."""
        try:
            result = subprocess.run(
                ['python3', '/app/init-ptt.py', str(cas_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f'PTT initialization failed: {result.stderr}')
                return False

            logger.info(f'Initialized PTT for {cas_path.parent.name}')
            return True

        except Exception as e:
            logger.error(f'PTT initialization failed: {e}')
            return False

    def poll(self) -> int:
        """
        Poll for and process ready targets.

        Returns:
            Number of targets processed
        """
        ready = self.find_ready_targets()
        processed = 0

        for target_dir in ready:
            if self.process_target(target_dir):
                processed += 1

        return processed


# Healthcheck port from environment
HEALTHCHECK_PORT: int = int(os.getenv('HEALTHCHECK_PORT', '8080'))


class HealthCheckHandler(BaseHTTPRequestHandler):
    """
    Simple HTTP health check handler for container monitoring.

    Provides a /health endpoint that returns 200 when the watcher
    is healthy (authenticated with Faraday) or 503 when unhealthy.
    """

    # Set by start_healthcheck_server
    client: Optional[FaradayClient] = None

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == '/health':
            self._handle_health()
        elif self.path == '/ready':
            self._handle_ready()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_health(self) -> None:
        """Handle /health endpoint."""
        try:
            if self.client and self.client.authenticated:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "healthy"}')
            else:
                self.send_response(503)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "unhealthy", "reason": "not authenticated"}')
        except Exception:
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "unhealthy", "reason": "error"}')

    def _handle_ready(self) -> None:
        """Handle /ready endpoint (for k8s readiness probes)."""
        # Same as health for now
        self._handle_health()

    def log_message(self, format: str, *args) -> None:
        """Suppress access logging to reduce noise."""
        pass


def start_healthcheck_server(client: FaradayClient, port: int = HEALTHCHECK_PORT) -> HTTPServer:
    """
    Start healthcheck server in background thread.

    Args:
        client: FaradayClient to check authentication status
        port: Port to listen on (default from HEALTHCHECK_PORT env)

    Returns:
        HTTPServer instance (for potential shutdown)
    """
    HealthCheckHandler.client = client
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f'Healthcheck server started on port {port}')
    return server


def process_existing_files(directory: Path, handler: FaradayScanHandler) -> int:
    """
    Process existing scan files in a directory.

    Args:
        directory: Directory to scan
        handler: Handler to process files with

    Returns:
        Number of files processed
    """
    if not directory.exists():
        return 0

    processed = 0
    for file_path in directory.rglob('*'):
        if not file_path.is_file():
            continue
        if not handler._is_supported_file(file_path):
            continue
        if handler.tracker.is_processed(file_path):
            continue

        logger.info(f'Processing existing file: {file_path}')
        if handler.process_file(file_path):
            processed += 1

    return processed


def main():
    """Main entry point."""
    logger.info('=' * 60)
    logger.info('Faraday-integrated Enrichment Watcher Starting')
    logger.info('=' * 60)

    # Load configuration
    config = WatcherConfig()
    config.log_config()

    # Ensure directories exist
    config.raw_dir.mkdir(parents=True, exist_ok=True)
    config.results_dir.mkdir(parents=True, exist_ok=True)
    config.logs_dir.mkdir(parents=True, exist_ok=True)

    # Initialize Faraday client
    faraday_config = config.to_faraday_config()
    client = FaradayClient(faraday_config)

    # Authenticate with retry
    logger.info('Authenticating with Faraday...')
    max_retries = 5
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            if client.authenticate():
                logger.info('Authenticated successfully')
                break
        except Exception as e:
            logger.warning(f'Authentication attempt {attempt + 1} failed: {e}')

        if attempt < max_retries - 1:
            logger.info(f'Retrying in {retry_delay}s...')
            time.sleep(retry_delay)
            retry_delay *= 2  # Exponential backoff
    else:
        logger.error('Failed to authenticate with Faraday after retries')
        sys.exit(1)

    # Start healthcheck server
    start_healthcheck_server(client)

    # Initialize processors
    tracker = ProcessedFileTracker(config.logs_dir / 'faraday_processed.json')
    handler = FaradayScanHandler(client, config, tracker)
    autorecon = AutoReconProcessor(client, config)

    # Process existing files
    logger.info('Processing existing files...')
    existing_count = process_existing_files(config.raw_dir, handler)
    logger.info(f'Processed {existing_count} existing files')

    # Process existing AutoRecon targets
    logger.info('Checking for completed AutoRecon scans...')
    autorecon_count = autorecon.poll()
    logger.info(f'Processed {autorecon_count} AutoRecon targets')

    # Start watchdog observer
    observer = Observer()
    observer.schedule(handler, str(config.raw_dir), recursive=True)
    observer.start()
    logger.info(f'Watching for new scans in: {config.raw_dir}')

    # Main loop with AutoRecon polling
    last_autorecon_check = time.time()

    try:
        while True:
            time.sleep(1)

            # Periodic AutoRecon check
            now = time.time()
            if now - last_autorecon_check >= config.autorecon_poll_interval:
                targets_processed = autorecon.poll()
                if targets_processed > 0:
                    logger.info(f'Processed {targets_processed} AutoRecon targets')
                last_autorecon_check = now

    except KeyboardInterrupt:
        logger.info('Shutting down...')
        observer.stop()

    observer.join()
    logger.info('Watcher stopped')


if __name__ == '__main__':
    main()
