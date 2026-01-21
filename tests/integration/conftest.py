"""Integration test fixtures for AutoReconProcessor."""
import json
import logging
import os
import sys
from io import StringIO
from pathlib import Path
from typing import Dict, Any
from unittest.mock import patch, MagicMock

import pytest

# Add infrastructure modules to path
INFRASTRUCTURE_DIR = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment"
PARSERS_DIR = INFRASTRUCTURE_DIR / "parsers"
sys.path.insert(0, str(INFRASTRUCTURE_DIR))
sys.path.insert(0, str(PARSERS_DIR))

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# Session-scoped fixture to create temp artifacts directory early
@pytest.fixture(scope="session")
def session_tmp_dir(tmp_path_factory):
    """Create session-level temp directory for artifacts."""
    tmp = tmp_path_factory.mktemp("artifacts")
    (tmp / "logs").mkdir(parents=True, exist_ok=True)
    (tmp / "results").mkdir(parents=True, exist_ok=True)
    return tmp


@pytest.fixture(scope="session", autouse=True)
def setup_watcher_module(session_tmp_dir):
    """
    Setup watcher module import by patching logging before import.

    This fixture runs once per session before any tests.
    """
    # Create the artifacts directory structure that watcher.py expects
    artifacts_logs = Path("/tmp/test_artifacts/logs")
    artifacts_logs.mkdir(parents=True, exist_ok=True)

    # Patch logging.FileHandler before importing watcher
    original_file_handler = logging.FileHandler

    class SafeFileHandler(logging.FileHandler):
        """File handler that creates parent directories if needed."""

        def __init__(self, filename, mode='a', encoding=None, delay=False):
            # Use temp directory for test logs
            test_log_path = session_tmp_dir / "logs" / "enrichment.log"
            test_log_path.parent.mkdir(parents=True, exist_ok=True)
            super().__init__(str(test_log_path), mode, encoding, delay)

    # Patch the FileHandler
    logging.FileHandler = SafeFileHandler

    yield

    # Restore original
    logging.FileHandler = original_file_handler


@pytest.fixture
def fixtures_dir():
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture
def autorecon_fixtures():
    """Return autorecon fixture directory."""
    return FIXTURES_DIR / "autorecon"


@pytest.fixture
def tmp_artifacts(tmp_path):
    """Create temporary artifacts directory structure."""
    artifacts = tmp_path / "artifacts"
    (artifacts / "logs").mkdir(parents=True)
    (artifacts / "results").mkdir(parents=True)
    return artifacts


@pytest.fixture
def mock_parser_responses() -> Dict[str, Dict[str, Any]]:
    """Standard parser output for mocking subprocess calls."""
    return {
        "enum4linux": {
            "type": "enum4linux",
            "target": "10.10.10.3",
            "os_info": {
                "native_os": "Unix",
                "native_lanman": "Samba 3.0.20-Debian",
                "workgroup": "WORKGROUP",
                "domain": None
            },
            "shares": [
                {"name": "print$", "type": "Disk", "comment": "Printer Drivers"},
                {"name": "tmp", "type": "Disk", "comment": "oh nance!", "accessible": True},
                {"name": "IPC$", "type": "IPC", "comment": "IPC Service"}
            ],
            "users": [
                {"username": "root", "rid": "0x3e8"},
                {"username": "msfadmin", "rid": "0xbb8"},
                {"username": "user", "rid": "0xbba"}
            ],
            "groups": {
                "local": [],
                "domain": [],
                "builtin": [{"name": "Administrators", "rid": "0x220"}]
            },
            "password_policy": {"min_length": 5},
            "sessions": [],
            "stats": {
                "shares_found": 3,
                "users_found": 3,
                "groups_found": 1,
                "interesting": ["Accessible share: tmp", "Enumerated 3 users"]
            }
        },
        "smbmap": {
            "type": "smbmap",
            "target": "10.10.10.3",
            "hostname": "lame.htb",
            "shares": [
                {"name": "print$", "type": "Disk", "permissions": "NO ACCESS", "readable": False, "writable": False},
                {"name": "tmp", "type": "Disk", "permissions": "READ, WRITE", "readable": True, "writable": True},
                {"name": "IPC$", "type": "IPC", "permissions": "NO ACCESS", "readable": False, "writable": False}
            ],
            "file_listings": {},
            "stats": {
                "shares_found": 3,
                "readable_shares": 1,
                "writable_shares": 1,
                "files_listed": 0,
                "interesting_files": [],
                "interesting": ["Writable share: tmp", "Readable share: tmp"]
            }
        },
        "feroxbuster": {
            "type": "feroxbuster",
            "target": "http://10.10.10.15",
            "config": {"threads": 50, "timeout": 7},
            "findings": [
                {"status": 200, "method": "GET", "lines": 12, "words": 25, "size": 321, "url": "http://10.10.10.15/", "path": "/"},
                {"status": 301, "method": "GET", "lines": 9, "words": 28, "size": 315, "url": "http://10.10.10.15/images", "path": "/images"},
                {"status": 200, "method": "GET", "lines": 42, "words": 89, "size": 1285, "url": "http://10.10.10.15/index.html", "path": "/index.html"},
                {"status": 301, "method": "GET", "lines": 9, "words": 28, "size": 315, "url": "http://10.10.10.15/admin", "path": "/admin"},
                {"status": 200, "method": "GET", "lines": 28, "words": 65, "size": 892, "url": "http://10.10.10.15/admin/login.php", "path": "/admin/login.php"},
                {"status": 403, "method": "GET", "lines": 11, "words": 32, "size": 304, "url": "http://10.10.10.15/.git/", "path": "/.git/"}
            ],
            "stats": {
                "total_found": 6,
                "status_codes": {"200": 3, "301": 2, "403": 1},
                "interesting": ["/admin", "/admin/login.php", "/.git/"],
                "directories": ["/", "/images", "/admin"],
                "files": ["/index.html", "/admin/login.php", "/.git/"]
            }
        }
    }


@pytest.fixture
def patched_watcher_module(tmp_artifacts, autorecon_fixtures, monkeypatch):
    """
    Import and patch watcher module with test paths.

    Returns the patched watcher module.
    """
    # Import the watcher module (logging is already patched by session fixture)
    import watcher

    # Patch the global path constants
    monkeypatch.setattr(watcher, "LOGS_DIR", tmp_artifacts / "logs")
    monkeypatch.setattr(watcher, "RESULTS_DIR", autorecon_fixtures)
    monkeypatch.setattr(watcher, "PARSERS_DIR", PARSERS_DIR)

    return watcher


@pytest.fixture
def autorecon_processor(patched_watcher_module):
    """Create AutoReconProcessor with mocked paths (no subprocess mocking)."""
    pipeline = patched_watcher_module.EnrichmentPipeline()
    return patched_watcher_module.AutoReconProcessor(pipeline)


@pytest.fixture
def autorecon_processor_real(patched_watcher_module):
    """
    Create AutoReconProcessor using real parsers for true integration tests.

    This fixture is for tests marked with @pytest.mark.integration.
    """
    pipeline = patched_watcher_module.EnrichmentPipeline()
    return patched_watcher_module.AutoReconProcessor(pipeline)


@pytest.fixture
def mock_subprocess_run(monkeypatch, mock_parser_responses):
    """
    Mock subprocess.run to return predefined parser outputs.

    Captures calls and returns appropriate mock data based on the parser script.
    """
    import subprocess

    calls = []

    def mock_run(args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})

        # Determine which parser is being called
        script_name = Path(args[1]).name if len(args) > 1 else ""

        result = subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

        if "enum4linux" in script_name:
            result.stdout = json.dumps(mock_parser_responses["enum4linux"])
        elif "smbmap" in script_name:
            result.stdout = json.dumps(mock_parser_responses["smbmap"])
        elif "feroxbuster" in script_name:
            result.stdout = json.dumps(mock_parser_responses["feroxbuster"])
        elif "format-cas" in str(args):
            # CAS formatter - just succeed
            result.stdout = "{}"
        else:
            # Unknown parser - return empty
            result.stdout = "{}"

        return result

    monkeypatch.setattr(subprocess, "run", mock_run)

    return calls
