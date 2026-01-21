"""Shared fixtures for parser tests."""
import sys
from pathlib import Path

import pytest

# Add parsers to path for imports
PARSERS_DIR = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers"
sys.path.insert(0, str(PARSERS_DIR))

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture
def enum4linux_fixtures():
    """Return enum4linux fixtures directory."""
    return FIXTURES_DIR / "enum4linux"


@pytest.fixture
def feroxbuster_fixtures():
    """Return feroxbuster fixtures directory."""
    return FIXTURES_DIR / "feroxbuster"


@pytest.fixture
def smbmap_fixtures():
    """Return smbmap fixtures directory."""
    return FIXTURES_DIR / "smbmap"


@pytest.fixture
def onesixtyone_fixtures():
    """Return onesixtyone fixtures directory."""
    return FIXTURES_DIR / "onesixtyone"


@pytest.fixture
def showmount_fixtures():
    """Return showmount fixtures directory."""
    return FIXTURES_DIR / "showmount"


@pytest.fixture
def ffuf_fixtures():
    """Return ffuf fixtures directory."""
    return FIXTURES_DIR / "ffuf"


@pytest.fixture
def dnsrecon_fixtures():
    """Return dnsrecon fixtures directory."""
    return FIXTURES_DIR / "dnsrecon"


@pytest.fixture
def sslscan_fixtures():
    """Return sslscan fixtures directory."""
    return FIXTURES_DIR / "sslscan"


@pytest.fixture
def snmpwalk_fixtures():
    """Return snmpwalk fixtures directory."""
    return FIXTURES_DIR / "snmpwalk"


@pytest.fixture
def wpscan_fixtures():
    """Return wpscan fixtures directory."""
    return FIXTURES_DIR / "wpscan"


@pytest.fixture
def dirsearch_fixtures():
    """Return dirsearch fixtures directory."""
    return FIXTURES_DIR / "dirsearch"


@pytest.fixture
def rpcdump_fixtures():
    """Return rpcdump fixtures directory."""
    return FIXTURES_DIR / "rpcdump"


@pytest.fixture
def redis_cli_fixtures():
    """Return redis-cli fixtures directory."""
    return FIXTURES_DIR / "redis-cli"


@pytest.fixture
def dirb_fixtures():
    """Return dirb fixtures directory."""
    return FIXTURES_DIR / "dirb"


@pytest.fixture
def dig_fixtures():
    """Return dig fixtures directory."""
    return FIXTURES_DIR / "dig"
