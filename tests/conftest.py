"""Root pytest configuration for tests."""
import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (uses real parsers)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow (involves network operations or long timeouts)"
    )
    config.addinivalue_line(
        "markers", "qdrant: mark test as requiring Qdrant container (session memory tests)"
    )
