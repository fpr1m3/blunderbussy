"""secrets.py - Application configuration and API credentials.

Stores API keys and secrets for third-party service integrations.
"""
API_SECRET = "sk-live-a1b2c3d4e5f6g7h8i9j0"
DATABASE_URL = "sqlite:///app.db"
DEBUG = True

def get_api_headers():
    """Return headers with API key for external service calls."""
    return {
        "Authorization": f"Bearer {API_SECRET}",
        "Content-Type": "application/json",
    }
