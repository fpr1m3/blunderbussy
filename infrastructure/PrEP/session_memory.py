#!/usr/bin/env python3
"""
Session Memory - Qdrant-backed semantic search over session history.
====================================================================

Creates per-target collections for:
- Technique attempts and outcomes
- Error resolutions
- Significant discoveries

Enables queries like:
- "I've seen this error before, what worked?"
- "What have I tried on port 22?"
- "How did I solve this on similar boxes?"

Usage:
    from session_memory import SessionMemory

    mem = SessionMemory.for_target("10.129.5.135")

    # Index an event
    mem.index_event(
        event_type="technique_attempt",
        context="Tried SQLi UNION SELECT on login form",
        outcome="blocked",
        technique_id="sqli_union_basic",
        tags=["sqli", "waf", "port_80"]
    )

    # Search for similar experiences
    results = mem.search("WAF blocking UNION SELECT", event_type="error_resolution")
"""

import hashlib
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False


class EventType(str, Enum):
    """Types of events indexed in session memory."""
    TECHNIQUE_ATTEMPT = "technique_attempt"
    ERROR_RESOLUTION = "error_resolution"
    DISCOVERY = "discovery"
    CREDENTIAL_FOUND = "credential_found"
    ACCESS_GAINED = "access_gained"
    FLAG_CAPTURED = "flag_captured"


class Outcome(str, Enum):
    """Outcome of a technique attempt."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    PENDING = "pending"


@dataclass
class SessionEvent:
    """An event to index in session memory."""
    event_type: EventType
    context: str  # Full context of the event (will be embedded)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    technique_id: Optional[str] = None  # PTT reference
    outcome: Optional[Outcome] = None
    resolution: Optional[str] = None  # How it was resolved (for error_resolution)
    tags: list[str] = field(default_factory=list)

    def to_payload(self) -> dict:
        """Convert to Qdrant payload format."""
        return {
            "event_type": self.event_type.value,
            "context": self.context,
            "timestamp": self.timestamp,
            "technique_id": self.technique_id,
            "outcome": self.outcome.value if self.outcome else None,
            "resolution": self.resolution,
            "tags": self.tags,
        }


@dataclass
class SearchResult:
    """A search result from session memory."""
    score: float
    event_type: str
    context: str
    timestamp: str
    technique_id: Optional[str]
    outcome: Optional[str]
    resolution: Optional[str]
    tags: list[str]


class SessionMemory:
    """
    Qdrant-backed semantic search over session history.

    Creates one collection per target for isolation.
    """

    # Embedding model - must match mcp-server-qdrant config
    MODEL_NAME = "all-MiniLM-L6-v2"
    VECTOR_SIZE = 384
    VECTOR_NAME = "fast-all-minilm-l6-v2"

    def __init__(
        self,
        target: str,
        qdrant_url: str = "http://qdrant:6333",
    ):
        """
        Initialize session memory for a target.

        Args:
            target: Target IP or hostname
            qdrant_url: Qdrant REST API URL
        """
        self.target = target
        self.qdrant_url = qdrant_url.rstrip('/')
        self.collection_name = self._collection_name(target)
        self._model: Optional[SentenceTransformer] = None

    @classmethod
    def for_target(
        cls,
        target: str,
        qdrant_url: Optional[str] = None,
    ) -> "SessionMemory":
        """
        Factory method to create SessionMemory for a target.

        Uses QDRANT_URL env var if not specified.
        """
        url = qdrant_url or os.environ.get("QDRANT_URL", "http://qdrant:6333")
        return cls(target=target, qdrant_url=url)

    @staticmethod
    def _collection_name(target: str) -> str:
        """Generate collection name from target."""
        # Hash the target for consistent naming
        target_hash = hashlib.md5(target.encode()).hexdigest()[:12]
        return f"dame_session_{target_hash}"

    @staticmethod
    def _event_id(event: SessionEvent) -> str:
        """Generate deterministic ID for event."""
        key = f"{event.timestamp}:{event.context[:100]}"
        return hashlib.md5(key.encode()).hexdigest()

    def _ensure_model(self):
        """Lazy load embedding model."""
        if self._model is None:
            if not HAS_SENTENCE_TRANSFORMERS:
                raise RuntimeError(
                    "sentence-transformers not installed. "
                    "Run: pip install sentence-transformers"
                )
            self._model = SentenceTransformer(self.MODEL_NAME)

    def _ensure_requests(self):
        """Check requests is available."""
        if not HAS_REQUESTS:
            raise RuntimeError(
                "requests not installed. Run: pip install requests"
            )

    def _ensure_collection(self) -> bool:
        """Create collection if it doesn't exist."""
        self._ensure_requests()

        # Check if exists
        resp = requests.get(
            f"{self.qdrant_url}/collections/{self.collection_name}"
        )

        if resp.status_code == 200:
            return True

        # Create with named vector
        config = {
            "vectors": {
                self.VECTOR_NAME: {
                    "size": self.VECTOR_SIZE,
                    "distance": "Cosine"
                }
            }
        }

        resp = requests.put(
            f"{self.qdrant_url}/collections/{self.collection_name}",
            json=config
        )

        return resp.status_code == 200

    def index_event(
        self,
        event_type: EventType | str,
        context: str,
        outcome: Optional[Outcome | str] = None,
        technique_id: Optional[str] = None,
        resolution: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> bool:
        """
        Index an event in session memory.

        Args:
            event_type: Type of event (technique_attempt, error_resolution, etc.)
            context: Full context description (will be embedded for search)
            outcome: Outcome if applicable (success, failed, blocked, partial)
            technique_id: PTT technique reference if applicable
            resolution: How it was resolved (for error_resolution events)
            tags: Additional tags for filtering

        Returns:
            True if indexed successfully
        """
        self._ensure_model()
        self._ensure_collection()

        # Normalize enums
        if isinstance(event_type, str):
            event_type = EventType(event_type)
        if isinstance(outcome, str):
            outcome = Outcome(outcome) if outcome else None

        event = SessionEvent(
            event_type=event_type,
            context=context,
            outcome=outcome,
            technique_id=technique_id,
            resolution=resolution,
            tags=tags or [],
        )

        # Embed the context
        embedding = self._model.encode(context).tolist()

        # Create point
        point = {
            "id": self._event_id(event),
            "vector": {self.VECTOR_NAME: embedding},
            "payload": event.to_payload(),
        }

        # Upsert to Qdrant
        resp = requests.put(
            f"{self.qdrant_url}/collections/{self.collection_name}/points",
            json={"points": [point]},
            params={"wait": "true"}
        )

        return resp.status_code == 200

    def search(
        self,
        query: str,
        event_type: Optional[EventType | str] = None,
        outcome: Optional[Outcome | str] = None,
        limit: int = 5,
    ) -> list[SearchResult]:
        """
        Search session memory for similar events.

        Args:
            query: Natural language search query
            event_type: Filter by event type
            outcome: Filter by outcome
            limit: Maximum results to return

        Returns:
            List of matching events ranked by similarity
        """
        self._ensure_model()
        self._ensure_requests()

        # Check collection exists
        resp = requests.get(
            f"{self.qdrant_url}/collections/{self.collection_name}"
        )
        if resp.status_code != 200:
            return []  # No collection yet

        # Embed query
        embedding = self._model.encode(query).tolist()

        # Build filter
        filter_conditions = []

        if event_type:
            if isinstance(event_type, str):
                event_type = EventType(event_type)
            filter_conditions.append({
                "key": "event_type",
                "match": {"value": event_type.value}
            })

        if outcome:
            if isinstance(outcome, str):
                outcome = Outcome(outcome)
            filter_conditions.append({
                "key": "outcome",
                "match": {"value": outcome.value}
            })

        # Search request
        search_body = {
            "vector": {
                "name": self.VECTOR_NAME,
                "vector": embedding
            },
            "limit": limit,
            "with_payload": True,
        }

        if filter_conditions:
            search_body["filter"] = {
                "must": filter_conditions
            }

        resp = requests.post(
            f"{self.qdrant_url}/collections/{self.collection_name}/points/search",
            json=search_body
        )

        if resp.status_code != 200:
            return []

        results = []
        for hit in resp.json().get("result", []):
            payload = hit.get("payload", {})
            results.append(SearchResult(
                score=hit["score"],
                event_type=payload.get("event_type", ""),
                context=payload.get("context", ""),
                timestamp=payload.get("timestamp", ""),
                technique_id=payload.get("technique_id"),
                outcome=payload.get("outcome"),
                resolution=payload.get("resolution"),
                tags=payload.get("tags", []),
            ))

        return results

    def search_errors(
        self,
        error_description: str,
        limit: int = 3,
    ) -> list[SearchResult]:
        """
        Search for similar errors and their resolutions.

        Convenience method for "I've seen this before, what worked?"
        """
        return self.search(
            query=error_description,
            event_type=EventType.ERROR_RESOLUTION,
            outcome=Outcome.SUCCESS,
            limit=limit,
        )

    def search_techniques(
        self,
        description: str,
        limit: int = 5,
    ) -> list[SearchResult]:
        """
        Search for similar technique attempts.

        Convenience method for "What have I tried on this service?"
        """
        return self.search(
            query=description,
            event_type=EventType.TECHNIQUE_ATTEMPT,
            limit=limit,
        )

    def get_stats(self) -> dict:
        """Get collection statistics."""
        self._ensure_requests()

        resp = requests.get(
            f"{self.qdrant_url}/collections/{self.collection_name}"
        )

        if resp.status_code != 200:
            return {"exists": False, "points_count": 0}

        data = resp.json().get("result", {})
        return {
            "exists": True,
            "points_count": data.get("points_count", 0),
            "vectors_count": data.get("vectors_count", 0),
            "status": data.get("status", "unknown"),
        }

    def delete_collection(self) -> bool:
        """Delete the session memory collection."""
        self._ensure_requests()

        resp = requests.delete(
            f"{self.qdrant_url}/collections/{self.collection_name}"
        )

        return resp.status_code == 200


# =============================================================================
# Cross-Session Search
# =============================================================================

def search_all_sessions(
    query: str,
    qdrant_url: str = "http://qdrant:6333",
    limit: int = 10,
) -> list[dict]:
    """
    Search across ALL session memory collections.

    Useful for "How did I solve this on similar boxes?"

    Returns results with target info included.
    """
    if not HAS_REQUESTS:
        raise RuntimeError("requests not installed")
    if not HAS_SENTENCE_TRANSFORMERS:
        raise RuntimeError("sentence-transformers not installed")

    qdrant_url = qdrant_url.rstrip('/')

    # List all collections
    resp = requests.get(f"{qdrant_url}/collections")
    if resp.status_code != 200:
        return []

    collections = resp.json().get("result", {}).get("collections", [])
    session_collections = [
        c["name"] for c in collections
        if c["name"].startswith("dame_session_")
    ]

    if not session_collections:
        return []

    # Embed query once
    model = SentenceTransformer(SessionMemory.MODEL_NAME)
    embedding = model.encode(query).tolist()

    # Search each collection
    all_results = []

    for collection in session_collections:
        search_body = {
            "vector": {
                "name": SessionMemory.VECTOR_NAME,
                "vector": embedding
            },
            "limit": limit,
            "with_payload": True,
        }

        resp = requests.post(
            f"{qdrant_url}/collections/{collection}/points/search",
            json=search_body
        )

        if resp.status_code == 200:
            for hit in resp.json().get("result", []):
                payload = hit.get("payload", {})
                all_results.append({
                    "score": hit["score"],
                    "collection": collection,
                    "event_type": payload.get("event_type"),
                    "context": payload.get("context"),
                    "outcome": payload.get("outcome"),
                    "resolution": payload.get("resolution"),
                    "timestamp": payload.get("timestamp"),
                })

    # Sort by score and limit
    all_results.sort(key=lambda x: x["score"], reverse=True)
    return all_results[:limit]


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """CLI for testing session memory."""
    import argparse

    parser = argparse.ArgumentParser(description="Session Memory CLI")
    parser.add_argument("--target", "-t", required=True, help="Target IP/hostname")
    parser.add_argument("--qdrant", default="http://localhost:6333", help="Qdrant URL")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Index command
    index_parser = subparsers.add_parser("index", help="Index an event")
    index_parser.add_argument("--type", required=True, choices=[e.value for e in EventType])
    index_parser.add_argument("--context", required=True, help="Event context")
    index_parser.add_argument("--outcome", choices=[o.value for o in Outcome])
    index_parser.add_argument("--technique", help="Technique ID")
    index_parser.add_argument("--resolution", help="Resolution description")
    index_parser.add_argument("--tags", nargs="+", default=[])

    # Search command
    search_parser = subparsers.add_parser("search", help="Search events")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--type", choices=[e.value for e in EventType])
    search_parser.add_argument("--outcome", choices=[o.value for o in Outcome])
    search_parser.add_argument("--limit", type=int, default=5)

    # Stats command
    subparsers.add_parser("stats", help="Show collection stats")

    # Cross-session search
    cross_parser = subparsers.add_parser("cross-search", help="Search all sessions")
    cross_parser.add_argument("query", help="Search query")
    cross_parser.add_argument("--limit", type=int, default=10)

    args = parser.parse_args()

    mem = SessionMemory.for_target(args.target, args.qdrant)

    if args.command == "index":
        success = mem.index_event(
            event_type=args.type,
            context=args.context,
            outcome=args.outcome,
            technique_id=args.technique,
            resolution=args.resolution,
            tags=args.tags,
        )
        print("Indexed" if success else "Failed to index")

    elif args.command == "search":
        results = mem.search(
            query=args.query,
            event_type=args.type,
            outcome=args.outcome,
            limit=args.limit,
        )

        if not results:
            print("No results found")
            return

        for i, r in enumerate(results, 1):
            print(f"\n{i}. [{r.score:.3f}] {r.event_type}")
            print(f"   Context: {r.context[:80]}...")
            if r.outcome:
                print(f"   Outcome: {r.outcome}")
            if r.resolution:
                print(f"   Resolution: {r.resolution[:60]}...")
            if r.technique_id:
                print(f"   Technique: {r.technique_id}")

    elif args.command == "stats":
        stats = mem.get_stats()
        print(f"Collection: {mem.collection_name}")
        print(f"Exists: {stats['exists']}")
        print(f"Points: {stats['points_count']}")

    elif args.command == "cross-search":
        results = search_all_sessions(
            query=args.query,
            qdrant_url=args.qdrant,
            limit=args.limit,
        )

        if not results:
            print("No results across sessions")
            return

        for i, r in enumerate(results, 1):
            print(f"\n{i}. [{r['score']:.3f}] {r['collection']}")
            print(f"   Type: {r['event_type']}")
            print(f"   Context: {r['context'][:60]}...")
            if r['resolution']:
                print(f"   Resolution: {r['resolution'][:60]}...")


if __name__ == "__main__":
    main()
