#!/usr/bin/env python3
"""
Index extracted skills into Qdrant vector database.

Embeds skill trigger conditions for semantic search.
Dame queries this to find relevant techniques based on CAS observations.

Usage:
    # Index Windows skills
    python index_skills.py --input ./skills_corpus/all_skills.jsonl --platform windows

    # Index Linux skills
    python index_skills.py --input ./skills_corpus/linux_skills.jsonl --platform linux

    # Search (no platform required)
    python index_skills.py --search "SMB anonymous share" --limit 5
"""

import argparse
import json
import hashlib
import sys
from enum import Enum
from pathlib import Path
from typing import Optional


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SkillIndexer:
    def __init__(self, qdrant_url: str = "http://localhost:6333",
                 collection_name: str = "skills",
                 model_name: str = "all-MiniLM-L6-v2",
                 platform: Optional[Platform] = None):
        self.qdrant_url = qdrant_url.rstrip('/')
        self.collection_name = collection_name
        self.model_name = model_name
        self.platform = platform
        self.model: Optional[SentenceTransformer] = None
        self.vector_size = 384  # all-MiniLM-L6-v2 dimension
        # Named vector for mcp-server-qdrant compatibility
        # Format: "fast-" + lowercase model name
        self.vector_name = "fast-" + model_name.lower().replace("/", "-").replace("sentence-transformers-", "")

    def _ensure_model(self):
        """Lazy load the embedding model."""
        if self.model is None:
            if not HAS_SENTENCE_TRANSFORMERS:
                print("Error: sentence-transformers not installed")
                print("Run: pip install sentence-transformers")
                sys.exit(1)
            print(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)

    def _create_collection(self):
        """Create Qdrant collection if it doesn't exist."""
        # Check if collection exists
        resp = requests.get(f"{self.qdrant_url}/collections/{self.collection_name}")

        if resp.status_code == 200:
            print(f"Collection '{self.collection_name}' already exists")
            return True

        # Create collection with named vector for mcp-server-qdrant compatibility
        config = {
            "vectors": {
                self.vector_name: {
                    "size": self.vector_size,
                    "distance": "Cosine"
                }
            }
        }

        resp = requests.put(
            f"{self.qdrant_url}/collections/{self.collection_name}",
            json=config
        )

        if resp.status_code == 200:
            print(f"Created collection '{self.collection_name}' with vector '{self.vector_name}'")
            return True
        else:
            print(f"Failed to create collection: {resp.text}")
            return False

    def _skill_to_text(self, skill: dict) -> str:
        """Convert skill trigger conditions to searchable text."""
        parts = []

        trigger = skill.get("trigger", {})

        # Service
        if service := trigger.get("service"):
            parts.append(f"service: {service}")

        # Indicators
        if indicators := trigger.get("indicators"):
            if isinstance(indicators, list):
                parts.extend(indicators)
            else:
                parts.append(str(indicators))

        # Name (for context)
        if name := skill.get("name"):
            parts.append(name)

        # Category
        if category := skill.get("category"):
            parts.append(f"category: {category}")

        return " | ".join(parts)

    def _skill_id(self, skill: dict) -> str:
        """Generate deterministic ID for skill."""
        # Use hash of name + source video for deduplication
        key = f"{skill.get('name', '')}:{skill.get('_source_video', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def index_skills(self, jsonl_path: Path, batch_size: int = 100):
        """Index all skills from JSONL file."""
        if not HAS_REQUESTS:
            print("Error: requests not installed")
            print("Run: pip install requests")
            sys.exit(1)

        self._ensure_model()

        # Create collection
        if not self._create_collection():
            return

        # Load skills
        skills = []
        with open(jsonl_path) as f:
            for line in f:
                if line.strip():
                    try:
                        skills.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        print(f"Loaded {len(skills)} skills from {jsonl_path}")

        # Process in batches
        total_indexed = 0

        for i in range(0, len(skills), batch_size):
            batch = skills[i:i + batch_size]

            # Generate texts and embeddings
            texts = [self._skill_to_text(s) for s in batch]
            embeddings = self.model.encode(texts, show_progress_bar=False)

            # Prepare points for Qdrant
            # Schema matches mcp-server-qdrant expectations:
            #   document: searchable text (trigger conditions)
            #   metadata: full skill object for Dame to use
            #   Named vector: matches embedding provider naming convention
            points = []
            for j, (skill, embedding) in enumerate(zip(batch, embeddings)):
                metadata = {
                    "name": skill.get("name", ""),
                    "category": skill.get("category", ""),
                    "trigger": skill.get("trigger", {}),
                    "prerequisites": skill.get("prerequisites", {}),
                    "execution": skill.get("execution", []),
                    "decision_points": skill.get("decision_points", []),
                    "success_indicators": skill.get("success_indicators", []),
                    "follow_up": skill.get("follow_up", []),
                    "references": skill.get("references", {}),
                    "_source_video": skill.get("_source_video", "")
                }
                # Add platform if specified
                if self.platform:
                    metadata["platform"] = self.platform.value

                point = {
                    "id": self._skill_id(skill),  # Deterministic hash ID for deduplication
                    "vector": {self.vector_name: embedding.tolist()},  # Named vector
                    "payload": {
                        "document": texts[j],  # Searchable trigger text
                        "metadata": metadata
                    }
                }
                points.append(point)

            # Upsert to Qdrant
            resp = requests.put(
                f"{self.qdrant_url}/collections/{self.collection_name}/points",
                json={"points": points},
                params={"wait": "true"}
            )

            if resp.status_code == 200:
                total_indexed += len(batch)
                print(f"Indexed {total_indexed}/{len(skills)} skills")
            else:
                print(f"Failed to index batch: {resp.text}")

        print(f"\n✓ Indexed {total_indexed} skills into '{self.collection_name}'")

    def search(self, query: str, limit: int = 5) -> list[dict]:
        """Search for skills matching a query."""
        self._ensure_model()

        # Embed query
        embedding = self.model.encode(query).tolist()

        # Search Qdrant with named vector
        resp = requests.post(
            f"{self.qdrant_url}/collections/{self.collection_name}/points/search",
            json={
                "vector": {
                    "name": self.vector_name,
                    "vector": embedding
                },
                "limit": limit,
                "with_payload": True
            }
        )

        if resp.status_code != 200:
            print(f"Search failed: {resp.text}")
            return []

        results = resp.json().get("result", [])
        return [
            {
                "score": r["score"],
                "document": r["payload"].get("document", ""),
                "skill": r["payload"].get("metadata", r["payload"])  # Fallback for old schema
            }
            for r in results
        ]


def main():
    parser = argparse.ArgumentParser(
        description="Index skills into Qdrant vector database"
    )

    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=Path('./skills_corpus/all_skills.jsonl'),
        help='JSONL file with extracted skills'
    )
    parser.add_argument(
        '--qdrant', '-q',
        type=str,
        default='http://localhost:6333',
        help='Qdrant server URL'
    )
    parser.add_argument(
        '--collection', '-c',
        type=str,
        default='skills',
        help='Collection name'
    )
    parser.add_argument(
        '--platform', '-p',
        type=str,
        choices=[p.value for p in Platform],
        help='Platform for skills (windows, linux). Required for indexing.'
    )
    parser.add_argument(
        '--search', '-s',
        type=str,
        help='Test search query (instead of indexing)'
    )
    parser.add_argument(
        '--limit', '-l',
        type=int,
        default=5,
        help='Number of results for search'
    )

    args = parser.parse_args()

    # Parse platform if provided
    platform = Platform(args.platform) if args.platform else None

    indexer = SkillIndexer(
        qdrant_url=args.qdrant,
        collection_name=args.collection,
        platform=platform
    )

    if args.search:
        # Search mode
        print(f"Searching for: {args.search}\n")
        results = indexer.search(args.search, args.limit)

        for i, r in enumerate(results, 1):
            skill = r["skill"]
            print(f"{i}. [{r['score']:.3f}] {skill['name']}")
            print(f"   Category: {skill['category']}")
            print(f"   Trigger: {skill['trigger']}")
            if skill.get('execution'):
                print(f"   Execution: {skill['execution'][0][:60]}...")
            print()
    else:
        # Index mode
        if not args.input.exists():
            print(f"Error: Input file not found: {args.input}")
            sys.exit(1)

        if not args.platform:
            print("Error: --platform is required for indexing")
            print("  Use: --platform windows  or  --platform linux")
            sys.exit(1)

        indexer.index_skills(args.input)


if __name__ == '__main__':
    main()
