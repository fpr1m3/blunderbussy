#!/usr/bin/env python3
"""
Session State Management for Dame
==================================
Manages runtime session state for Dame exploitation workflow using hierarchical blocks.

This module complements PTT (what to do) with session state (how it's going),
tracking credentials, hypotheses, shells, and query caching for context efficiency.

Directory Structure:
    /artifacts/{target}/session/
    ├── state.yaml          # Core state (always loaded)
    ├── credentials.yaml    # Credential store
    ├── hypotheses.yaml     # Hypothesis tracking
    ├── attack_log.jsonl    # Append-only action log
    ├── query_cache.yaml    # Deduplication cache
    ├── files/              # Analyzed file cache
    │   └── {sha256}.yaml
    └── memory_block.md     # Pre-formatted context injection

Usage:
    from session_state import SessionStateManager

    # Initialize for target
    mgr = SessionStateManager.from_target("10.129.5.135")

    # Add discovered credential
    mgr.add_credential(Credential(
        username="admin",
        secret="password123",
        secret_type=CredentialType.PASSWORD,
        source="hydra bruteforce"
    ))

    # Track hypothesis
    mgr.add_hypothesis(
        description="Kernel CVE-2024-1086 for root",
        confidence=0.8,
        priority=1,
        evidence=["Kernel version 5.15 detected"]
    )

    # Generate context block for injection
    block = mgr.generate_memory_block()  # <500 tokens markdown

    # Save all state
    mgr.save_all()
"""

import os
import json
import fcntl
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Hypothesis Confidence Constants (Phase 5)
# =============================================================================

class ConfidenceDelta:
    """Confidence adjustment values for hypothesis ranking."""
    EVIDENCE_CONFIRMS = 0.15      # Evidence supports hypothesis
    EVIDENCE_CONTRADICTS = -0.20  # Evidence contradicts hypothesis
    TECHNIQUE_SUCCESS = 0.10      # Related technique succeeded
    TECHNIQUE_FAIL = -0.05        # Related technique failed
    STALE_DECAY = -0.02           # No progress decay (per interval)
    BLOCKED_THRESHOLD = 0.1       # Set confidence when blocked


class ConfidenceLevel:
    """Threshold values for confidence display labels."""
    HIGH = 0.7      # >= 0.7 = HIGH
    MEDIUM = 0.4    # >= 0.4 = MEDIUM
    LOW = 0.2       # >= 0.2 = LOW
    ARCHIVE = 0.2   # < 0.2 after 2 hours = archive
    PROMOTE = 0.9   # >= 0.9 = promote to confirmed


# =============================================================================
# Enums
# =============================================================================

class AccessLevel(str, Enum):
    NONE = "none"
    USER = "user"
    ROOT = "root"
    SYSTEM = "system"


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    BLOCKED = "blocked"  # Blocked by confirmed findings


class CredentialType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    COOKIE = "cookie"


class ShellType(str, Enum):
    REVERSE = "reverse_shell"
    BIND = "bind_shell"
    WEB = "webshell"
    SSH = "ssh"
    PWNCAT = "pwncat"


# =============================================================================
# Pydantic Models
# =============================================================================

class Credential(BaseModel):
    """A discovered credential."""
    id: str = Field(default_factory=lambda: hashlib.sha256(
        f"{datetime.utcnow().isoformat()}{os.urandom(8).hex()}".encode()
    ).hexdigest()[:12])
    username: str
    secret: str
    secret_type: CredentialType = CredentialType.PASSWORD
    domain: Optional[str] = None
    source: str = ""
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    valid_for: List[str] = Field(default_factory=list)  # services verified against
    verified: bool = False

    def dedup_key(self) -> str:
        """Generate key for deduplication."""
        return f"{self.username}:{self.domain or 'local'}"


class WebSession(BaseModel):
    """A web application session."""
    id: str = Field(default_factory=lambda: hashlib.sha256(
        f"{datetime.utcnow().isoformat()}{os.urandom(8).hex()}".encode()
    ).hexdigest()[:12])
    target_url: str
    cookie_file: Optional[str] = None
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    status: str = "active"


class ShellSession(BaseModel):
    """An active shell session."""
    session_id: str
    session_type: ShellType = ShellType.REVERSE
    user: str = ""
    host: str = ""
    access_level: AccessLevel = AccessLevel.USER
    established_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    technique_id: Optional[str] = None  # PTT technique that got this shell


class Hypothesis(BaseModel):
    """A hypothesis about potential attack path."""
    id: str = Field(default_factory=lambda: f"hyp-{os.urandom(4).hex()}")
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    priority: int = Field(ge=1, le=5, default=3)
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    evidence_for: List[str] = Field(default_factory=list)
    evidence_against: List[str] = Field(default_factory=list)
    related_technique_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class QueryCacheEntry(BaseModel):
    """A cached query to prevent repetition."""
    query_hash: str
    query_text: str
    tool: str  # qdrant-find, google_web_search, web_fetch
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    results_summary: str = ""
    ttl_minutes: int = 60
    hit_count: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        ts = datetime.fromisoformat(self.timestamp)
        return datetime.utcnow() > ts + timedelta(minutes=self.ttl_minutes)


class AnalyzedFile(BaseModel):
    """A file that has been downloaded and analyzed."""
    sha256: str
    remote_path: str
    local_cache_path: str
    findings: List[str] = Field(default_factory=list)
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    skip_reread: bool = True


# =============================================================================
# Store Models (top-level YAML files)
# =============================================================================

class SessionState(BaseModel):
    """Core session state (state.yaml)."""
    version: str = "1.0"
    target: str
    session_id: str = Field(default_factory=lambda: f"sess-{os.urandom(6).hex()}")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    current_access_level: AccessLevel = AccessLevel.NONE
    flags_captured: Dict[str, str] = Field(default_factory=dict)  # user/root -> flag value
    shells: List[ShellSession] = Field(default_factory=list)
    web_sessions: List[WebSession] = Field(default_factory=list)


class CredentialStore(BaseModel):
    """Credential store (credentials.yaml)."""
    version: str = "1.0"
    credentials: List[Credential] = Field(default_factory=list)


class HypothesisStore(BaseModel):
    """Hypothesis store (hypotheses.yaml)."""
    version: str = "1.0"
    hypotheses: List[Hypothesis] = Field(default_factory=list)


class QueryCache(BaseModel):
    """Query cache (query_cache.yaml)."""
    version: str = "1.0"
    entries: List[QueryCacheEntry] = Field(default_factory=list)
    max_entries: int = 100


# =============================================================================
# Session State Manager
# =============================================================================

class SessionStateManager:
    """
    Manages session state for Dame exploitation workflow.

    Handles loading/saving of hierarchical state blocks with file locking
    for safe concurrent access.
    """

    # Default TTLs for query cache by tool type
    DEFAULT_TTL = {
        "qdrant-find": 60,      # Skills DB queries: 60 min
        "google_web_search": 30, # Web searches: 30 min
        "web_fetch": 30,         # Web fetches: 30 min
    }

    def __init__(self, target: str, base_path: str = "/artifacts"):
        self.target = target
        self.base_path = Path(base_path)
        self.session_dir = self.base_path / target / "session"
        self._lock_file = None

        # State containers
        self.state: Optional[SessionState] = None
        self.credentials: Optional[CredentialStore] = None
        self.hypotheses: Optional[HypothesisStore] = None
        self.query_cache: Optional[QueryCache] = None

    @classmethod
    def from_target(cls, target: str, base_path: str = "/artifacts") -> "SessionStateManager":
        """
        Factory method to create/load session state for a target.

        Args:
            target: Target identifier (IP or hostname)
            base_path: Base artifacts path (default: /artifacts)

        Returns:
            Initialized SessionStateManager with loaded or fresh state
        """
        mgr = cls(target, base_path)
        mgr.load_all()
        return mgr

    def _ensure_dirs(self):
        """Ensure session directory structure exists."""
        self.session_dir.mkdir(parents=True, exist_ok=True)
        (self.session_dir / "files").mkdir(exist_ok=True)
        # Set restrictive permissions (0700 for directory)
        os.chmod(self.session_dir, 0o700)

    def _acquire_lock(self):
        """Acquire file lock for session updates."""
        self._ensure_dirs()
        lock_path = self.session_dir / ".session.lock"
        self._lock_file = open(lock_path, 'w')
        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)

    def _release_lock(self):
        """Release file lock."""
        if self._lock_file:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    def _load_yaml(self, filename: str) -> Optional[Dict]:
        """Load YAML file from session directory."""
        import yaml
        filepath = self.session_dir / filename
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                return None
        return None

    def _save_yaml(self, filename: str, data: Dict):
        """Save data to YAML file with restricted permissions."""
        import yaml
        self._ensure_dirs()
        filepath = self.session_dir / filename
        with open(filepath, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        # Set restrictive permissions (0600 for credentials)
        os.chmod(filepath, 0o600)

    def load_all(self):
        """Load all session state from disk."""
        self._ensure_dirs()

        # Load core state
        state_data = self._load_yaml("state.yaml")
        if state_data:
            self.state = SessionState(**state_data)
        else:
            self.state = SessionState(target=self.target)

        # Load credentials
        creds_data = self._load_yaml("credentials.yaml")
        if creds_data:
            self.credentials = CredentialStore(**creds_data)
        else:
            self.credentials = CredentialStore()

        # Load hypotheses
        hyp_data = self._load_yaml("hypotheses.yaml")
        if hyp_data:
            self.hypotheses = HypothesisStore(**hyp_data)
        else:
            self.hypotheses = HypothesisStore()

        # Load query cache
        cache_data = self._load_yaml("query_cache.yaml")
        if cache_data:
            self.query_cache = QueryCache(**cache_data)
        else:
            self.query_cache = QueryCache()

        # Prune expired cache entries
        self._prune_cache()

    def save_all(self):
        """Save all session state to disk with locking."""
        try:
            self._acquire_lock()

            # Update timestamp
            if self.state:
                self.state.updated_at = datetime.utcnow().isoformat()
                self._save_yaml("state.yaml", self.state.model_dump(mode="json"))

            if self.credentials:
                self._save_yaml("credentials.yaml", self.credentials.model_dump(mode="json"))

            if self.hypotheses:
                self._save_yaml("hypotheses.yaml", self.hypotheses.model_dump(mode="json"))

            if self.query_cache:
                self._save_yaml("query_cache.yaml", self.query_cache.model_dump(mode="json"))

            # Generate and save memory block
            self._save_memory_block()

        finally:
            self._release_lock()

    # =========================================================================
    # Credential Management
    # =========================================================================

    def add_credential(self, credential: Credential) -> str:
        """
        Add a credential, deduplicating by username+domain.

        Returns:
            Credential ID (existing if duplicate, new otherwise)
        """
        if not self.credentials:
            self.credentials = CredentialStore()

        dedup_key = credential.dedup_key()

        # Check for existing
        for existing in self.credentials.credentials:
            if existing.dedup_key() == dedup_key:
                # Update if new secret is different
                if existing.secret != credential.secret:
                    existing.secret = credential.secret
                    existing.source = credential.source
                    existing.discovered_at = datetime.utcnow().isoformat()
                return existing.id

        # Add new credential
        self.credentials.credentials.append(credential)
        return credential.id

    def get_credentials_for_service(self, service: str) -> List[Credential]:
        """Get credentials verified for a specific service."""
        if not self.credentials:
            return []
        return [c for c in self.credentials.credentials if service in c.valid_for]

    def mark_credential_verified(self, cred_id: str, service: str):
        """Mark a credential as verified for a service."""
        if not self.credentials:
            return

        for cred in self.credentials.credentials:
            if cred.id == cred_id:
                if service not in cred.valid_for:
                    cred.valid_for.append(service)
                cred.verified = True
                break

    def get_all_credentials(self) -> List[Credential]:
        """Get all credentials."""
        if not self.credentials:
            return []
        return self.credentials.credentials

    # =========================================================================
    # Hypothesis Management
    # =========================================================================

    def add_hypothesis(
        self,
        description: str,
        confidence: float,
        priority: int = 3,
        evidence: Optional[List[str]] = None
    ) -> str:
        """
        Add a new hypothesis.

        Args:
            description: What we think might work
            confidence: 0.0 to 1.0
            priority: 1 (highest) to 5 (lowest)
            evidence: Initial evidence supporting hypothesis

        Returns:
            Hypothesis ID
        """
        if not self.hypotheses:
            self.hypotheses = HypothesisStore()

        hyp = Hypothesis(
            description=description,
            confidence=confidence,
            priority=priority,
            evidence_for=evidence or []
        )
        self.hypotheses.hypotheses.append(hyp)
        return hyp.id

    def update_hypothesis(
        self,
        hyp_id: str,
        confidence_delta: Optional[float] = None,
        evidence_for: Optional[str] = None,
        evidence_against: Optional[str] = None,
        status: Optional[HypothesisStatus] = None
    ):
        """Update an existing hypothesis."""
        if not self.hypotheses:
            return

        for hyp in self.hypotheses.hypotheses:
            if hyp.id == hyp_id:
                if confidence_delta is not None:
                    hyp.confidence = max(0.0, min(1.0, hyp.confidence + confidence_delta))
                if evidence_for:
                    hyp.evidence_for.append(evidence_for)
                if evidence_against:
                    hyp.evidence_against.append(evidence_against)
                if status:
                    hyp.status = status
                hyp.updated_at = datetime.utcnow().isoformat()
                break

    def get_active_hypotheses(self, limit: int = 5) -> List[Hypothesis]:
        """Get top active hypotheses sorted by priority and confidence."""
        if not self.hypotheses:
            return []

        active = [h for h in self.hypotheses.hypotheses if h.status == HypothesisStatus.ACTIVE]
        # Sort by priority (ascending) then confidence (descending)
        active.sort(key=lambda h: (h.priority, -h.confidence))
        return active[:limit]

    def get_hypothesis_by_id(self, hyp_id: str) -> Optional[Hypothesis]:
        """Get a hypothesis by ID."""
        if not self.hypotheses:
            return None
        for hyp in self.hypotheses.hypotheses:
            if hyp.id == hyp_id:
                return hyp
        return None

    def get_hypotheses_by_technique(self, technique_id: str) -> List[Hypothesis]:
        """Get all hypotheses linked to a technique."""
        if not self.hypotheses:
            return []
        return [
            h for h in self.hypotheses.hypotheses
            if technique_id in h.related_technique_ids
        ]

    def update_hypothesis_for_technique_outcome(
        self,
        technique_id: str,
        success: bool,
        evidence: Optional[str] = None
    ) -> List[str]:
        """
        Update all hypotheses linked to a technique based on outcome.

        Args:
            technique_id: The technique that completed
            success: Whether the technique succeeded
            evidence: Optional evidence string to record

        Returns:
            List of updated hypothesis IDs
        """
        if not self.hypotheses:
            return []

        updated_ids = []
        delta = ConfidenceDelta.TECHNIQUE_SUCCESS if success else ConfidenceDelta.TECHNIQUE_FAIL

        for hyp in self.hypotheses.hypotheses:
            if technique_id in hyp.related_technique_ids and hyp.status == HypothesisStatus.ACTIVE:
                hyp.confidence = max(0.0, min(1.0, hyp.confidence + delta))
                hyp.updated_at = datetime.utcnow().isoformat()

                if evidence:
                    if success:
                        hyp.evidence_for.append(evidence)
                    else:
                        hyp.evidence_against.append(evidence)

                # Auto-promote or auto-archive based on new confidence
                if hyp.confidence >= ConfidenceLevel.PROMOTE:
                    hyp.status = HypothesisStatus.CONFIRMED
                elif hyp.confidence < ConfidenceLevel.ARCHIVE:
                    # Check if old enough to archive
                    created = datetime.fromisoformat(hyp.created_at)
                    if datetime.utcnow() - created > timedelta(hours=2):
                        hyp.status = HypothesisStatus.REJECTED

                updated_ids.append(hyp.id)

        return updated_ids

    def update_hypothesis_confidence(
        self,
        hyp_id: str,
        delta: float,
        reason: str,
        is_contradiction: bool = False
    ) -> bool:
        """
        Update hypothesis confidence with tracking.

        Args:
            hyp_id: Hypothesis ID
            delta: Confidence change (can be negative)
            reason: Reason for the update
            is_contradiction: If True, record as evidence_against

        Returns:
            True if hypothesis was found and updated
        """
        hyp = self.get_hypothesis_by_id(hyp_id)
        if not hyp or hyp.status != HypothesisStatus.ACTIVE:
            return False

        hyp.confidence = max(0.0, min(1.0, hyp.confidence + delta))
        hyp.updated_at = datetime.utcnow().isoformat()

        if is_contradiction:
            hyp.evidence_against.append(reason)
        else:
            hyp.evidence_for.append(reason)

        # Auto-promote or auto-archive
        if hyp.confidence >= ConfidenceLevel.PROMOTE:
            hyp.status = HypothesisStatus.CONFIRMED
        elif hyp.confidence < ConfidenceLevel.ARCHIVE:
            created = datetime.fromisoformat(hyp.created_at)
            if datetime.utcnow() - created > timedelta(hours=2):
                hyp.status = HypothesisStatus.REJECTED

        return True

    def block_hypothesis(self, hyp_id: str, reason: str) -> bool:
        """
        Mark a hypothesis as blocked by a confirmed finding.

        Sets confidence to BLOCKED_THRESHOLD and status to BLOCKED.
        """
        hyp = self.get_hypothesis_by_id(hyp_id)
        if not hyp:
            return False

        hyp.confidence = ConfidenceDelta.BLOCKED_THRESHOLD
        hyp.status = HypothesisStatus.BLOCKED
        hyp.evidence_against.append(f"Blocked: {reason}")
        hyp.updated_at = datetime.utcnow().isoformat()
        return True

    def decay_stale_hypotheses(self, stale_minutes: int = 30) -> List[str]:
        """
        Apply decay to hypotheses with no recent updates.

        Args:
            stale_minutes: Minutes of inactivity before decay applies

        Returns:
            List of hypothesis IDs that were decayed
        """
        if not self.hypotheses:
            return []

        decayed_ids = []
        cutoff = datetime.utcnow() - timedelta(minutes=stale_minutes)

        for hyp in self.hypotheses.hypotheses:
            if hyp.status != HypothesisStatus.ACTIVE:
                continue

            updated = datetime.fromisoformat(hyp.updated_at)
            if updated < cutoff:
                hyp.confidence = max(0.0, hyp.confidence + ConfidenceDelta.STALE_DECAY)
                hyp.updated_at = datetime.utcnow().isoformat()
                decayed_ids.append(hyp.id)

                # Archive if too low
                if hyp.confidence < ConfidenceLevel.ARCHIVE:
                    created = datetime.fromisoformat(hyp.created_at)
                    if datetime.utcnow() - created > timedelta(hours=2):
                        hyp.status = HypothesisStatus.REJECTED

        return decayed_ids

    def prune_hypotheses(self) -> Dict[str, List[str]]:
        """
        Prune hypotheses based on confidence thresholds.

        Returns:
            Dict with 'archived' and 'promoted' hypothesis ID lists
        """
        if not self.hypotheses:
            return {"archived": [], "promoted": []}

        archived = []
        promoted = []

        for hyp in self.hypotheses.hypotheses:
            if hyp.status != HypothesisStatus.ACTIVE:
                continue

            # Promote high-confidence hypotheses
            if hyp.confidence >= ConfidenceLevel.PROMOTE:
                hyp.status = HypothesisStatus.CONFIRMED
                hyp.updated_at = datetime.utcnow().isoformat()
                promoted.append(hyp.id)
                continue

            # Archive low-confidence hypotheses older than 2 hours
            if hyp.confidence < ConfidenceLevel.ARCHIVE:
                created = datetime.fromisoformat(hyp.created_at)
                if datetime.utcnow() - created > timedelta(hours=2):
                    hyp.status = HypothesisStatus.REJECTED
                    hyp.updated_at = datetime.utcnow().isoformat()
                    archived.append(hyp.id)

        return {"archived": archived, "promoted": promoted}

    @staticmethod
    def confidence_label(confidence: float) -> str:
        """Get display label for confidence value."""
        if confidence >= ConfidenceLevel.HIGH:
            return "HIGH"
        elif confidence >= ConfidenceLevel.MEDIUM:
            return "MED"
        elif confidence >= ConfidenceLevel.LOW:
            return "LOW"
        else:
            return "VERY LOW"

    # =========================================================================
    # Shell Management
    # =========================================================================

    def add_shell(self, shell: ShellSession):
        """Register an active shell session."""
        if not self.state:
            return

        # Update access level if this shell is higher
        access_order = [AccessLevel.NONE, AccessLevel.USER, AccessLevel.ROOT, AccessLevel.SYSTEM]
        current_idx = access_order.index(self.state.current_access_level)
        new_idx = access_order.index(shell.access_level)
        if new_idx > current_idx:
            self.state.current_access_level = shell.access_level

        self.state.shells.append(shell)

    def get_active_shells(self) -> List[ShellSession]:
        """Get all registered shell sessions."""
        if not self.state:
            return []
        return self.state.shells

    def capture_flag(self, flag_type: str, value: str):
        """Record a captured flag (user or root)."""
        if not self.state:
            return
        self.state.flags_captured[flag_type] = value

    # =========================================================================
    # Query Cache
    # =========================================================================

    def _compute_query_hash(self, query: str, tool: str) -> str:
        """Compute hash for query deduplication."""
        return hashlib.sha256(f"{tool}:{query.lower().strip()}".encode()).hexdigest()[:16]

    def check_query_cache(self, query: str, tool: str) -> Optional[QueryCacheEntry]:
        """
        Check if a query has been recently executed.

        Returns:
            Cached entry if found and not expired, None otherwise
        """
        if not self.query_cache:
            return None

        query_hash = self._compute_query_hash(query, tool)

        for entry in self.query_cache.entries:
            if entry.query_hash == query_hash and not entry.is_expired():
                entry.hit_count += 1
                return entry

        return None

    def cache_query(self, query: str, tool: str, results_summary: str, ttl_minutes: Optional[int] = None):
        """
        Cache a query result for deduplication.

        Args:
            query: The query text
            tool: Tool name (qdrant-find, google_web_search, web_fetch)
            results_summary: Brief summary of results
            ttl_minutes: Cache TTL (uses default for tool if not specified)
        """
        if not self.query_cache:
            self.query_cache = QueryCache()

        query_hash = self._compute_query_hash(query, tool)
        ttl = ttl_minutes or self.DEFAULT_TTL.get(tool, 60)

        # Remove existing entry with same hash
        self.query_cache.entries = [e for e in self.query_cache.entries if e.query_hash != query_hash]

        # Add new entry
        entry = QueryCacheEntry(
            query_hash=query_hash,
            query_text=query,
            tool=tool,
            results_summary=results_summary,
            ttl_minutes=ttl
        )
        self.query_cache.entries.insert(0, entry)

        # Enforce max entries
        if len(self.query_cache.entries) > self.query_cache.max_entries:
            self.query_cache.entries = self.query_cache.entries[:self.query_cache.max_entries]

    def _prune_cache(self):
        """Remove expired cache entries."""
        if not self.query_cache:
            return

        # Remove entries older than 2 hours regardless of TTL
        cutoff = datetime.utcnow() - timedelta(hours=2)
        self.query_cache.entries = [
            e for e in self.query_cache.entries
            if datetime.fromisoformat(e.timestamp) > cutoff and not e.is_expired()
        ]

    # =========================================================================
    # Attack Log
    # =========================================================================

    def log_action(self, action_type: str, details: Dict[str, Any]):
        """
        Append action to attack log (JSONL format).

        This is append-only and never loaded into memory.
        """
        self._ensure_dirs()
        log_path = self.session_dir / "attack_log.jsonl"

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action_type": action_type,
            **details
        }

        with open(log_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")

    # =========================================================================
    # File Cache
    # =========================================================================

    def cache_file_analysis(self, sha256: str, remote_path: str, local_path: str, findings: List[str]):
        """Cache analysis results for a downloaded file."""
        self._ensure_dirs()
        file_cache_path = self.session_dir / "files" / f"{sha256}.yaml"

        analyzed = AnalyzedFile(
            sha256=sha256,
            remote_path=remote_path,
            local_cache_path=local_path,
            findings=findings
        )
        self._save_yaml(f"files/{sha256}.yaml", analyzed.model_dump(mode="json"))

    def get_cached_file(self, sha256: str) -> Optional[AnalyzedFile]:
        """Get cached analysis for a file by SHA256."""
        data = self._load_yaml(f"files/{sha256}.yaml")
        if data:
            return AnalyzedFile(**data)
        return None

    # =========================================================================
    # Memory Block Generation
    # =========================================================================

    def generate_memory_block(self) -> str:
        """
        Generate pre-formatted context injection block.

        Budget: ~500 tokens total
        - State: 100 tokens
        - Hypotheses: 150 tokens
        - Credentials: 100 tokens
        - Queries: 50 tokens
        - Shells: 100 tokens
        """
        lines = []
        lines.append("## Current Session State (Auto-Updated)\n")

        # Core state (100 tokens)
        if self.state:
            access = self.state.current_access_level.value
            flags = ", ".join(f"{k} captured" for k in self.state.flags_captured.keys()) or "none"
            lines.append(f"**Target:** {self.target} | **Access:** {access}")
            lines.append(f"**Flags:** {flags}\n")

        # Active shells (100 tokens)
        shells = self.get_active_shells()
        if shells:
            lines.append("**Active Shells:**")
            for shell in shells[:3]:  # Limit to 3
                lines.append(f"- {shell.session_type.value} as {shell.user} ({shell.access_level.value})")
            lines.append("")

        # Hypotheses (150 tokens)
        hypotheses = self.get_active_hypotheses(limit=3)
        if hypotheses:
            lines.append("**Active Hypotheses:**")
            for i, hyp in enumerate(hypotheses, 1):
                label = self.confidence_label(hyp.confidence)
                conf = f"{hyp.confidence:.1f}"
                # Truncate description to ~50 chars
                desc = hyp.description[:50] + "..." if len(hyp.description) > 50 else hyp.description
                lines.append(f"{i}. [{label} {conf}] {desc}")
            lines.append("")

        # Credentials summary (100 tokens)
        creds = self.get_all_credentials()
        if creds:
            lines.append("**Credentials Available:**")
            for cred in creds[:5]:  # Limit to 5
                verified = "verified" if cred.verified else "unverified"
                services = ", ".join(cred.valid_for[:2]) if cred.valid_for else "untested"
                # Mask secret
                secret_display = "***"
                lines.append(f"- {cred.username}:{secret_display} ({verified}, for {services})")
            lines.append("")

        # Recent queries (50 tokens)
        if self.query_cache and self.query_cache.entries:
            recent = self.query_cache.entries[:3]
            lines.append("**Recent Queries (avoid repetition):**")
            for entry in recent:
                age_mins = int((datetime.utcnow() - datetime.fromisoformat(entry.timestamp)).total_seconds() / 60)
                query_short = entry.query_text[:40] + "..." if len(entry.query_text) > 40 else entry.query_text
                lines.append(f"- \"{query_short}\" ({age_mins} min ago)")

        return "\n".join(lines)

    def _save_memory_block(self):
        """Save the memory block to disk."""
        block = self.generate_memory_block()
        block_path = self.session_dir / "memory_block.md"
        with open(block_path, 'w') as f:
            f.write(block)


# =============================================================================
# Credential Extraction Patterns
# =============================================================================

CREDENTIAL_PATTERNS = {
    "hydra_found": {
        "pattern": r"\[.+\]\[.+\] host: .+ login: (\S+)\s+password: (\S+)",
        "groups": {"username": 1, "secret": 2},
        "type": CredentialType.PASSWORD
    },
    "ssh_login_success": {
        "pattern": r"Authenticated to .+ as (\w+)",
        "groups": {"username": 1},
        "type": CredentialType.PASSWORD
    },
    "hash_found": {
        "pattern": r"(\w+):(\$\d+\$[^\s:]+|\b[a-f0-9]{32}\b)",
        "groups": {"username": 1, "secret": 2},
        "type": CredentialType.HASH
    },
    "mysql_creds": {
        "pattern": r"'(\w+)'@'[^']+' IDENTIFIED BY '([^']+)'",
        "groups": {"username": 1, "secret": 2},
        "type": CredentialType.PASSWORD
    },
    "env_file": {
        "pattern": r"(?:DB_)?(?:PASSWORD|PASS|SECRET)=(\S+)",
        "groups": {"secret": 1},
        "type": CredentialType.PASSWORD
    },
    "netntlm_hash": {
        "pattern": r"(\w+)::(\w+):[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+",
        "groups": {"username": 1, "domain": 2},
        "type": CredentialType.HASH
    }
}


def extract_credentials_from_output(output: str, source: str = "") -> List[Credential]:
    """
    Extract credentials from shell command output.

    Args:
        output: Command output text
        source: Description of where credentials came from

    Returns:
        List of extracted Credential objects
    """
    import re
    credentials = []

    for pattern_name, config in CREDENTIAL_PATTERNS.items():
        for match in re.finditer(config["pattern"], output, re.IGNORECASE | re.MULTILINE):
            groups = config["groups"]

            username = match.group(groups.get("username", 0)) if "username" in groups else "unknown"
            secret = match.group(groups.get("secret", 0)) if "secret" in groups else ""
            domain = match.group(groups.get("domain", 0)) if "domain" in groups else None

            if username or secret:
                cred = Credential(
                    username=username,
                    secret=secret,
                    secret_type=config["type"],
                    domain=domain,
                    source=source or pattern_name
                )
                credentials.append(cred)

    return credentials


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI for session state operations."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: session_state.py <command> <target>")
        print("Commands: init, show, block, add-cred, add-hyp")
        sys.exit(1)

    command = sys.argv[1]
    target = sys.argv[2]

    mgr = SessionStateManager.from_target(target)

    if command == "init":
        mgr.save_all()
        print(f"Session initialized for {target}")
        print(f"  Session ID: {mgr.state.session_id}")
        print(f"  Path: {mgr.session_dir}")

    elif command == "show":
        print(f"Target: {target}")
        print(f"Session ID: {mgr.state.session_id}")
        print(f"Access Level: {mgr.state.current_access_level.value}")
        print(f"Flags: {mgr.state.flags_captured}")
        print(f"Credentials: {len(mgr.get_all_credentials())}")
        print(f"Hypotheses: {len(mgr.get_active_hypotheses())}")
        print(f"Shells: {len(mgr.get_active_shells())}")

    elif command == "block":
        print(mgr.generate_memory_block())

    elif command == "add-cred" and len(sys.argv) >= 5:
        username = sys.argv[3]
        secret = sys.argv[4]
        cred = Credential(username=username, secret=secret, source="manual")
        cred_id = mgr.add_credential(cred)
        mgr.save_all()
        print(f"Added credential: {cred_id}")

    elif command == "add-hyp" and len(sys.argv) >= 5:
        description = sys.argv[3]
        confidence = float(sys.argv[4])
        hyp_id = mgr.add_hypothesis(description, confidence)
        mgr.save_all()
        print(f"Added hypothesis: {hyp_id}")

    else:
        print(f"Unknown command or missing args: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
