#!/usr/bin/env python3
"""
Pentesting Task Tree (PTT) Module
=================================
Manages the PTT lifecycle for Dame agent exploitation workflow.

Features:
- CAS to PTT transformation
- Status tracking and updates
- Error classification and recovery
- Priority re-calculation
- Findings propagation

Usage:
    from ptt import PTTManager

    # Initialize from CAS
    ptt = PTTManager.from_cas("/artifacts/target/context.yaml")

    # Get next technique to try
    technique = ptt.get_next_technique()

    # Update on success/failure
    ptt.update_technique(technique.id, status="success", findings=[...])
    ptt.update_technique(technique.id, status="failed", error={"type": "connection_failure", ...})

    # Save state
    ptt.save("/artifacts/target/ptt.yaml")
"""

import uuid
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class Status(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"
    COMPROMISED = "compromised"
    EXPLOITED = "exploited"


class ErrorType(str, Enum):
    CONNECTION_FAILURE = "connection_failure"
    VERSION_MISMATCH = "version_mismatch"
    PAYLOAD_BLOCKED = "payload_blocked"
    NETWORK_BLOCKED = "network_blocked"
    AUTH_FAILURE = "auth_failure"
    EXPLOIT_CRASH = "exploit_crash"
    PERMISSION_DENIED = "permission_denied"
    UNKNOWN = "unknown"


class VectorCategory(str, Enum):
    QUICK_WIN = "quick_win"
    KNOWN_VULN = "known_vuln"
    BRUTE_FORCE = "brute_force"
    MISCONFIG = "misconfig"
    CUSTOM = "custom"


# Recovery actions for each error type
RECOVERY_ACTIONS = {
    ErrorType.CONNECTION_FAILURE: ["retry_after_delay", "try_alternate_port", "verify_target"],
    ErrorType.VERSION_MISMATCH: ["re_fingerprint", "find_correct_exploit", "try_generic_exploit"],
    ErrorType.PAYLOAD_BLOCKED: ["encode_payload", "try_fileless", "try_different_payload"],
    ErrorType.NETWORK_BLOCKED: ["try_port_443", "try_port_80", "try_bind_shell", "try_dns_tunnel"],
    ErrorType.AUTH_FAILURE: ["try_next_wordlist", "check_lockout", "try_alternate_creds"],
    ErrorType.EXPLOIT_CRASH: ["wait_recovery", "try_stable_variant", "skip_service"],
    ErrorType.PERMISSION_DENIED: ["try_privesc", "find_alternate_path"],
    ErrorType.UNKNOWN: ["log_and_research", "web_search_error"],
}


@dataclass
class ErrorEntry:
    attempt: int
    timestamp: str
    error_type: str
    error_message: str
    recovery_action: str = ""


@dataclass
class Finding:
    type: str  # credential, access, loot, user, file
    value: str
    context: str = ""


@dataclass
class Technique:
    id: str
    name: str
    source: str  # skills_db, manual, cas_recommendation
    skill_ref: str = ""
    status: str = Status.PENDING.value
    command: str = ""
    tool: str = ""
    attempts: int = 0
    max_attempts: int = 3
    last_attempt: str = ""
    findings: List[Dict] = field(default_factory=list)
    error_history: List[Dict] = field(default_factory=list)
    research_queries: List[str] = field(default_factory=list)
    research_results: List[str] = field(default_factory=list)


@dataclass
class Vector:
    id: str
    name: str
    category: str
    status: str = Status.PENDING.value
    priority: int = 3
    techniques_total: int = 0
    techniques_completed: int = 0
    techniques: List[Technique] = field(default_factory=list)


@dataclass
class Service:
    id: str
    port: int
    proto: str
    service: str
    version: str
    status: str = Status.PENDING.value
    priority_score: float = 5.0
    epss_score: float = 0.0
    known_vulns: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    attempts: int = 0
    max_attempts: int = 5
    vectors: List[Vector] = field(default_factory=list)


@dataclass
class Host:
    id: str
    ip: str
    hostname: str
    os: str
    status: str = Status.PENDING.value
    priority: int = 5
    findings: Dict = field(default_factory=lambda: {
        "users_discovered": [],
        "credentials": [],
        "access_level": "none"
    })
    services: List[Service] = field(default_factory=list)


@dataclass
class Engagement:
    id: str
    target: str
    session_id: str
    status: str = Status.PENDING.value
    platform: str = "unknown"
    findings: Dict = field(default_factory=lambda: {
        "credentials": [],
        "access_gained": [],
        "loot": []
    })
    iteration_stats: Dict = field(default_factory=lambda: {
        "total_attempts": 0,
        "successful_techniques": 0,
        "failed_techniques": 0,
        "skipped_techniques": 0
    })
    hosts: List[Host] = field(default_factory=list)


class PTTManager:
    """Manages PTT lifecycle and operations."""

    def __init__(self, engagement: Engagement):
        self.engagement = engagement
        self._technique_index: Dict[str, Technique] = {}
        self._service_index: Dict[str, Service] = {}
        self._host_index: Dict[str, Host] = {}
        self._build_indices()

    def _build_indices(self):
        """Build lookup indices for quick access."""
        for host in self.engagement.hosts:
            self._host_index[host.id] = host
            for service in host.services:
                self._service_index[service.id] = service
                for vector in service.vectors:
                    for technique in vector.techniques:
                        self._technique_index[technique.id] = technique

    @classmethod
    def from_cas(cls, cas_path: str) -> "PTTManager":
        """Initialize PTT from a CAS YAML file."""
        cas_path = Path(cas_path)
        with open(cas_path) as f:
            cas = yaml.safe_load(f)

        # Create engagement
        target_info = cas.get("target", {})
        engagement = Engagement(
            id=str(uuid.uuid4()),
            target=target_info.get("identifier", "unknown"),
            session_id=target_info.get("session_id", ""),
            status=Status.PENDING.value,
            platform=cls._detect_platform(cas)
        )

        # Process hosts
        for cas_host in cas.get("hosts", []):
            host = cls._transform_host(cas_host)
            engagement.hosts.append(host)

        # Apply attack guidance as quick wins
        guidance = cas.get("attack_guidance", {})
        cls._apply_quick_wins(engagement, guidance)
        cls._apply_recommended_commands(engagement, guidance)

        return cls(engagement)

    @classmethod
    def from_file(cls, ptt_path: str) -> "PTTManager":
        """Load existing PTT from file."""
        with open(ptt_path) as f:
            data = yaml.safe_load(f)

        engagement = cls._dict_to_engagement(data.get("engagement", {}))
        return cls(engagement)

    @staticmethod
    def _detect_platform(cas: Dict) -> str:
        """Detect target platform from CAS data."""
        for host in cas.get("hosts", []):
            os_info = host.get("os", {})
            os_name = os_info.get("name", "").lower() if os_info else ""
            if "linux" in os_name or "ubuntu" in os_name or "debian" in os_name:
                return "linux"
            elif "windows" in os_name:
                return "windows"
        return "unknown"

    @classmethod
    def _transform_host(cls, cas_host: Dict) -> Host:
        """Transform CAS host to PTT Host node."""
        host = Host(
            id=str(uuid.uuid4()),
            ip=cas_host.get("ip", ""),
            hostname=cas_host.get("hostname", ""),
            os=cas_host.get("os", {}).get("name", "") if cas_host.get("os") else "",
            priority=cas_host.get("priority", 5)
        )

        # Process ports/services
        for cas_port in cas_host.get("ports", []):
            service = cls._transform_service(cas_port)
            host.services.append(service)

        return host

    @classmethod
    def _transform_service(cls, cas_port: Dict) -> Service:
        """Transform CAS port to PTT Service node."""
        service = Service(
            id=str(uuid.uuid4()),
            port=cas_port.get("port", 0),
            proto=cas_port.get("proto", "tcp"),
            service=cas_port.get("service", "unknown"),
            version=cas_port.get("version", ""),
            priority_score=float(cas_port.get("priority", 5)),
            known_vulns=cas_port.get("vulns", []),
            cves=[]
        )

        # Create vectors from CAS attack vectors
        vectors_data = cas_port.get("vectors", [])
        for i, vector_name in enumerate(vectors_data):
            vector = Vector(
                id=str(uuid.uuid4()),
                name=vector_name,
                category=cls._categorize_vector(vector_name),
                priority=i + 2  # Quick wins will be priority 1
            )
            service.vectors.append(vector)

        return service

    @staticmethod
    def _categorize_vector(vector_name: str) -> str:
        """Categorize attack vector."""
        name_lower = vector_name.lower()
        if any(x in name_lower for x in ["default", "anonymous", "null"]):
            return VectorCategory.QUICK_WIN.value
        elif any(x in name_lower for x in ["cve", "exploit", "vuln"]):
            return VectorCategory.KNOWN_VULN.value
        elif any(x in name_lower for x in ["brute", "spray", "enum"]):
            return VectorCategory.BRUTE_FORCE.value
        elif any(x in name_lower for x in ["misconfig", "disclosure"]):
            return VectorCategory.MISCONFIG.value
        return VectorCategory.CUSTOM.value

    @classmethod
    def _apply_quick_wins(cls, engagement: Engagement, guidance: Dict):
        """Add quick wins from CAS guidance as priority 1 vectors."""
        quick_wins = guidance.get("quick_wins", [])
        for qw in quick_wins:
            # Parse quick win string (e.g., "hydra Bruteforce logins on ssh:22")
            parts = qw.split(" on ")
            if len(parts) == 2:
                tool_action = parts[0]
                service_port = parts[1]

                # Find matching service
                for host in engagement.hosts:
                    for service in host.services:
                        if f"{service.service}:{service.port}" == service_port:
                            # Create quick win vector
                            vector = Vector(
                                id=str(uuid.uuid4()),
                                name=f"quick_win_{tool_action.split()[0]}",
                                category=VectorCategory.QUICK_WIN.value,
                                priority=1
                            )
                            # Insert at beginning
                            service.vectors.insert(0, vector)
                            break

    @classmethod
    def _apply_recommended_commands(cls, engagement: Engagement, guidance: Dict):
        """Add recommended commands as techniques."""
        for cmd in guidance.get("recommended_commands", []):
            service_name = cmd.get("service", "")
            port = cmd.get("port", 0)

            # Find matching service
            for host in engagement.hosts:
                for service in host.services:
                    if service.service == service_name and service.port == port:
                        # Find or create appropriate vector
                        category = cls._categorize_command(cmd.get("category", ""))
                        vector = cls._find_or_create_vector(service, category)

                        # Create technique
                        technique = Technique(
                            id=str(uuid.uuid4()),
                            name=f"{cmd.get('tool', 'command')} - {cmd.get('category', 'unknown')}",
                            source="cas_recommendation",
                            command=cmd.get("command", ""),
                            tool=cmd.get("tool", "")
                        )
                        vector.techniques.append(technique)
                        vector.techniques_total = len(vector.techniques)
                        break

    @staticmethod
    def _categorize_command(category: str) -> str:
        """Categorize command into vector category."""
        cat_lower = category.lower()
        if "brute" in cat_lower:
            return VectorCategory.BRUTE_FORCE.value
        elif "scan" in cat_lower or "enum" in cat_lower:
            return VectorCategory.MISCONFIG.value
        return VectorCategory.CUSTOM.value

    @staticmethod
    def _find_or_create_vector(service: Service, category: str) -> Vector:
        """Find existing vector or create new one."""
        for vector in service.vectors:
            if vector.category == category:
                return vector

        # Create new vector
        vector = Vector(
            id=str(uuid.uuid4()),
            name=f"{category}_attacks",
            category=category,
            priority=3
        )
        service.vectors.append(vector)
        return vector

    def get_next_technique(self) -> Optional[Technique]:
        """Get the next technique to attempt based on priority."""
        candidates = []

        for host in self.engagement.hosts:
            if host.status in [Status.SKIPPED.value, Status.COMPROMISED.value]:
                continue

            for service in host.services:
                if service.status in [Status.SKIPPED.value, Status.EXPLOITED.value]:
                    continue

                # Sort vectors by priority
                sorted_vectors = sorted(service.vectors, key=lambda v: v.priority)

                for vector in sorted_vectors:
                    if vector.status in [Status.SUCCESS.value, Status.FAILED.value, Status.SKIPPED.value]:
                        continue

                    for technique in vector.techniques:
                        if technique.status == Status.PENDING.value:
                            candidates.append({
                                "technique": technique,
                                "vector": vector,
                                "service": service,
                                "host": host,
                                "score": self._calculate_technique_score(technique, vector, service, host)
                            })

        if not candidates:
            return None

        # Sort by score and return highest
        candidates.sort(key=lambda x: x["score"], reverse=True)
        best = candidates[0]

        # Mark as in progress
        best["technique"].status = Status.IN_PROGRESS.value
        best["vector"].status = Status.IN_PROGRESS.value
        best["service"].status = Status.IN_PROGRESS.value
        best["host"].status = Status.IN_PROGRESS.value

        return best["technique"]

    def _calculate_technique_score(self, technique: Technique, vector: Vector,
                                    service: Service, host: Host) -> float:
        """Calculate priority score for a technique."""
        # Base score from service priority
        score = service.priority_score

        # Boost for quick wins
        if vector.category == VectorCategory.QUICK_WIN.value:
            score *= 2.0
        elif vector.category == VectorCategory.KNOWN_VULN.value:
            score *= 1.5

        # Boost for CAS recommendations
        if technique.source == "cas_recommendation":
            score *= 1.3

        # Penalty for previous failures on this service
        if service.attempts > 0:
            score *= (1.0 - (service.attempts / service.max_attempts) * 0.3)

        return score

    def update_technique(self, technique_id: str, status: str,
                         findings: List[Dict] = None, error: Dict = None):
        """Update technique status and propagate changes."""
        technique = self._technique_index.get(technique_id)
        if not technique:
            raise ValueError(f"Technique {technique_id} not found")

        technique.status = status
        technique.last_attempt = datetime.utcnow().isoformat()
        technique.attempts += 1
        self.engagement.iteration_stats["total_attempts"] += 1

        if status == Status.SUCCESS.value:
            self._handle_success(technique, findings or [])
        elif status == Status.FAILED.value:
            self._handle_failure(technique, error or {})

    def _handle_success(self, technique: Technique, findings: List[Dict]):
        """Handle successful technique execution."""
        technique.findings.extend(findings)
        self.engagement.iteration_stats["successful_techniques"] += 1

        # Find parent nodes and propagate
        for host in self.engagement.hosts:
            for service in host.services:
                for vector in service.vectors:
                    if technique in vector.techniques:
                        vector.status = Status.SUCCESS.value
                        vector.techniques_completed += 1
                        service.status = Status.EXPLOITED.value

                        # Propagate findings
                        for finding in findings:
                            if finding.get("type") == "credential":
                                host.findings["credentials"].append(finding.get("value"))
                                self.engagement.findings["credentials"].append(finding.get("value"))
                            elif finding.get("type") == "access":
                                self.engagement.findings["access_gained"].append({
                                    "host": host.ip,
                                    "level": finding.get("value"),
                                    "technique": technique.name
                                })
                                host.findings["access_level"] = finding.get("value", "user")

                        # Check if host is fully compromised
                        if host.findings["access_level"] in ["root", "SYSTEM"]:
                            host.status = Status.COMPROMISED.value
                        else:
                            host.status = Status.PARTIAL.value

                        return

    def _handle_failure(self, technique: Technique, error: Dict):
        """Handle failed technique execution."""
        self.engagement.iteration_stats["failed_techniques"] += 1

        # Classify error
        error_type = self._classify_error(error.get("message", ""))
        recovery = RECOVERY_ACTIONS.get(error_type, ["log_and_research"])[0]

        # Log error
        error_entry = {
            "attempt": technique.attempts,
            "timestamp": datetime.utcnow().isoformat(),
            "error_type": error_type.value if isinstance(error_type, ErrorType) else error_type,
            "error_message": error.get("message", ""),
            "recovery_action": recovery
        }
        technique.error_history.append(error_entry)

        # Check if exhausted
        if technique.attempts >= technique.max_attempts:
            technique.status = Status.FAILED.value
            self._check_vector_exhausted(technique)

    def _classify_error(self, message: str) -> ErrorType:
        """Classify error message into error type."""
        msg_lower = message.lower()

        if any(x in msg_lower for x in ["connection refused", "timeout", "unreachable", "no route"]):
            return ErrorType.CONNECTION_FAILURE
        elif any(x in msg_lower for x in ["version", "not vulnerable", "patch"]):
            return ErrorType.VERSION_MISMATCH
        elif any(x in msg_lower for x in ["blocked", "detected", "quarantine", "av ", "edr"]):
            return ErrorType.PAYLOAD_BLOCKED
        elif any(x in msg_lower for x in ["reverse", "callback", "listener", "outbound"]):
            return ErrorType.NETWORK_BLOCKED
        elif any(x in msg_lower for x in ["invalid", "password", "credential", "login failed", "access denied"]):
            return ErrorType.AUTH_FAILURE
        elif any(x in msg_lower for x in ["crash", "segfault", "unresponsive", "died"]):
            return ErrorType.EXPLOIT_CRASH
        elif any(x in msg_lower for x in ["permission", "privilege", "unauthorized"]):
            return ErrorType.PERMISSION_DENIED

        return ErrorType.UNKNOWN

    def _check_vector_exhausted(self, technique: Technique):
        """Check if vector is exhausted after technique failure."""
        for host in self.engagement.hosts:
            for service in host.services:
                for vector in service.vectors:
                    if technique in vector.techniques:
                        vector.techniques_completed += 1
                        pending = [t for t in vector.techniques if t.status == Status.PENDING.value]
                        if not pending:
                            vector.status = Status.FAILED.value
                            self._check_service_exhausted(service)
                        return

    def _check_service_exhausted(self, service: Service):
        """Check if service is exhausted after vector failure."""
        pending_vectors = [v for v in service.vectors if v.status == Status.PENDING.value]
        if not pending_vectors:
            service.status = Status.FAILED.value

    def reprioritize(self):
        """Re-calculate priorities based on current state."""
        for host in self.engagement.hosts:
            for service in host.services:
                # Boost if related service had success
                if self._has_related_success(service, host):
                    service.priority_score *= 1.2

                # Demote if high failure rate
                total = sum(v.techniques_total for v in service.vectors)
                failed = sum(1 for v in service.vectors for t in v.techniques
                            if t.status == Status.FAILED.value)
                if total > 0 and failed / total > 0.5:
                    service.priority_score *= 0.7

    def _has_related_success(self, service: Service, host: Host) -> bool:
        """Check if a related service had success."""
        for s in host.services:
            if s.id != service.id and s.status == Status.EXPLOITED.value:
                return True
        return False

    def get_summary(self) -> Dict:
        """Get current PTT summary for context."""
        return {
            "status": self.engagement.status,
            "platform": self.engagement.platform,
            "hosts_total": len(self.engagement.hosts),
            "hosts_compromised": len([h for h in self.engagement.hosts
                                      if h.status == Status.COMPROMISED.value]),
            "services_exploited": sum(1 for h in self.engagement.hosts
                                      for s in h.services
                                      if s.status == Status.EXPLOITED.value),
            "techniques_attempted": self.engagement.iteration_stats["total_attempts"],
            "techniques_successful": self.engagement.iteration_stats["successful_techniques"],
            "credentials_found": len(self.engagement.findings["credentials"]),
            "access_gained": self.engagement.findings["access_gained"]
        }

    def to_dict(self) -> Dict:
        """Convert PTT to dictionary for serialization."""
        return {
            "ptt_version": "1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "engagement": self._engagement_to_dict(self.engagement)
        }

    def _engagement_to_dict(self, engagement: Engagement) -> Dict:
        """Convert engagement to dict, handling dataclasses."""
        return {
            "id": engagement.id,
            "target": engagement.target,
            "session_id": engagement.session_id,
            "status": engagement.status,
            "platform": engagement.platform,
            "findings": engagement.findings,
            "iteration_stats": engagement.iteration_stats,
            "hosts": [self._host_to_dict(h) for h in engagement.hosts]
        }

    def _host_to_dict(self, host: Host) -> Dict:
        return {
            "id": host.id,
            "ip": host.ip,
            "hostname": host.hostname,
            "os": host.os,
            "status": host.status,
            "priority": host.priority,
            "findings": host.findings,
            "services": [self._service_to_dict(s) for s in host.services]
        }

    def _service_to_dict(self, service: Service) -> Dict:
        return {
            "id": service.id,
            "port": service.port,
            "proto": service.proto,
            "service": service.service,
            "version": service.version,
            "status": service.status,
            "priority_score": service.priority_score,
            "epss_score": service.epss_score,
            "known_vulns": service.known_vulns,
            "cves": service.cves,
            "attempts": service.attempts,
            "max_attempts": service.max_attempts,
            "vectors": [self._vector_to_dict(v) for v in service.vectors]
        }

    def _vector_to_dict(self, vector: Vector) -> Dict:
        return {
            "id": vector.id,
            "name": vector.name,
            "category": vector.category,
            "status": vector.status,
            "priority": vector.priority,
            "techniques_total": vector.techniques_total,
            "techniques_completed": vector.techniques_completed,
            "techniques": [self._technique_to_dict(t) for t in vector.techniques]
        }

    def _technique_to_dict(self, technique: Technique) -> Dict:
        return {
            "id": technique.id,
            "name": technique.name,
            "source": technique.source,
            "skill_ref": technique.skill_ref,
            "status": technique.status,
            "command": technique.command,
            "tool": technique.tool,
            "attempts": technique.attempts,
            "max_attempts": technique.max_attempts,
            "last_attempt": technique.last_attempt,
            "findings": technique.findings,
            "error_history": technique.error_history,
            "research_queries": technique.research_queries,
            "research_results": technique.research_results
        }

    @classmethod
    def _dict_to_engagement(cls, data: Dict) -> Engagement:
        """Reconstruct Engagement from dict."""
        engagement = Engagement(
            id=data.get("id", str(uuid.uuid4())),
            target=data.get("target", ""),
            session_id=data.get("session_id", ""),
            status=data.get("status", Status.PENDING.value),
            platform=data.get("platform", "unknown"),
            findings=data.get("findings", {}),
            iteration_stats=data.get("iteration_stats", {})
        )

        for host_data in data.get("hosts", []):
            host = Host(
                id=host_data.get("id", str(uuid.uuid4())),
                ip=host_data.get("ip", ""),
                hostname=host_data.get("hostname", ""),
                os=host_data.get("os", ""),
                status=host_data.get("status", Status.PENDING.value),
                priority=host_data.get("priority", 5),
                findings=host_data.get("findings", {})
            )

            for svc_data in host_data.get("services", []):
                service = Service(
                    id=svc_data.get("id", str(uuid.uuid4())),
                    port=svc_data.get("port", 0),
                    proto=svc_data.get("proto", "tcp"),
                    service=svc_data.get("service", ""),
                    version=svc_data.get("version", ""),
                    status=svc_data.get("status", Status.PENDING.value),
                    priority_score=svc_data.get("priority_score", 5.0),
                    epss_score=svc_data.get("epss_score", 0.0),
                    known_vulns=svc_data.get("known_vulns", []),
                    cves=svc_data.get("cves", []),
                    attempts=svc_data.get("attempts", 0),
                    max_attempts=svc_data.get("max_attempts", 5)
                )

                for vec_data in svc_data.get("vectors", []):
                    vector = Vector(
                        id=vec_data.get("id", str(uuid.uuid4())),
                        name=vec_data.get("name", ""),
                        category=vec_data.get("category", ""),
                        status=vec_data.get("status", Status.PENDING.value),
                        priority=vec_data.get("priority", 3),
                        techniques_total=vec_data.get("techniques_total", 0),
                        techniques_completed=vec_data.get("techniques_completed", 0)
                    )

                    for tech_data in vec_data.get("techniques", []):
                        technique = Technique(
                            id=tech_data.get("id", str(uuid.uuid4())),
                            name=tech_data.get("name", ""),
                            source=tech_data.get("source", ""),
                            skill_ref=tech_data.get("skill_ref", ""),
                            status=tech_data.get("status", Status.PENDING.value),
                            command=tech_data.get("command", ""),
                            tool=tech_data.get("tool", ""),
                            attempts=tech_data.get("attempts", 0),
                            max_attempts=tech_data.get("max_attempts", 3),
                            last_attempt=tech_data.get("last_attempt", ""),
                            findings=tech_data.get("findings", []),
                            error_history=tech_data.get("error_history", []),
                            research_queries=tech_data.get("research_queries", []),
                            research_results=tech_data.get("research_results", [])
                        )
                        vector.techniques.append(technique)

                    service.vectors.append(vector)
                host.services.append(service)
            engagement.hosts.append(host)

        return engagement

    def save(self, path: str):
        """Save PTT to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)


def main():
    """CLI for PTT operations."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: ptt.py <init|show|next> <cas_path|ptt_path>")
        sys.exit(1)

    command = sys.argv[1]
    path = sys.argv[2]

    if command == "init":
        # Initialize PTT from CAS
        ptt = PTTManager.from_cas(path)
        output = Path(path).parent / "ptt.yaml"
        ptt.save(str(output))
        print(f"PTT initialized: {output}")
        print(yaml.dump(ptt.get_summary(), default_flow_style=False))

    elif command == "show":
        # Show PTT summary
        ptt = PTTManager.from_file(path)
        print(yaml.dump(ptt.get_summary(), default_flow_style=False))

    elif command == "next":
        # Get next technique
        ptt = PTTManager.from_file(path)
        technique = ptt.get_next_technique()
        if technique:
            print(f"Next technique: {technique.name}")
            print(f"  ID: {technique.id}")
            print(f"  Tool: {technique.tool}")
            print(f"  Command: {technique.command}")
        else:
            print("No more techniques to try")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
