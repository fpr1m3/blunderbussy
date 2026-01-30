#!/usr/bin/env python3
"""
Ground Truth Data Structures
=============================

Canonical vulnerability types, aliases, and YAML loader for evaluation
ground truth manifests used by the benchmark harness.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    import sys
    print("ERROR: PyYAML required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Canonical vulnerability types
# ---------------------------------------------------------------------------

class VulnType(str, Enum):
    """Canonical vulnerability type identifiers."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_EXECUTION = "code_execution"
    LOCAL_FILE_INCLUSION = "local_file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    DESERIALIZATION = "deserialization"
    SSTI = "ssti"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    EVAL_INJECTION = "eval_injection"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"


# Maps common aliases/abbreviations to canonical VulnType
VULN_TYPE_ALIASES: dict[str, VulnType] = {
    # SQL injection
    "sql_injection": VulnType.SQL_INJECTION,
    "sqli": VulnType.SQL_INJECTION,
    "sql": VulnType.SQL_INJECTION,
    "sql_inject": VulnType.SQL_INJECTION,
    # Command injection
    "command_injection": VulnType.COMMAND_INJECTION,
    "cmd_injection": VulnType.COMMAND_INJECTION,
    "os_command_injection": VulnType.COMMAND_INJECTION,
    "rce": VulnType.COMMAND_INJECTION,
    "command_exec": VulnType.COMMAND_INJECTION,
    # Code execution
    "code_execution": VulnType.CODE_EXECUTION,
    "code_exec": VulnType.CODE_EXECUTION,
    "remote_code_execution": VulnType.CODE_EXECUTION,
    "arbitrary_code_execution": VulnType.CODE_EXECUTION,
    "dynamic_code_execution": VulnType.CODE_EXECUTION,
    # LFI
    "local_file_inclusion": VulnType.LOCAL_FILE_INCLUSION,
    "lfi": VulnType.LOCAL_FILE_INCLUSION,
    "file_inclusion": VulnType.LOCAL_FILE_INCLUSION,
    # Path traversal
    "path_traversal": VulnType.PATH_TRAVERSAL,
    "directory_traversal": VulnType.PATH_TRAVERSAL,
    "dir_traversal": VulnType.PATH_TRAVERSAL,
    # XSS
    "xss_reflected": VulnType.XSS_REFLECTED,
    "reflected_xss": VulnType.XSS_REFLECTED,
    "xss": VulnType.XSS_REFLECTED,  # default xss -> reflected
    "xss_stored": VulnType.XSS_STORED,
    "stored_xss": VulnType.XSS_STORED,
    "persistent_xss": VulnType.XSS_STORED,
    # Hardcoded creds
    "hardcoded_credentials": VulnType.HARDCODED_CREDENTIALS,
    "hardcoded_creds": VulnType.HARDCODED_CREDENTIALS,
    "hardcoded_secrets": VulnType.HARDCODED_CREDENTIALS,
    "hardcoded_password": VulnType.HARDCODED_CREDENTIALS,
    # Deserialization
    "deserialization": VulnType.DESERIALIZATION,
    "unsafe_deserialization": VulnType.DESERIALIZATION,
    "insecure_deserialization": VulnType.DESERIALIZATION,
    # SSTI
    "ssti": VulnType.SSTI,
    "server_side_template_injection": VulnType.SSTI,
    "template_injection": VulnType.SSTI,
    # Prototype pollution
    "prototype_pollution": VulnType.PROTOTYPE_POLLUTION,
    "proto_pollution": VulnType.PROTOTYPE_POLLUTION,
    # Eval injection
    "eval_injection": VulnType.EVAL_INJECTION,
    "eval": VulnType.EVAL_INJECTION,
    "code_injection": VulnType.EVAL_INJECTION,
    # SSRF
    "ssrf": VulnType.SSRF,
    "server_side_request_forgery": VulnType.SSRF,
    # Open redirect
    "open_redirect": VulnType.OPEN_REDIRECT,
    "redirect": VulnType.OPEN_REDIRECT,
    "url_redirect": VulnType.OPEN_REDIRECT,
}


def normalize_vuln_type(raw: str) -> Optional[VulnType]:
    """Normalize a vulnerability type string to a canonical VulnType.

    Handles case-insensitive matching, hyphens, and spaces.
    Returns None if the type is unrecognized.
    """
    if not raw:
        return None
    normalized = raw.lower().strip().replace("-", "_").replace(" ", "_")
    return VULN_TYPE_ALIASES.get(normalized)


# ---------------------------------------------------------------------------
# Ground truth data structures
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthVuln:
    """A single ground truth vulnerability entry."""
    id: str
    vuln_type: str
    cwe: str
    severity: str
    file: str
    line: int
    end_line: Optional[int] = None
    function: Optional[str] = None
    exploitable: bool = True
    description: str = ""
    sink_function: Optional[str] = None
    sanitized: bool = False
    tags: list[str] = field(default_factory=list)


@dataclass
class GroundTruth:
    """Complete ground truth for a test fixture."""
    fixture_name: str
    language: str
    description: str
    vulnerabilities: list[GroundTruthVuln]
    total_files: int = 0
    safe_patterns: list[str] = field(default_factory=list)

    @property
    def exploitable_vulns(self) -> list[GroundTruthVuln]:
        """Vulnerabilities that are exploitable (not sanitized)."""
        return [v for v in self.vulnerabilities if v.exploitable and not v.sanitized]

    @property
    def sanitized_vulns(self) -> list[GroundTruthVuln]:
        """Vulnerabilities that are sanitized / safe patterns."""
        return [v for v in self.vulnerabilities if v.sanitized]


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def load_ground_truth(path: str | Path) -> GroundTruth:
    """Load a ground truth manifest from a YAML file.

    Expected format:
        fixture_name: vuln-php-app
        language: php
        description: "PHP application with intentional vulnerabilities"
        total_files: 11
        safe_patterns:
          - prepared_statements
          - htmlspecialchars
        vulnerabilities:
          - id: GT-PHP-001
            vuln_type: local_file_inclusion
            cwe: CWE-98
            severity: critical
            file: src/view.php
            line: 12
            ...
    """
    path = Path(path)
    with open(path) as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"Ground truth file must be a YAML mapping, got {type(data).__name__}")

    vulns = []
    for v in data.get("vulnerabilities", []):
        vulns.append(GroundTruthVuln(
            id=str(v["id"]),
            vuln_type=str(v["vuln_type"]),
            cwe=str(v.get("cwe", "")),
            severity=str(v.get("severity", "medium")),
            file=str(v["file"]),
            line=int(v["line"]),
            end_line=int(v["end_line"]) if v.get("end_line") is not None else None,
            function=v.get("function"),
            exploitable=v.get("exploitable", True),
            description=v.get("description", ""),
            sink_function=v.get("sink_function"),
            sanitized=v.get("sanitized", False),
            tags=v.get("tags", []),
        ))

    return GroundTruth(
        fixture_name=data.get("fixture_name", path.parent.name),
        language=data.get("language", "unknown"),
        description=data.get("description", ""),
        vulnerabilities=vulns,
        total_files=data.get("total_files", 0),
        safe_patterns=data.get("safe_patterns", []),
    )
