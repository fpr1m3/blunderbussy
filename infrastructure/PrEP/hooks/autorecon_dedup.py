#!/usr/bin/env python3
"""
BeforeTool Hook - AutoRecon Deduplication
==========================================
Gemini CLI hook that prevents redundant re-running of scans that AutoRecon
has already completed during the reconnaissance phase.

Triggered before: run_shell_command, Shell, bash, execute_command tools
Action: Block commands that duplicate AutoRecon work, with pointer to CAS results

Input (stdin): JSON with tool_name, tool_input (BeforeToolInput interface)
Output (stdout): JSON response using Gemini CLI HookOutput format:
    - continue: true to proceed
    - decision: "block" with reason pointing to existing results

Why this matters:
    AutoRecon scans take 20-60+ minutes. Re-running them wastes time and
    may produce slightly different results, causing confusion. Dame should
    use CAS results instead.
"""

import sys
import json
import os
import re
import shlex
from pathlib import Path
from typing import Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None


# =============================================================================
# Configuration
# =============================================================================

# Tools that execute shell commands
SHELL_TOOLS = {
    "run_shell_command": "command",
    "Shell": "command",
    "bash": "command",
    "execute_command": "command",
}

# AutoRecon-covered tools mapped to CAS scan_types and sections
# Format: {command_base: (scan_type_in_cas, cas_section, description)}
AUTORECON_TOOLS = {
    # Port/Service Scanning
    "nmap": ("nmap", "hosts[].ports", "Port/service scan"),
    "masscan": ("nmap", "hosts[].ports", "Port scan"),

    # Directory Enumeration
    "feroxbuster": ("feroxbuster", "directories", "Directory enumeration"),
    "gobuster": ("feroxbuster", "directories", "Directory enumeration"),
    "dirsearch": ("feroxbuster", "directories", "Directory enumeration"),
    "ffuf": ("feroxbuster", "directories", "Directory/vhost enumeration"),
    "dirb": ("feroxbuster", "directories", "Directory enumeration"),

    # Web Scanning
    "nikto": ("nikto", "vulnerabilities", "Web vulnerability scan"),
    "whatweb": ("whatweb", "technologies", "Web technology detection"),

    # SMB Enumeration
    "enum4linux": ("enum4linux", "hosts[].smb_info", "SMB enumeration"),
    "enum4linux-ng": ("enum4linux", "hosts[].smb_info", "SMB enumeration"),
    "smbmap": ("smbmap", "hosts[].smb_info", "SMB share mapping"),
    "smbclient": ("smbclient", "hosts[].smb_info", "SMB client"),

    # DNS Enumeration
    "dnsrecon": ("dnsrecon", "dns_records", "DNS enumeration"),

    # Vulnerability Scanning
    "nuclei": ("nuclei", "vulnerabilities", "Vulnerability scan"),
}

# Exceptions that should be allowed even for covered tools
ALLOWED_PATTERNS = [
    # Targeted NSE scripts not in default AutoRecon run
    r"nmap.*--script[= ](?!default|vuln|safe|discovery)(\w+)",

    # Explicit re-scan flag from user
    r"--force-rescan",
    r"--ignore-autorecon",

    # Reading/displaying results (not scanning)
    r"cat\s+.*nmap",
    r"less\s+.*nmap",
    r"grep\s+.*nmap",
]

# Patterns indicating scan against different host (pivot)
PIVOT_INDICATORS = [
    r"192\.168\.",      # Internal network (common pivot target)
    r"172\.(1[6-9]|2[0-9]|3[01])\.",  # Private 172.16-31.x
    r"10\.(?!10\.|129\.)",  # 10.x but not HTB ranges
]


# =============================================================================
# Helpers
# =============================================================================

def get_target_from_env() -> str:
    """Get current target from environment or CAS path."""
    target = os.environ.get("TARGET")
    if target:
        return target

    cas_path = os.environ.get("CAS_PATH")
    if cas_path:
        parts = Path(cas_path).parts
        for i, part in enumerate(parts):
            if part == "artifacts" and i + 1 < len(parts):
                return parts[i + 1]

    # Try .current_target file written by /attack command
    current_target_file = Path(
        os.environ.get("ARTIFACTS_PATH", "/artifacts")
    ) / ".current_target"
    if current_target_file.exists():
        try:
            target = current_target_file.read_text().strip()
            if target:
                return target
        except OSError:
            pass

    artifacts_dir = Path(os.environ.get("ARTIFACTS_PATH", "/artifacts"))
    if artifacts_dir.exists():
        # Find most recent target with CAS
        cas_dirs = [
            d for d in artifacts_dir.iterdir()
            if d.is_dir() and (d / "context.yaml").exists()
        ]
        if cas_dirs:
            cas_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            return cas_dirs[0].name

    return ""


def load_cas(target: str) -> Optional[dict]:
    """Load CAS for target."""
    if not yaml:
        return None

    artifacts_path = os.environ.get("ARTIFACTS_PATH", "/artifacts")
    cas_path = Path(artifacts_path) / target / "context.yaml"

    if not cas_path.exists():
        return None

    try:
        with open(cas_path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def extract_base_command(command: str) -> Tuple[str, list]:
    """
    Extract base command and arguments from shell command.

    Returns:
        (base_command, args) - Base command name and argument list
    """
    if not command or not command.strip():
        return "", []

    # Handle pipes - only check first command
    if "|" in command:
        command = command.split("|")[0]

    # Handle command chaining
    for sep in ["&&", ";", "||"]:
        if sep in command:
            command = command.split(sep)[0]

    command = command.strip()

    try:
        parts = shlex.split(command)
    except ValueError:
        # Fallback to simple split
        parts = command.split()

    if not parts:
        return "", []

    # Handle sudo
    if parts[0] == "sudo" and len(parts) > 1:
        parts = parts[1:]

    # Handle env vars at start
    while parts and "=" in parts[0]:
        parts = parts[1:]

    if not parts:
        return "", []

    base = Path(parts[0]).name  # Handle /usr/bin/nmap -> nmap
    return base, parts[1:] if len(parts) > 1 else []


def is_exception(command: str, args: list, target: str) -> Tuple[bool, str]:
    """
    Check if command matches an exception pattern that should be allowed.

    Returns:
        (is_exception, reason)
    """
    full_command = command + " " + " ".join(args)

    # Check allowed patterns
    for pattern in ALLOWED_PATTERNS:
        if re.search(pattern, full_command, re.IGNORECASE):
            return True, f"Allowed pattern: {pattern}"

    # Check for pivot to different host
    for pattern in PIVOT_INDICATORS:
        if re.search(pattern, full_command):
            return True, "Scanning different network (possible pivot)"

    # Check if scanning a different target than CAS target
    if target:
        # Look for IP addresses in command
        ips_in_command = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", full_command)
        if ips_in_command and target not in ips_in_command:
            return True, f"Scanning different target: {ips_in_command[0]}"

    # smbclient with specific share access (not -L listing)
    if command == "smbclient" and "-L" not in args:
        return True, "SMB share access (not enumeration)"

    return False, ""


def get_cas_section_summary(cas: dict, section: str) -> str:
    """Get a brief summary of what's in a CAS section."""
    if not cas:
        return ""

    if section == "hosts[].ports":
        hosts = cas.get("hosts", [])
        if hosts:
            ports = []
            for host in hosts:
                for port in host.get("ports", []):
                    ports.append(f"{port.get('port')}/{port.get('service', 'unknown')}")
            if ports:
                return f"Found ports: {', '.join(ports[:10])}" + ("..." if len(ports) > 10 else "")
        return "Port data available"

    if section == "directories":
        dirs = cas.get("directories", [])
        if dirs:
            paths = [d.get("path", d) if isinstance(d, dict) else str(d) for d in dirs[:5]]
            return f"Found {len(dirs)} directories: {', '.join(paths)}" + ("..." if len(dirs) > 5 else "")
        return "Directory data available"

    if section == "vulnerabilities":
        vulns = cas.get("vulnerabilities", [])
        if vulns:
            return f"Found {len(vulns)} vulnerabilities"
        return "Vulnerability data available"

    if section == "technologies":
        techs = cas.get("technologies", [])
        if techs:
            tech_names = [t.get("name", str(t)) if isinstance(t, dict) else str(t) for t in techs[:5]]
            return f"Technologies: {', '.join(tech_names)}"
        return "Technology data available"

    return f"Data available in CAS {section}"


# =============================================================================
# Main Hook Logic
# =============================================================================

def main():
    """Process BeforeTool event."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only check shell tools
    if tool_name not in SHELL_TOOLS:
        print(json.dumps({"continue": True}))
        return

    # Get the command parameter for this tool
    command_param = SHELL_TOOLS[tool_name]
    command = tool_input.get(command_param, "")

    if not command:
        print(json.dumps({"continue": True}))
        return

    # Extract base command
    base_cmd, args = extract_base_command(command)

    if not base_cmd:
        print(json.dumps({"continue": True}))
        return

    # Check if this is an AutoRecon-covered tool
    if base_cmd not in AUTORECON_TOOLS:
        print(json.dumps({"continue": True}))
        return

    # Get target and CAS
    target = get_target_from_env()

    # Check exceptions first
    is_exc, exc_reason = is_exception(base_cmd, args, target)
    if is_exc:
        print(json.dumps({
            "continue": True,
            "reason": f"AutoRecon dedup exception: {exc_reason}"
        }))
        return

    # Load CAS to verify scan was actually run
    cas = load_cas(target) if target else None
    scan_type, cas_section, description = AUTORECON_TOOLS[base_cmd]

    # If we can't load CAS, allow the command (defensive - don't block without proof)
    if not cas:
        print(json.dumps({
            "continue": True,
            "reason": f"No CAS found for {target} - allowing {base_cmd}"
        }))
        return

    # Check if this scan type exists in CAS
    scan_types = cas.get("target", {}).get("scan_types", [])

    if scan_type not in scan_types:
        # Scan wasn't run by AutoRecon - allow it
        print(json.dumps({
            "continue": True,
            "reason": f"{base_cmd} was not run by AutoRecon for this target"
        }))
        return

    # Build helpful block message
    cas_path = f"/artifacts/{target}/context.yaml" if target else "/artifacts/{target}/context.yaml"
    section_summary = get_cas_section_summary(cas, cas_section) if cas else ""

    message_parts = [
        f"⚠️ **{description} already completed by AutoRecon**",
        "",
        f"Tool `{base_cmd}` results are available in CAS:",
        f"  📄 {cas_path}",
        f"  📍 Section: `{cas_section}`",
    ]

    if section_summary:
        message_parts.append(f"  📊 {section_summary}")

    message_parts.extend([
        "",
        "**Instead of re-scanning:**",
        f"1. Read the CAS: `cat {cas_path} | grep -A 20 '{cas_section.split('[')[0]}'`",
        "2. Or load in Python: `yaml.safe_load(open('{cas_path}'))`",
        "",
        "**To force re-scan** (if you have a specific reason):",
        f"  Add `--force-rescan` flag or scan a specific target not in CAS",
    ])

    print(json.dumps({
        "decision": "block",
        "reason": "\n".join(message_parts),
        "systemMessage": f"Blocked redundant {base_cmd} scan - results already in CAS",
        "hookSpecificOutput": {
            "hookEventName": "BeforeTool",
            "blocked_tool": base_cmd,
            "scan_type": scan_type,
            "cas_section": cas_section,
            "cas_path": cas_path,
            "target": target,
        }
    }))


if __name__ == "__main__":
    main()
