#!/usr/bin/env python3
"""
Agent Opulence - Pwncat MCP Server
==================================
MCP interface for pwncat-cs post-exploitation framework.

Protocol: JSON-RPC 2.0 over stdio
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

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('pwncat-mcp')

# Pwncat availability flag - set during initialize()
PWNCAT_AVAILABLE = False


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
        self._initialized = False

    async def initialize(self) -> bool:
        """Initialize pwncat manager.

        Imports pwncat.manager.Manager and creates an instance.
        Handles ImportError gracefully if pwncat-cs is not installed.

        Returns:
            True on success, False if pwncat is not available
        """
        global PWNCAT_AVAILABLE

        if self._initialized:
            return True

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
            logger.warning(f"pwncat-cs not installed: {e}")
            logger.warning("Pwncat functionality will be unavailable")
            PWNCAT_AVAILABLE = False
            return False

        except Exception as e:
            logger.error(f"Failed to initialize pwncat manager: {e}")
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
            raise RuntimeError("PwncatClient not initialized. Call initialize() first.")

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
            raise RuntimeError("PwncatClient not initialized. Call initialize() first.")

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

        Queries pwncat-mcp container (which shares gluetun's network namespace)
        via HTTP to get the actual VPN tunnel IP.

        Args:
            interface: Network interface to query (default: tun0 for VPN)

        Returns:
            Dict containing:
            - lhost: The IP address to use in reverse shell payloads
            - interface: The interface queried
            - error: Error message if IP couldn't be determined
        """
        import urllib.request
        import json as json_module

        # pwncat-mcp runs on gluetun's network at port 9998
        # (port 9999 conflicts with gluetun's health server)
        PWNCAT_MCP_URL = "http://gluetun:9998/lhost"

        try:
            req = urllib.request.Request(PWNCAT_MCP_URL)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json_module.loads(response.read().decode())
                if "lhost" in data:
                    logger.info(f"LHOST discovered via pwncat-mcp: {data['lhost']}")
                    return data
                else:
                    return {
                        "error": data.get("error", "Unknown error from pwncat-mcp"),
                        "interface": interface
                    }
        except urllib.error.URLError as e:
            logger.error(f"Failed to query pwncat-mcp for LHOST: {e}")
            return {
                "error": f"Cannot reach pwncat-mcp: {e}",
                "interface": interface,
                "hint": "Ensure pwncat-mcp container is running"
            }
        except Exception as e:
            logger.error(f"Failed to get LHOST: {e}")
            return {
                "error": str(e),
                "interface": interface
            }


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
    """Get pwncat client and ensure it's initialized.

    Returns:
        Initialized PwncatClient instance
    """
    pwncat = get_client()
    if not pwncat._initialized:
        await pwncat.initialize()
    return pwncat


# MCP Tool definitions
TOOLS: List[Dict[str, Any]] = [
    {
        "name": "pwncat__listen",
        "description": "Start a reverse shell listener. Waits for incoming connections on the specified port.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Port to listen on for incoming connections"
                },
                "host": {
                    "type": "string",
                    "description": "Host/interface to bind to (default: 0.0.0.0)",
                    "default": "0.0.0.0"
                },
                "timeout": {
                    "type": "number",
                    "description": "Maximum seconds to wait for connection (optional, omit to wait indefinitely)"
                }
            },
            "required": ["port"]
        }
    },
    {
        "name": "pwncat__connect",
        "description": "Connect to a bind shell on a remote target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target host/IP address"
                },
                "port": {
                    "type": "integer",
                    "description": "Target port"
                },
                "platform": {
                    "type": "string",
                    "description": "Target platform (default: linux)",
                    "enum": ["linux", "windows"],
                    "default": "linux"
                }
            },
            "required": ["host", "port"]
        }
    },
    {
        "name": "pwncat__sessions",
        "description": "List all active pwncat sessions with their metadata (session_id, platform, hostname, user).",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "pwncat__command",
        "description": "Execute a shell command in an active session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                }
            },
            "required": ["session_id", "command"]
        }
    },
    {
        "name": "pwncat__module",
        "description": "Run a pwncat module (enumerate, escalate, persist) in a session. Examples: enumerate.system.uname, escalate.auto, persist.passwd_user",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier"
                },
                "module": {
                    "type": "string",
                    "description": "Module name (e.g., enumerate.system.uname, escalate.auto)"
                },
                "options": {
                    "type": "object",
                    "description": "Module-specific options as key-value pairs"
                }
            },
            "required": ["session_id", "module"]
        }
    },
    {
        "name": "pwncat__upload",
        "description": "Upload a file from the local system to the target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier"
                },
                "local_path": {
                    "type": "string",
                    "description": "Path to the local file to upload"
                },
                "remote_path": {
                    "type": "string",
                    "description": "Destination path on the target"
                }
            },
            "required": ["session_id", "local_path", "remote_path"]
        }
    },
    {
        "name": "pwncat__download",
        "description": "Download a file from the target to the local system.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier"
                },
                "remote_path": {
                    "type": "string",
                    "description": "Path to the file on the target"
                },
                "local_path": {
                    "type": "string",
                    "description": "Destination path on the local system"
                }
            },
            "required": ["session_id", "remote_path", "local_path"]
        }
    },
    {
        "name": "pwncat__close",
        "description": "Close/terminate an active session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier to close"
                }
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "pwncat__get_lhost",
        "description": "Get the VPN IP address for reverse shell callbacks. Returns the IP that HTB targets should connect back to. ALWAYS call this before crafting reverse shell payloads - never hardcode or guess the IP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface to query (default: tun0 for HTB VPN)",
                    "default": "tun0"
                }
            },
            "required": []
        }
    }
]


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    """Handle MCP tool calls.

    Dispatches tool calls to appropriate PwncatClient methods.

    Args:
        name: Tool name (e.g., 'pwncat__listen')
        arguments: Tool arguments dict

    Returns:
        Tool result (dict or list)

    Raises:
        ValueError: If tool name is unknown
    """
    pwncat = await ensure_client_initialized()

    try:
        if name == "pwncat__listen":
            return await pwncat.listen(
                port=arguments["port"],
                host=arguments.get("host", "0.0.0.0"),
                timeout=arguments.get("timeout")
            )

        elif name == "pwncat__connect":
            return await pwncat.connect(
                host=arguments["host"],
                port=arguments["port"],
                platform=arguments.get("platform", "linux")
            )

        elif name == "pwncat__sessions":
            return await pwncat.list_sessions()

        elif name == "pwncat__command":
            return await pwncat.run_command(
                session_id=arguments["session_id"],
                command=arguments["command"]
            )

        elif name == "pwncat__module":
            options = arguments.get("options", {})
            return await pwncat.run_module(
                session_id=arguments["session_id"],
                module=arguments["module"],
                **options
            )

        elif name == "pwncat__upload":
            return await pwncat.upload(
                session_id=arguments["session_id"],
                local_path=arguments["local_path"],
                remote_path=arguments["remote_path"]
            )

        elif name == "pwncat__download":
            return await pwncat.download(
                session_id=arguments["session_id"],
                remote_path=arguments["remote_path"],
                local_path=arguments["local_path"]
            )

        elif name == "pwncat__close":
            return await pwncat.close_session(
                session_id=arguments["session_id"]
            )

        elif name == "pwncat__get_lhost":
            return await pwncat.get_lhost(
                interface=arguments.get("interface", "tun0")
            )

        else:
            raise ValueError(f"Unknown tool: {name}")

    except ValueError:
        # Re-raise ValueError (unknown tool, session not found, etc.)
        raise
    except TimeoutError as e:
        # Return timeout info rather than raising
        return {"error": "timeout", "message": str(e)}
    except FileNotFoundError as e:
        return {"error": "file_not_found", "message": str(e)}
    except RuntimeError as e:
        return {"error": "runtime_error", "message": str(e)}
    except Exception as e:
        logger.error(f"Tool call {name} failed: {e}")
        return {"error": "internal_error", "message": str(e)}


async def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle JSON-RPC request."""
    method = request.get('method', '')
    params = request.get('params', {})
    req_id = request.get('id')

    try:
        if method == 'initialize':
            # Initialize pwncat client during MCP initialization
            pwncat = await ensure_client_initialized()
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "opulence-pwncat",
                    "version": "1.0.0",
                    "pwncat_available": PWNCAT_AVAILABLE
                }
            }

        elif method == 'tools/list':
            result = {"tools": TOOLS}

        elif method == 'tools/call':
            tool_name = params.get('name', '')
            arguments = params.get('arguments', {})
            tool_result = await handle_tool_call(tool_name, arguments)
            result = {
                "content": [
                    {"type": "text", "text": json.dumps(tool_result, indent=2)}
                ]
            }

        elif method == 'notifications/initialized':
            return None

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }

        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    except Exception as e:
        logger.error(f"Error handling request: {e}")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32603, "message": str(e)}
        }


async def main():
    """Main entry point - stdio JSON-RPC server."""
    logger.info("Pwncat MCP server starting...")

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())

    while True:
        try:
            line = await reader.readline()
            if not line:
                break

            request = json.loads(line.decode().strip())
            response = await handle_request(request)

            if response:
                writer.write((json.dumps(response) + '\n').encode())
                await writer.drain()

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
        except Exception as e:
            logger.error(f"Error: {e}")
            break

    logger.info("Pwncat MCP server stopped")


if __name__ == '__main__':
    asyncio.run(main())
