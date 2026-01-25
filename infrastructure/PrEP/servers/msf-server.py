#!/usr/bin/env python3
"""
Agent Opulence - Metasploit MCP Server
======================================
FastMCP interface for Metasploit Framework via Go bridge service.

Architecture:
    Python MCP (this file) -> HTTP -> Go Bridge (msf-bridge) -> MSFRPC -> msfrpcd
"""

import os
import sys
import json
import logging
from typing import Optional, List, Dict, Any
from enum import Enum

import httpx
from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# Protocol layer for standardized YAML responses
from infrastructure.PrEP.protocol import (
    format_success,
    format_error,
    BridgeUnavailableError,
)

# Tool name for protocol layer context
TOOL_NAME = "msf"

# Configure logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger('msf-mcp')

# Initialize FastMCP server
mcp = FastMCP("msf_mcp")

# Configuration
MSF_BRIDGE_URL = os.environ.get("MSF_BRIDGE_URL", "http://localhost:9997")
HTTP_TIMEOUT = float(os.environ.get("MSF_HTTP_TIMEOUT", "30.0"))


# Enums
class ModuleType(str, Enum):
    """Metasploit module types."""
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"
    PAYLOAD = "payload"


class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


# Pydantic Input Models
class SearchModulesInput(BaseModel):
    """Input model for searching Metasploit modules."""
    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query (e.g., 'ssh', 'apache', 'smb', 'cve-2021')",
        min_length=1,
        max_length=200
    )
    module_type: Optional[ModuleType] = Field(
        default=None,
        description="Filter by module type: exploit, auxiliary, post, payload"
    )
    limit: int = Field(
        default=50,
        description="Maximum number of results to return",
        ge=1,
        le=500
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured"
    )


class ModuleInfoInput(BaseModel):
    """Input model for getting module information."""
    model_config = ConfigDict(str_strip_whitespace=True)

    module_type: ModuleType = Field(
        ...,
        description="Module type: exploit, auxiliary, post, or payload"
    )
    module: str = Field(
        ...,
        description="Full module path (e.g., 'multi/http/apache_mod_cgi_bash_env_exec')",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format"
    )


class ExploitInput(BaseModel):
    """Input model for executing an exploit module."""
    model_config = ConfigDict(str_strip_whitespace=True)

    module: str = Field(
        ...,
        description="Exploit module path (e.g., 'unix/ftp/vsftpd_234_backdoor')",
        min_length=1
    )
    rhosts: str = Field(
        ...,
        description="Target host(s) - IP address or hostname",
        min_length=1
    )
    rport: Optional[int] = Field(
        default=None,
        description="Target port",
        ge=1,
        le=65535
    )
    lhost: Optional[str] = Field(
        default=None,
        description="Local host for reverse connection (your IP)"
    )
    lport: Optional[int] = Field(
        default=4444,
        description="Local port for reverse connection",
        ge=1,
        le=65535
    )
    payload: Optional[str] = Field(
        default=None,
        description="Payload to use (e.g., 'linux/x64/meterpreter/reverse_tcp')"
    )
    additional_options: Optional[Dict[str, str]] = Field(
        default=None,
        description="Additional module options as key-value pairs"
    )


class AuxiliaryInput(BaseModel):
    """Input model for executing an auxiliary module."""
    model_config = ConfigDict(str_strip_whitespace=True)

    module: str = Field(
        ...,
        description="Auxiliary module path (e.g., 'scanner/ssh/ssh_login')",
        min_length=1
    )
    rhosts: str = Field(
        ...,
        description="Target host(s)",
        min_length=1
    )
    options: Optional[Dict[str, str]] = Field(
        default=None,
        description="Module options as key-value pairs"
    )


class SessionInteractInput(BaseModel):
    """Input model for interacting with a session."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: int = Field(
        ...,
        description="Session ID number",
        ge=0
    )
    command: str = Field(
        ...,
        description="Command to execute in the session",
        min_length=1
    )


class SessionUpgradeInput(BaseModel):
    """Input model for upgrading a shell to Meterpreter."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: int = Field(
        ...,
        description="Session ID to upgrade",
        ge=0
    )
    lhost: str = Field(
        ...,
        description="Local host for Meterpreter reverse connection"
    )
    lport: int = Field(
        default=4433,
        description="Local port for Meterpreter connection",
        ge=1,
        le=65535
    )


class JobStopInput(BaseModel):
    """Input model for stopping a job."""
    model_config = ConfigDict(str_strip_whitespace=True)

    job_id: str = Field(
        ...,
        description="Job ID to stop"
    )


class PayloadsInput(BaseModel):
    """Input model for getting compatible payloads."""
    model_config = ConfigDict(str_strip_whitespace=True)

    module: str = Field(
        ...,
        description="Exploit module path to get compatible payloads for",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured"
    )


class SessionsListInput(BaseModel):
    """Input model for listing sessions."""
    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured"
    )


class JobsListInput(BaseModel):
    """Input model for listing jobs."""
    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured"
    )


class StatusInput(BaseModel):
    """Input model for checking status."""
    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured"
    )


# Bridge Client
class MSFBridgeClient:
    """HTTP client for communicating with the Go MSF bridge."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[dict] = None
    ) -> dict:
        """Make an HTTP request to the bridge."""
        url = f"{self.base_url}{endpoint}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(method, url, json=json_data)
            response.raise_for_status()
            return response.json()

    async def health(self) -> dict:
        """Check bridge health status."""
        return await self._request("GET", "/health")

    async def connect(
        self,
        host: Optional[str] = None,
        port: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None
    ) -> dict:
        """Connect to msfrpcd."""
        data = {}
        if host:
            data["host"] = host
        if port:
            data["port"] = port
        if user:
            data["user"] = user
        if password:
            data["pass"] = password
        return await self._request("POST", "/connect", data if data else None)

    async def version(self) -> dict:
        """Get MSF version info."""
        return await self._request("GET", "/version")

    async def modules(self, module_type: str) -> dict:
        """List modules of a given type."""
        return await self._request("GET", f"/modules/{module_type}")

    async def module_info(self, module_type: str, module: str) -> dict:
        """Get module information."""
        return await self._request("POST", "/module/info", {
            "type": module_type,
            "module": module
        })

    async def module_options(self, module_type: str, module: str) -> dict:
        """Get module options."""
        return await self._request("POST", "/module/options", {
            "type": module_type,
            "module": module
        })

    async def module_execute(
        self,
        module_type: str,
        module: str,
        options: dict
    ) -> dict:
        """Execute a module."""
        return await self._request("POST", "/module/execute", {
            "type": module_type,
            "module": module,
            "options": options
        })

    async def compatible_payloads(self, module: str) -> dict:
        """Get compatible payloads for an exploit."""
        return await self._request("GET", f"/module/payloads/{module}")

    async def sessions(self) -> dict:
        """List active sessions."""
        return await self._request("GET", "/sessions")

    async def session_execute(self, session_id: int, command: str) -> dict:
        """Execute command in a shell session."""
        return await self._request("POST", "/session/execute", {
            "session_id": session_id,
            "command": command
        })

    async def session_meterpreter(self, session_id: int, command: str) -> dict:
        """Execute Meterpreter command."""
        return await self._request("POST", "/session/meterpreter", {
            "session_id": session_id,
            "command": command
        })

    async def session_upgrade(
        self,
        session_id: int,
        lhost: str,
        lport: int
    ) -> dict:
        """Upgrade shell to Meterpreter."""
        return await self._request("POST", "/session/upgrade", {
            "session_id": session_id,
            "lhost": lhost,
            "lport": lport
        })

    async def jobs(self) -> dict:
        """List running jobs."""
        return await self._request("GET", "/jobs")

    async def job_stop(self, job_id: str) -> dict:
        """Stop a running job."""
        return await self._request("POST", "/job/stop", {
            "job_id": job_id
        })


# Global bridge client
bridge = MSFBridgeClient(MSF_BRIDGE_URL, HTTP_TIMEOUT)


# Error handling utilities
# DEPRECATED: This function is replaced by the protocol layer (format_error).
# Kept for reference during migration. Remove after all tools are updated.
def _handle_bridge_error(e: Exception) -> str:
    """Format bridge communication errors.

    DEPRECATED: Use format_error() from infrastructure.PrEP.protocol instead.
    This function returns plain text; format_error returns structured YAML.
    """
    if isinstance(e, httpx.ConnectError):
        return f"Error: Cannot connect to MSF bridge at {MSF_BRIDGE_URL}. Is the bridge running?"
    elif isinstance(e, httpx.TimeoutException):
        return "Error: Request to MSF bridge timed out. The operation may still be in progress."
    elif isinstance(e, httpx.HTTPStatusError):
        try:
            error_data = e.response.json()
            return f"Error: {error_data.get('error', 'Unknown error')} - {error_data.get('details', '')}"
        except Exception:
            return f"Error: Bridge returned status {e.response.status_code}"
    return f"Error: {type(e).__name__}: {str(e)}"


def _filter_modules(modules: List[str], query: str, limit: int) -> List[str]:
    """Filter module list by search query."""
    query_lower = query.lower()
    filtered = [m for m in modules if query_lower in m.lower()]
    return filtered[:limit]


# MCP Tools
@mcp.tool(
    name="msf_search",
    annotations={
        "title": "Search Metasploit Modules",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_search(params: SearchModulesInput) -> str:
    """Search Metasploit modules by keyword.

    Search across exploits, auxiliary modules, post-exploitation modules, and payloads
    in the Metasploit Framework. Supports filtering by module type.

    Args:
        params (SearchModulesInput): Search parameters containing:
            - query (str): Search string to match against module names
            - module_type (Optional[ModuleType]): Filter by type (exploit/auxiliary/post/payload)
            - limit (int): Maximum results (default: 50)
            - response_format (ResponseFormat): Output format (markdown/json)

    Returns:
        str: Search results formatted as YAML with structured response

    Examples:
        - Search for SSH modules: query="ssh"
        - Search for SMB exploits: query="smb", module_type="exploit"
        - Search for CVE: query="cve-2021"
    """
    context = {
        "query": params.query,
        "module_type": params.module_type.value if params.module_type else None,
        "limit": params.limit,
    }

    try:
        all_modules: List[str] = []
        types_to_search = (
            [params.module_type.value]
            if params.module_type
            else ["exploit", "auxiliary", "post", "payload"]
        )

        for mod_type in types_to_search:
            try:
                result = await bridge.modules(mod_type)
                modules = result.get("modules", [])
                # Add type prefix for clarity
                prefixed = [f"{mod_type}/{m}" for m in modules]
                all_modules.extend(prefixed)
            except Exception as e:
                logger.warning(f"Failed to fetch {mod_type} modules: {e}")

        # Filter by query
        filtered = _filter_modules(all_modules, params.query, params.limit)

        result_data = {
            "query": params.query,
            "count": len(filtered),
            "modules": filtered,
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_module_info",
    annotations={
        "title": "Get Module Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_module_info(params: ModuleInfoInput) -> str:
    """Get detailed information about a Metasploit module.

    Retrieves comprehensive details including description, options, targets,
    and compatible payloads for exploitation modules.

    Args:
        params (ModuleInfoInput): Parameters containing:
            - module_type (ModuleType): Module type (exploit/auxiliary/post/payload)
            - module (str): Full module path
            - response_format (ResponseFormat): Output format

    Returns:
        str: Module information formatted as YAML with structured response
    """
    context = {
        "module_type": params.module_type.value,
        "module": params.module,
    }

    try:
        info = await bridge.module_info(params.module_type.value, params.module)
        options = await bridge.module_options(params.module_type.value, params.module)

        result_data = {
            "name": info.get("name", params.module),
            "type": params.module_type.value,
            "rank": info.get("rank", "unknown"),
            "description": info.get("description", "No description available."),
            "authors": info.get("authors", []),
            "options": options,
            "references": info.get("references", [])[:10],
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_exploit",
    annotations={
        "title": "Execute Exploit Module",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def msf_exploit(params: ExploitInput) -> str:
    """Execute an exploit module against a target.

    Runs a Metasploit exploit with the specified options. This is a potentially
    destructive action that will attempt to exploit vulnerabilities on the target.

    Args:
        params (ExploitInput): Exploit parameters containing:
            - module (str): Exploit module path
            - rhosts (str): Target host(s)
            - rport (Optional[int]): Target port
            - lhost (Optional[str]): Local host for reverse connections
            - lport (Optional[int]): Local port (default: 4444)
            - payload (Optional[str]): Payload module to use
            - additional_options (Optional[Dict]): Extra module options

    Returns:
        str: Execution result formatted as YAML with job ID

    Warning:
        Only use against authorized targets with proper permission.
    """
    context = {
        "module": f"exploit/{params.module}",
        "target": params.rhosts,
        "rport": params.rport,
        "payload": params.payload,
    }

    try:
        # Build options dict
        options: Dict[str, str] = {
            "RHOSTS": params.rhosts
        }

        if params.rport:
            options["RPORT"] = str(params.rport)
        if params.lhost:
            options["LHOST"] = params.lhost
        if params.lport:
            options["LPORT"] = str(params.lport)
        if params.payload:
            options["PAYLOAD"] = params.payload
        if params.additional_options:
            options.update(params.additional_options)

        result = await bridge.module_execute("exploit", params.module, options)

        job_id = result.get("job_id", "unknown")
        result_data = {
            "status": "started",
            "module": f"exploit/{params.module}",
            "target": params.rhosts,
            "job_id": job_id,
            "next_steps": [
                "Use msf_sessions_list to check for new sessions",
                "Use msf_jobs_list to monitor job status",
            ],
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_auxiliary",
    annotations={
        "title": "Execute Auxiliary Module",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def msf_auxiliary(params: AuxiliaryInput) -> str:
    """Execute an auxiliary module (scanner, fuzzer, etc.).

    Runs a Metasploit auxiliary module. Auxiliary modules perform various tasks
    like scanning, enumeration, and service identification.

    Args:
        params (AuxiliaryInput): Parameters containing:
            - module (str): Auxiliary module path
            - rhosts (str): Target host(s)
            - options (Optional[Dict]): Additional module options

    Returns:
        str: Execution result formatted as YAML with job ID
    """
    context = {
        "module": f"auxiliary/{params.module}",
        "target": params.rhosts,
    }

    try:
        options: Dict[str, str] = {
            "RHOSTS": params.rhosts
        }
        if params.options:
            options.update(params.options)

        result = await bridge.module_execute("auxiliary", params.module, options)

        job_id = result.get("job_id", "unknown")
        result_data = {
            "status": "started",
            "module": f"auxiliary/{params.module}",
            "target": params.rhosts,
            "job_id": job_id,
            "next_steps": [
                "Use msf_jobs_list to monitor progress",
            ],
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_sessions_list",
    annotations={
        "title": "List Active Sessions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_sessions_list(params: SessionsListInput) -> str:
    """List all active Meterpreter and shell sessions.

    Returns information about all currently active sessions including session type,
    target information, and exploit used.

    Args:
        params (SessionsListInput): Parameters containing:
            - response_format (ResponseFormat): Output format (markdown/json)

    Returns:
        str: Session list formatted as YAML with structured response
    """
    context = {}

    try:
        result = await bridge.sessions()
        sessions = result.get("sessions", [])

        result_data = {
            "count": len(sessions),
            "sessions": sessions,
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_session_interact",
    annotations={
        "title": "Execute Session Command",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def msf_session_interact(params: SessionInteractInput) -> str:
    """Execute a command in an active session.

    Runs a command in a shell or Meterpreter session and returns the output.

    Args:
        params (SessionInteractInput): Parameters containing:
            - session_id (int): Target session ID
            - command (str): Command to execute

    Returns:
        str: Command output formatted as YAML with structured response
    """
    context = {
        "session_id": params.session_id,
        "command": params.command,
    }

    try:
        # Try shell execute first, then meterpreter
        try:
            result = await bridge.session_execute(params.session_id, params.command)
        except Exception:
            result = await bridge.session_meterpreter(params.session_id, params.command)

        output = result.get("output") or result.get("result", "")

        result_data = {
            "session_id": params.session_id,
            "command": params.command,
            "output": output if output else "(no output)",
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_session_upgrade",
    annotations={
        "title": "Upgrade to Meterpreter",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def msf_session_upgrade(params: SessionUpgradeInput) -> str:
    """Upgrade a shell session to Meterpreter.

    Attempts to upgrade a basic shell session to a full Meterpreter session
    for enhanced post-exploitation capabilities.

    Args:
        params (SessionUpgradeInput): Parameters containing:
            - session_id (int): Session to upgrade
            - lhost (str): Local host for Meterpreter callback
            - lport (int): Local port (default: 4433)

    Returns:
        str: Upgrade result formatted as YAML with structured response
    """
    context = {
        "session_id": params.session_id,
        "lhost": params.lhost,
        "lport": params.lport,
    }

    try:
        result = await bridge.session_upgrade(
            params.session_id,
            params.lhost,
            params.lport
        )

        result_data = {
            "status": "initiated",
            "session_id": params.session_id,
            "callback": f"{params.lhost}:{params.lport}",
            "result": result.get('result', 'unknown'),
            "next_steps": [
                "Use msf_sessions_list to check for new Meterpreter session",
            ],
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_jobs_list",
    annotations={
        "title": "List Running Jobs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_jobs_list(params: JobsListInput) -> str:
    """List all running Metasploit jobs.

    Shows currently active background jobs including listeners, scanners,
    and other long-running operations.

    Args:
        params (JobsListInput): Parameters containing:
            - response_format (ResponseFormat): Output format (markdown/json)

    Returns:
        str: Jobs list formatted as YAML with structured response
    """
    context = {}

    try:
        result = await bridge.jobs()
        jobs = result.get("jobs", [])

        result_data = {
            "count": len(jobs),
            "jobs": jobs,
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_job_stop",
    annotations={
        "title": "Stop Job",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
async def msf_job_stop(params: JobStopInput) -> str:
    """Stop a running Metasploit job.

    Terminates a background job such as a listener or scanner.

    Args:
        params (JobStopInput): Parameters containing:
            - job_id (str): ID of the job to stop

    Returns:
        str: Stop result formatted as YAML with structured response
    """
    context = {
        "job_id": params.job_id,
    }

    try:
        result = await bridge.job_stop(params.job_id)

        result_data = {
            "status": "stopped",
            "job_id": params.job_id,
            "result": result.get('result', 'stopped'),
        }

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_payloads",
    annotations={
        "title": "Get Compatible Payloads",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_payloads(params: PayloadsInput) -> str:
    """Get compatible payloads for an exploit module.

    Lists all payloads that can be used with a specific exploit module.

    Args:
        params (PayloadsInput): Parameters containing:
            - module (str): Exploit module path
            - response_format (ResponseFormat): Output format (markdown/json)

    Returns:
        str: Compatible payloads formatted as YAML with structured response
    """
    context = {
        "module": params.module,
    }

    try:
        result = await bridge.compatible_payloads(params.module)
        payloads = result.get("payloads", [])

        result_data = {
            "module": params.module,
            "count": len(payloads),
            "payloads": sorted(payloads)[:100],  # Limit output
        }

        if len(payloads) > 100:
            result_data["truncated"] = True
            result_data["total_available"] = len(payloads)

        return format_success(result_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


@mcp.tool(
    name="msf_status",
    annotations={
        "title": "Check MSF Connection Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def msf_status(params: StatusInput) -> str:
    """Check the connection status to Metasploit.

    Returns the current connection status and version information.

    Args:
        params (StatusInput): Parameters containing:
            - response_format (ResponseFormat): Output format (markdown/json)

    Returns:
        str: Connection status formatted as YAML with structured response
    """
    context = {
        "bridge_url": MSF_BRIDGE_URL,
    }

    try:
        health = await bridge.health()
        connected = health.get("connected", False)

        status_data = {
            "bridge_url": MSF_BRIDGE_URL,
            "connected": connected,
            "host": health.get('host'),
        }

        if connected:
            try:
                version = await bridge.version()
                status_data.update({
                    "version": version.get('version'),
                    "ruby": version.get('ruby'),
                    "api": version.get('api')
                })
            except Exception:
                pass

        return format_success(status_data, TOOL_NAME, context)

    except Exception as e:
        return format_error(e, TOOL_NAME, context)


if __name__ == "__main__":
    mcp.run()
