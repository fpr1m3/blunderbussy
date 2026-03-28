"""
Tests for infrastructure/PrEP/servers/findings-server.py

Pattern: spawn the server as a subprocess, send JSON-RPC messages via stdin,
read responses from stdout. Uses tmp_path + FINDINGS_DIR/TARGET env vars.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Absolute path to the server under test
SERVER_PATH = os.path.join(
    os.path.dirname(__file__),
    "../../infrastructure/PrEP/servers/findings-server.py",
)


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------


def _send_jsonrpc(messages: list[dict], env: dict) -> list[dict]:
    """
    Send a list of JSON-RPC messages to the findings server via stdin.
    Returns a list of parsed response dicts (one per non-notification message).

    Each message dict must have at least "method". Messages without an "id"
    key are treated as notifications and produce no response.
    """
    # Assign sequential IDs to non-notification messages
    rpc_id = 1
    lines = []
    expected_responses = 0
    for msg in messages:
        if "id" not in msg:
            # Assign ID unless it's a notification that must not have one
            if msg.get("_notification", False):
                msg = {k: v for k, v in msg.items() if k != "_notification"}
            else:
                msg = dict(msg, id=rpc_id)
                rpc_id += 1
                expected_responses += 1
        else:
            expected_responses += 1
        lines.append(json.dumps(msg))

    stdin_data = "\n".join(lines) + "\n"

    full_env = {**os.environ, **env}
    result = subprocess.run(
        [sys.executable, SERVER_PATH],
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=15,
        env=full_env,
    )

    assert result.returncode == 0, (
        f"Server exited non-zero:\nstdout={result.stdout}\nstderr={result.stderr}"
    )

    responses = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            responses.append(json.loads(line))

    return responses


def _make_env(tmp_path: Path, target: str = "test-target") -> dict:
    return {
        "FINDINGS_DIR": str(tmp_path),
        "TARGET": target,
    }


def _findings_file(tmp_path: Path, target: str = "test-target") -> Path:
    return tmp_path / target / "findings.json"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInitializeAndListTools:
    def test_initialize_and_list_tools(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {"method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {"method": "tools/list", "params": {}},
            ],
            env,
        )

        assert len(responses) == 2

        # initialize response
        init = responses[0]
        assert init["result"]["serverInfo"]["name"] == "findings-server"
        assert init["result"]["protocolVersion"] == "2024-11-05"

        # tools/list response
        tools_resp = responses[1]
        tools = tools_resp["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert tool_names == {"submit_flag", "submit_credential", "submit_vulnerability"}

    def test_tools_have_correct_schemas(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [{"method": "tools/list", "params": {}}],
            env,
        )
        tools = {t["name"]: t for t in responses[0]["result"]["tools"]}

        # submit_flag enums
        flag_schema = tools["submit_flag"]["inputSchema"]
        assert flag_schema["properties"]["flag_type"]["enum"] == ["user_flag", "root_flag"]
        assert flag_schema["properties"]["access_level"]["enum"] == ["user", "root"]
        assert set(flag_schema["required"]) == {"flag_type", "value", "path", "access_level"}

        # submit_credential enums
        cred_schema = tools["submit_credential"]["inputSchema"]
        assert cred_schema["properties"]["credential_type"]["enum"] == [
            "password", "hash", "key", "token"
        ]
        assert cred_schema["properties"]["access_level"]["enum"] == ["none", "user", "root"]
        assert set(cred_schema["required"]) == {
            "username", "password", "credential_type", "service"
        }

        # submit_vulnerability enums
        vuln_schema = tools["submit_vulnerability"]["inputSchema"]
        assert vuln_schema["properties"]["status"]["enum"] == ["discovered", "exploited"]
        assert set(vuln_schema["required"]) == {"name", "service_port", "status"}
        # service_port must be integer type
        assert vuln_schema["properties"]["service_port"]["type"] == "integer"

    def test_notifications_initialized_no_response(self, tmp_path):
        """notifications/initialized must produce no response line."""
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {"method": "initialize", "params": {}, "id": 1},
                # notification — no id, server should not respond
                {"method": "notifications/initialized", "_notification": True},
                {"method": "tools/list", "params": {}, "id": 2},
            ],
            env,
        )
        # Only 2 responses (initialize + tools/list), not 3
        assert len(responses) == 2
        assert responses[0]["id"] == 1
        assert responses[1]["id"] == 2


class TestSubmitFlag:
    def test_submit_flag_success(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "value": "HTB{test_flag_123}",
                            "path": "/home/user/user.txt",
                            "access_level": "user",
                        },
                    },
                }
            ],
            env,
        )

        assert len(responses) == 1
        result = responses[0]["result"]
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "user_flag" in text
        assert "activate_skill('flag-capture')" in text

        # Verify findings.json written
        findings_path = _findings_file(tmp_path)
        assert findings_path.exists()
        findings = json.loads(findings_path.read_text())
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "flag"
        assert f["flag_type"] == "user_flag"
        assert f["value"] == "HTB{test_flag_123}"
        assert f["path"] == "/home/user/user.txt"
        assert f["access_level"] == "user"
        assert "timestamp" in f

    def test_submit_flag_root(self, tmp_path):
        env = _make_env(tmp_path)
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "root_flag",
                            "value": "HTB{r00t_fl4g}",
                            "path": "/root/root.txt",
                            "access_level": "root",
                        },
                    },
                }
            ],
            env,
        )
        findings = json.loads(_findings_file(tmp_path).read_text())
        assert findings[0]["flag_type"] == "root_flag"
        assert findings[0]["access_level"] == "root"

    def test_submit_flag_invalid_enum(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "admin_flag",  # invalid
                            "value": "HTB{x}",
                            "path": "/tmp/flag.txt",
                            "access_level": "user",
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        assert "flag_type" in result["content"][0]["text"]

    def test_submit_flag_invalid_access_level(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "value": "HTB{x}",
                            "path": "/tmp/flag.txt",
                            "access_level": "admin",  # invalid
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        assert "access_level" in result["content"][0]["text"]

    def test_submit_flag_missing_required(self, tmp_path):
        env = _make_env(tmp_path)
        # Missing 'value' and 'path'
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "access_level": "user",
                            # value and path are missing
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        # Should name one of the missing fields
        text = result["content"][0]["text"]
        assert "value" in text or "path" in text

    def test_submit_flag_no_file_on_error(self, tmp_path):
        """Validation errors must not create findings.json."""
        env = _make_env(tmp_path)
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {"flag_type": "bad"},
                    },
                }
            ],
            env,
        )
        assert not _findings_file(tmp_path).exists()


class TestSubmitCredential:
    def test_submit_credential_success(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_credential",
                        "arguments": {
                            "username": "admin",
                            "password": "s3cr3t",
                            "credential_type": "password",
                            "service": "ssh",
                            "access_level": "user",
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "activate_skill('flag-capture')" in text

        findings = json.loads(_findings_file(tmp_path).read_text())
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "credential"
        assert f["username"] == "admin"
        assert f["password"] == "s3cr3t"
        assert f["credential_type"] == "password"
        assert f["service"] == "ssh"
        assert f["access_level"] == "user"
        assert "timestamp" in f

    def test_submit_credential_default_access_level(self, tmp_path):
        """access_level defaults to 'none' when not provided."""
        env = _make_env(tmp_path)
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_credential",
                        "arguments": {
                            "username": "svc_account",
                            "password": "aabbcc:hash",
                            "credential_type": "hash",
                            "service": "smb",
                        },
                    },
                }
            ],
            env,
        )
        findings = json.loads(_findings_file(tmp_path).read_text())
        assert findings[0]["access_level"] == "none"

    def test_submit_credential_all_types(self, tmp_path):
        """All valid credential_type values are accepted."""
        env = _make_env(tmp_path)
        for ctype in ["password", "hash", "key", "token"]:
            _send_jsonrpc(
                [
                    {
                        "method": "tools/call",
                        "params": {
                            "name": "submit_credential",
                            "arguments": {
                                "username": f"user_{ctype}",
                                "password": "val",
                                "credential_type": ctype,
                                "service": "test",
                            },
                        },
                    }
                ],
                env,
            )

    def test_submit_credential_invalid_type(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_credential",
                        "arguments": {
                            "username": "admin",
                            "password": "x",
                            "credential_type": "certificate",  # invalid
                            "service": "vpn",
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        assert "credential_type" in result["content"][0]["text"]

    def test_submit_credential_missing_required(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_credential",
                        "arguments": {
                            "username": "admin",
                            # password, credential_type, service missing
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True


class TestSubmitVulnerability:
    def test_submit_vulnerability_with_cve(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_vulnerability",
                        "arguments": {
                            "name": "Log4Shell RCE",
                            "service_port": 8080,
                            "status": "exploited",
                            "cve": "CVE-2021-44228",
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Log4Shell RCE" in text
        assert "8080" in text
        assert "CVE-2021-44228" in text

        findings = json.loads(_findings_file(tmp_path).read_text())
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "vulnerability"
        assert f["name"] == "Log4Shell RCE"
        assert f["service_port"] == 8080
        assert f["status"] == "exploited"
        assert f["cve"] == "CVE-2021-44228"
        assert "timestamp" in f

    def test_submit_vulnerability_without_cve(self, tmp_path):
        env = _make_env(tmp_path)
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_vulnerability",
                        "arguments": {
                            "name": "Anonymous FTP login",
                            "service_port": 21,
                            "status": "discovered",
                        },
                    },
                }
            ],
            env,
        )
        findings = json.loads(_findings_file(tmp_path).read_text())
        f = findings[0]
        assert "cve" not in f
        assert f["status"] == "discovered"

    def test_submit_vulnerability_invalid_status(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_vulnerability",
                        "arguments": {
                            "name": "SQL Injection",
                            "service_port": 3306,
                            "status": "patched",  # invalid
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        assert "status" in result["content"][0]["text"]

    def test_submit_vulnerability_missing_required(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_vulnerability",
                        "arguments": {
                            "name": "Heartbleed",
                            # service_port and status missing
                        },
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True


class TestMultipleFindingsAppend:
    def test_multiple_findings_append_to_same_file(self, tmp_path):
        """Multiple tool calls in one session all land in the same findings.json."""
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_vulnerability",
                        "arguments": {
                            "name": "Apache Struts RCE",
                            "service_port": 8080,
                            "status": "exploited",
                            "cve": "CVE-2017-5638",
                        },
                    },
                },
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_credential",
                        "arguments": {
                            "username": "tomcat",
                            "password": "tomcat",
                            "credential_type": "password",
                            "service": "tomcat-manager",
                        },
                    },
                },
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "value": "HTB{str4ts_pwn3d}",
                            "path": "/home/tomcat/user.txt",
                            "access_level": "user",
                        },
                    },
                },
            ],
            env,
        )

        assert len(responses) == 3
        for r in responses:
            assert r["result"]["isError"] is False

        findings = json.loads(_findings_file(tmp_path).read_text())
        assert len(findings) == 3
        types = [f["type"] for f in findings]
        assert types == ["vulnerability", "credential", "flag"]

    def test_findings_from_separate_sessions_append(self, tmp_path):
        """
        Two separate subprocess invocations write to the same findings.json
        (simulating Dame calling the server across multiple sessions).
        """
        env = _make_env(tmp_path)

        # First session
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "value": "HTB{first}",
                            "path": "/home/user/user.txt",
                            "access_level": "user",
                        },
                    },
                }
            ],
            env,
        )

        # Second session
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "root_flag",
                            "value": "HTB{second}",
                            "path": "/root/root.txt",
                            "access_level": "root",
                        },
                    },
                }
            ],
            env,
        )

        findings = json.loads(_findings_file(tmp_path).read_text())
        assert len(findings) == 2
        assert findings[0]["value"] == "HTB{first}"
        assert findings[1]["value"] == "HTB{second}"

    def test_different_targets_separate_files(self, tmp_path):
        """Findings for different TARGET values go to separate files."""
        env_a = _make_env(tmp_path, target="target-a")
        env_b = _make_env(tmp_path, target="target-b")

        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "user_flag",
                            "value": "HTB{target_a}",
                            "path": "/home/user/user.txt",
                            "access_level": "user",
                        },
                    },
                }
            ],
            env_a,
        )
        _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "submit_flag",
                        "arguments": {
                            "flag_type": "root_flag",
                            "value": "HTB{target_b}",
                            "path": "/root/root.txt",
                            "access_level": "root",
                        },
                    },
                }
            ],
            env_b,
        )

        findings_a = json.loads(_findings_file(tmp_path, "target-a").read_text())
        findings_b = json.loads(_findings_file(tmp_path, "target-b").read_text())
        assert findings_a[0]["value"] == "HTB{target_a}"
        assert findings_b[0]["value"] == "HTB{target_b}"


class TestUnknownTool:
    def test_unknown_tool_returns_error(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [
                {
                    "method": "tools/call",
                    "params": {
                        "name": "nonexistent_tool",
                        "arguments": {},
                    },
                }
            ],
            env,
        )
        result = responses[0]["result"]
        assert result["isError"] is True

    def test_unknown_method_returns_error(self, tmp_path):
        env = _make_env(tmp_path)
        responses = _send_jsonrpc(
            [{"method": "resources/list", "params": {}}],
            env,
        )
        assert "error" in responses[0]
        assert responses[0]["error"]["code"] == -32601
