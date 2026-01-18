#!/usr/bin/env python3
"""
MCP Server Test Suite
=====================
Tests all three opulence MCP servers for correct JSON-RPC responses.

Run: python test_servers.py
"""

import json
import subprocess
import sys
import os
import tempfile
import shutil
from pathlib import Path


def send_jsonrpc(server_script: str, requests: list, env: dict = None) -> list:
    """Send JSON-RPC requests to an MCP server and collect responses."""
    input_data = "\n".join(json.dumps(req) for req in requests) + "\n"

    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    proc = subprocess.Popen(
        [sys.executable, server_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=proc_env,
        text=True
    )

    stdout, stderr = proc.communicate(input=input_data, timeout=10)

    responses = []
    for line in stdout.strip().split("\n"):
        if line:
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return responses, stderr


def test_artifacts_server():
    """Test the opulence-artifacts MCP server."""
    print("\n" + "="*60)
    print("Testing opulence-artifacts MCP Server")
    print("="*60)

    # Create temp directory for artifacts
    temp_dir = tempfile.mkdtemp()
    cas_dir = os.path.join(temp_dir, "cas")
    raw_dir = os.path.join(temp_dir, "raw")
    os.makedirs(cas_dir)
    os.makedirs(raw_dir)

    # Create test artifacts
    test_artifact = {
        "type": "nmap",
        "target": "10.10.10.5",
        "services": [
            {"port": 22, "service": "ssh"},
            {"port": 80, "service": "http"}
        ]
    }

    import yaml
    with open(os.path.join(cas_dir, "nmap_10.10.10.5_20260115.yaml"), "w") as f:
        yaml.dump(test_artifact, f)

    with open(os.path.join(raw_dir, "nmap_10.10.10.5_raw.txt"), "w") as f:
        f.write("PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n")

    env = {"OPULENCE_ARTIFACTS_DIR": temp_dir}

    script_path = os.path.join(os.path.dirname(__file__), "artifacts", "server.py")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "artifact__list",
            "arguments": {"artifact_type": "all", "limit": 10}
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "artifact__read",
            "arguments": {"artifact_id": "nmap_10.10.10.5_20260115"}
        }},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "artifact__search",
            "arguments": {"query": "ssh", "limit": 5}
        }}
    ]

    try:
        responses, stderr = send_jsonrpc(script_path, requests, env)

        print(f"\nStderr: {stderr[:500] if stderr else 'None'}")
        print(f"Received {len(responses)} responses")

        all_passed = True

        # Check initialize
        if responses[0].get("result", {}).get("serverInfo", {}).get("name") == "opulence-artifacts":
            print("[PASS] Initialize response correct")
        else:
            print("[FAIL] Initialize response incorrect")
            all_passed = False

        # Check tools/list
        tools = responses[1].get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        expected_tools = ["artifact__read", "artifact__list", "artifact__search"]
        if all(t in tool_names for t in expected_tools):
            print(f"[PASS] All tools registered: {tool_names}")
        else:
            print(f"[FAIL] Missing tools. Found: {tool_names}")
            all_passed = False

        # Check artifact__list
        list_result = json.loads(responses[2].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if list_result.get("count", 0) > 0:
            print(f"[PASS] artifact__list returned {list_result['count']} artifacts")
        else:
            print("[FAIL] artifact__list returned no artifacts")
            all_passed = False

        # Check artifact__read
        read_result = json.loads(responses[3].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if read_result.get("content", {}).get("type") == "nmap":
            print("[PASS] artifact__read returned correct content")
        else:
            print(f"[FAIL] artifact__read returned unexpected content: {read_result.get('error', 'unknown')}")
            all_passed = False

        # Check artifact__search
        search_result = json.loads(responses[4].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if search_result.get("result_count", 0) > 0:
            print(f"[PASS] artifact__search found {search_result['result_count']} results")
        else:
            print("[FAIL] artifact__search found no results")
            all_passed = False

        return all_passed

    finally:
        shutil.rmtree(temp_dir)


def test_manifest_server():
    """Test the opulence-manifest MCP server."""
    print("\n" + "="*60)
    print("Testing opulence-manifest MCP Server")
    print("="*60)

    temp_dir = tempfile.mkdtemp()
    env = {"OPULENCE_MANIFEST_DIR": temp_dir}

    script_path = os.path.join(os.path.dirname(__file__), "manifest", "server.py")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "manifest__query",
            "arguments": {"section": "all", "depth": "summary"}
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "manifest__update",
            "arguments": {
                "update_type": "finding",
                "data": {
                    "type": "key_findings",
                    "title": "Test Finding",
                    "description": "SSH service on port 22"
                }
            }
        }},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "manifest__get_sessions",
            "arguments": {"limit": 10}
        }}
    ]

    try:
        responses, stderr = send_jsonrpc(script_path, requests, env)

        print(f"\nStderr: {stderr[:500] if stderr else 'None'}")
        print(f"Received {len(responses)} responses")

        all_passed = True

        # Check initialize
        if responses[0].get("result", {}).get("serverInfo", {}).get("name") == "opulence-manifest":
            print("[PASS] Initialize response correct")
        else:
            print("[FAIL] Initialize response incorrect")
            all_passed = False

        # Check tools/list
        tools = responses[1].get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        expected_tools = ["manifest__query", "manifest__get_sessions", "manifest__update"]
        if all(t in tool_names for t in expected_tools):
            print(f"[PASS] All tools registered: {tool_names}")
        else:
            print(f"[FAIL] Missing tools. Found: {tool_names}")
            all_passed = False

        # Check manifest__query
        query_result = json.loads(responses[2].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if "meta" in query_result:
            print("[PASS] manifest__query returned valid manifest summary")
        else:
            print("[FAIL] manifest__query returned invalid response")
            all_passed = False

        # Check manifest__update
        update_result = json.loads(responses[3].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if update_result.get("success"):
            print("[PASS] manifest__update succeeded")
        else:
            print(f"[FAIL] manifest__update failed: {update_result.get('error')}")
            all_passed = False

        # Check manifest__get_sessions
        sessions_result = json.loads(responses[4].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if "sessions" in sessions_result:
            print(f"[PASS] manifest__get_sessions returned {sessions_result.get('count', 0)} sessions")
        else:
            print("[FAIL] manifest__get_sessions returned invalid response")
            all_passed = False

        return all_passed

    finally:
        shutil.rmtree(temp_dir)


def test_scope_server():
    """Test the opulence-scope MCP server."""
    print("\n" + "="*60)
    print("Testing opulence-scope MCP Server")
    print("="*60)

    temp_dir = tempfile.mkdtemp()
    env = {"OPULENCE_SCOPE_DIR": temp_dir}

    # Create initial scope file
    import yaml
    scope_data = {
        "meta": {"operation_id": "test-op"},
        "in_scope": {
            "cidrs": ["10.10.10.0/24", "192.168.1.0/24"],
            "hostnames": ["target.htb", "*.internal.htb"],
            "domains": ["htb"],
            "urls": []
        },
        "out_of_scope": {
            "cidrs": ["10.10.10.254/32"],
            "hostnames": ["dc.htb"],
            "patterns": []
        },
        "action_policies": {
            "scan": "ALLOW",
            "exploit": "ASK",
            "c2": "ASK",
            "exfil": "DENY"
        }
    }
    os.makedirs(temp_dir, exist_ok=True)
    with open(os.path.join(temp_dir, "scope.yaml"), "w") as f:
        yaml.dump(scope_data, f)

    script_path = os.path.join(os.path.dirname(__file__), "scope", "server.py")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "scope__list",
            "arguments": {"include_pending": True}
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "scope__validate",
            "arguments": {"target": "10.10.10.5", "action": "scan"}
        }},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "scope__validate",
            "arguments": {"target": "10.10.10.254", "action": "scan"}
        }},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
            "name": "scope__validate",
            "arguments": {"target": "8.8.8.8", "action": "scan"}
        }},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "scope__request_expansion",
            "arguments": {
                "target": "172.16.0.1",
                "justification": "Discovered via pivot host",
                "agent": "test"
            }
        }}
    ]

    try:
        responses, stderr = send_jsonrpc(script_path, requests, env)

        print(f"\nStderr: {stderr[:500] if stderr else 'None'}")
        print(f"Received {len(responses)} responses")

        all_passed = True

        # Check initialize
        if responses[0].get("result", {}).get("serverInfo", {}).get("name") == "opulence-scope":
            print("[PASS] Initialize response correct")
        else:
            print("[FAIL] Initialize response incorrect")
            all_passed = False

        # Check tools/list
        tools = responses[1].get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        expected_tools = ["scope__validate", "scope__request_expansion", "scope__list"]
        if all(t in tool_names for t in expected_tools):
            print(f"[PASS] All tools registered: {tool_names}")
        else:
            print(f"[FAIL] Missing tools. Found: {tool_names}")
            all_passed = False

        # Check scope__list
        list_result = json.loads(responses[2].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if list_result.get("in_scope", {}).get("cidrs"):
            print("[PASS] scope__list returned valid scope configuration")
        else:
            print("[FAIL] scope__list returned invalid response")
            all_passed = False

        # Check scope__validate (in-scope IP)
        validate_in_scope = json.loads(responses[3].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if validate_in_scope.get("in_scope") == True:
            print("[PASS] scope__validate correctly identified in-scope IP (10.10.10.5)")
        else:
            print(f"[FAIL] scope__validate failed for in-scope IP: {validate_in_scope}")
            all_passed = False

        # Check scope__validate (out-of-scope IP)
        validate_blocked = json.loads(responses[4].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if validate_blocked.get("blocked") == True:
            print("[PASS] scope__validate correctly blocked out-of-scope IP (10.10.10.254)")
        else:
            print(f"[FAIL] scope__validate failed to block OOS IP: {validate_blocked}")
            all_passed = False

        # Check scope__validate (unknown IP)
        validate_unknown = json.loads(responses[5].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if validate_unknown.get("in_scope") == False and not validate_unknown.get("blocked"):
            print("[PASS] scope__validate correctly identified out-of-scope IP (8.8.8.8)")
        else:
            print(f"[FAIL] scope__validate unexpected for unknown IP: {validate_unknown}")
            all_passed = False

        # Check scope__request_expansion
        expansion_result = json.loads(responses[6].get("result", {}).get("content", [{}])[0].get("text", "{}"))
        if expansion_result.get("success") and expansion_result.get("status") == "pending":
            print("[PASS] scope__request_expansion created pending request")
        else:
            print(f"[FAIL] scope__request_expansion failed: {expansion_result}")
            all_passed = False

        return all_passed

    finally:
        shutil.rmtree(temp_dir)


def main():
    """Run all tests."""
    print("="*60)
    print("Agent Opulence - MCP Server Test Suite")
    print("Stream C: Custom MCP Servers")
    print("="*60)

    results = {}

    try:
        results["artifacts"] = test_artifacts_server()
    except Exception as e:
        print(f"[ERROR] Artifacts server test crashed: {e}")
        results["artifacts"] = False

    try:
        results["manifest"] = test_manifest_server()
    except Exception as e:
        print(f"[ERROR] Manifest server test crashed: {e}")
        results["manifest"] = False

    try:
        results["scope"] = test_scope_server()
    except Exception as e:
        print(f"[ERROR] Scope server test crashed: {e}")
        results["scope"] = False

    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    all_passed = True
    for server, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  opulence-{server}: [{status}]")
        if not passed:
            all_passed = False

    print("="*60)
    if all_passed:
        print("VICTORY: All MCP servers respond correctly to JSON-RPC requests!")
        return 0
    else:
        print("FAILURE: Some tests did not pass.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
