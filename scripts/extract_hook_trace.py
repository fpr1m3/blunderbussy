#!/usr/bin/env python3
"""Extract hook-pipe trace JSONL from a gemini-cli session JSON.

Reads a gemini-cli session transcript and emits one JSONL event per
successful tool call, suitable for replay through the hook pipeline.

Usage:
    python3 scripts/extract_hook_trace.py <session.json> <output.jsonl>

Output schema per line:
    {"seq": 0, "tool_name": "...", "tool_input": {...}, "tool_output": "..."}
"""

import json
import sys
from pathlib import Path


def extract_tool_calls(session: dict) -> list[dict]:
    """Walk session messages and extract successful tool calls."""
    events = []
    seq = 0

    for message in session.get("messages", []):
        if message.get("type") != "gemini":
            continue

        for tc in message.get("toolCalls", []):
            if tc.get("status") != "success":
                continue

            # Extract output from functionResponse
            tool_output = ""
            results = tc.get("result", [])
            if results and isinstance(results, list) and len(results) > 0:
                fr = results[0].get("functionResponse", {})
                resp = fr.get("response", {})
                tool_output = resp.get("output", "")

            events.append(
                {
                    "seq": seq,
                    "tool_name": tc.get("name", ""),
                    "tool_input": tc.get("args", {}),
                    "tool_output": tool_output,
                }
            )
            seq += 1

    return events


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <session.json> <output.jsonl>", file=sys.stderr)
        sys.exit(1)

    session_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    session = json.loads(session_path.read_text())
    events = extract_tool_calls(session)

    with output_path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    # Tool name breakdown
    from collections import Counter

    counts = Counter(e["tool_name"] for e in events)
    summary = ", ".join(f"{n}: {c}" for n, c in counts.most_common())
    print(f"Extracted {len(events)} events ({summary})")


if __name__ == "__main__":
    main()
