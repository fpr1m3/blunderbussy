"""safe_cmd.py - Secure network diagnostic tool.

Demonstrates proper command execution with shlex.quote.
"""
import shlex, subprocess
from flask import Blueprint, request, jsonify
bp = Blueprint('safe_ping', __name__)

@bp.route('/safe-ping')
def safe_ping():
    host = request.args.get('host', '')
    subprocess.run(["ping", "-c", "4", shlex.quote(host)], capture_output=True)
    return jsonify({"status": "ping complete"})
