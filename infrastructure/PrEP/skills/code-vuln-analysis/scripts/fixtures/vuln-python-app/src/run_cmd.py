"""run_cmd.py - Network diagnostic tool.

Pings a host provided by the user via query parameter.
"""
import os
from flask import Blueprint, request, jsonify

bp = Blueprint('ping', __name__)

@bp.route('/ping')
def run_ping():
    os.system("ping -c 4 " + request.args.get('host', ''))
    return jsonify({"status": "ping complete"})
