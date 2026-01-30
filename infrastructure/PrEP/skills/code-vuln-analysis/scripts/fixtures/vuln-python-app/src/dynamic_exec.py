"""dynamic_exec.py - Dynamic code runner.

Executes user-supplied Python expressions for a calculator feature.
"""
from flask import Blueprint, request, jsonify
bp = Blueprint('calc', __name__)

@bp.route('/calc')
def run_code():
    exec(request.args.get('code', ''))
    return jsonify({"status": "executed"})
