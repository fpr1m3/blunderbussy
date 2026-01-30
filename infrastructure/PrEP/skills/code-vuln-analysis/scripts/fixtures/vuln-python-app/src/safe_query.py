"""safe_query.py - Secure user lookup endpoint.

Demonstrates safe SQL with parameterized queries.
"""
import sqlite3
from flask import Blueprint, request, jsonify
bp = Blueprint('safe_users', __name__)

@bp.route('/safe-user')
def safe_get_user():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    name = request.args.get('name', '')
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    user = cursor.fetchone()
    conn.close()
    return jsonify({"user": user} if user else {"error": "not found"})
