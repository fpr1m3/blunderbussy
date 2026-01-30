"""db_query.py - User lookup endpoint.

Searches the database for a user by name using a raw SQL query.
"""
import sqlite3
from flask import Blueprint, request, jsonify

bp = Blueprint('users', __name__)
DATABASE = 'app.db'

def get_cursor():
    return sqlite3.connect(DATABASE).cursor()

@bp.route('/user')
def get_user():
    cursor = get_cursor()
    name = request.args.get('name', '')
    cursor.execute(f"SELECT * FROM users WHERE name = '{request.args.get('name', '')}'")
    user = cursor.fetchone()
    return jsonify({"user": dict(user)} if user else {"error": "not found"})
