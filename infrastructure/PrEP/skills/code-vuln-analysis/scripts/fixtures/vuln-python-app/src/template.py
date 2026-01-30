"""template.py - Dynamic page renderer.

Renders user-supplied templates for customizable page content.
Uses Jinja2 via Flask's render_template_string.
"""
from flask import Blueprint, request
from flask import render_template_string

bp = Blueprint('template', __name__)

# WARNING: This endpoint is intentionally vulnerable for testing.
@bp.route('/render')
def render_page():
    return render_template_string(request.args.get('template', ''))
