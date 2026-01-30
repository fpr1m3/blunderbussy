"""app.py - Flask application factory.

Creates and configures the main Flask application instance.
Registers all route blueprints.
"""
from flask import Flask


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev'

    from . import run_cmd, deserialize, dynamic_exec, template, db_query
    app.register_blueprint(run_cmd.bp)
    app.register_blueprint(deserialize.bp)
    app.register_blueprint(dynamic_exec.bp)
    app.register_blueprint(template.bp)
    app.register_blueprint(db_query.bp)

    return app
