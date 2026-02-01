#!/usr/bin/env python3
"""
Unit tests for entry point detection.
"""

import tempfile
import os
from pathlib import Path
from entrypoints import (
    detect_entrypoints,
    detect_web_routes,
    detect_cli_scripts,
    detect_flask_routes,
    detect_django_routes,
    detect_express_routes,
    detect_php_routes,
    EntryPoint,
    EntryPointType,
    format_output,
)


def create_temp_file(content: str, suffix: str = '.py') -> str:
    """Create a temporary file with given content."""
    fd, path = tempfile.mkstemp(suffix=suffix, text=True)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


def test_flask_routes():
    """Test Flask route detection."""
    flask_code = """
from flask import Flask

app = Flask(__name__)

@app.route('/api/users', methods=['GET', 'POST'])
def users():
    return "Users"

@app.route('/admin')
@login_required
def admin():
    return "Admin"

@app.route('/public/<int:id>')
def public(id):
    return f"Public {id}"
"""

    temp_file = create_temp_file(flask_code, '.py')

    try:
        with open(temp_file, 'r') as f:
            content = f.read()

        routes = detect_flask_routes(temp_file, content)

        assert len(routes) == 3, f"Expected 3 routes, found {len(routes)}"

        # Check /api/users
        api_route = [r for r in routes if r.route == '/api/users'][0]
        assert 'GET' in api_route.methods
        assert 'POST' in api_route.methods

        # Check /admin has auth
        admin_route = [r for r in routes if r.route == '/admin'][0]
        assert admin_route.auth_required is True

        # Check /public has no auth
        public_route = [r for r in routes if r.route == '/public/<int:id>'][0]
        assert public_route.auth_required is False

        print("✓ Flask route detection passed")

    finally:
        os.unlink(temp_file)


def test_django_routes():
    """Test Django URL pattern detection."""
    django_code = """
from django.urls import path
from . import views

urlpatterns = [
    path('api/users/', views.user_list),
    path('admin/dashboard/', views.admin_dashboard),
    re_path(r'^products/(?P<id>[0-9]+)/$', views.product_detail),
]
"""

    temp_file = create_temp_file(django_code, '.py')

    try:
        with open(temp_file, 'r') as f:
            content = f.read()

        routes = detect_django_routes(temp_file, content)

        assert len(routes) == 3, f"Expected 3 routes, found {len(routes)}"

        # Check function names captured
        user_route = [r for r in routes if 'users' in r.route][0]
        assert user_route.function == 'user_list'

        print("✓ Django route detection passed")

    finally:
        os.unlink(temp_file)


def test_express_routes():
    """Test Express.js route detection."""
    express_code = """
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json(users);
});

app.post('/api/login', (req, res) => {
    res.json({token: 'xxx'});
});

router.use('/admin', adminRouter);
"""

    temp_file = create_temp_file(express_code, '.js')

    try:
        with open(temp_file, 'r') as f:
            content = f.read()

        routes = detect_express_routes(temp_file, content)

        assert len(routes) >= 2, f"Expected at least 2 routes, found {len(routes)}"

        # Check GET route
        get_route = [r for r in routes if r.route == '/api/users'][0]
        assert 'GET' in get_route.methods

        # Check POST route
        post_route = [r for r in routes if r.route == '/api/login'][0]
        assert 'POST' in post_route.methods

        print("✓ Express route detection passed")

    finally:
        os.unlink(temp_file)


def test_php_direct_access():
    """Test PHP direct file access detection."""
    php_code = """<?php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = $_GET['id'];
    mysql_query("SELECT * FROM users WHERE id = $id");
}
?>"""

    # Create file in a web-accessible directory name
    temp_dir = tempfile.mkdtemp(suffix='public')
    temp_file = os.path.join(temp_dir, 'admin.php')

    with open(temp_file, 'w') as f:
        f.write(php_code)

    try:
        with open(temp_file, 'r') as f:
            content = f.read()

        routes = detect_php_routes(temp_file, content)

        # Should detect direct access
        assert len(routes) >= 1, f"Expected at least 1 route, found {len(routes)}"

        direct_route = routes[0]
        assert direct_route.type in (EntryPointType.WEB_DIRECT, EntryPointType.WEB_ROUTE)

        print("✓ PHP direct access detection passed")

    finally:
        os.unlink(temp_file)
        os.rmdir(temp_dir)


def test_cli_script_detection():
    """Test CLI script detection."""
    python_cli = """#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    print(f"Processing {args.input}")

if __name__ == '__main__':
    main()
"""

    temp_file = create_temp_file(python_cli, '.py')

    try:
        cli_scripts = detect_cli_scripts(temp_file)

        assert len(cli_scripts) >= 1, f"Expected at least 1 CLI script, found {len(cli_scripts)}"

        # Should detect both shebang and __main__
        has_shebang = any('shebang' in ep.metadata for ep in cli_scripts)
        has_main = any('__main__' in str(ep.metadata) for ep in cli_scripts)

        assert has_shebang or has_main, "Should detect shebang or __main__ block"

        print("✓ CLI script detection passed")

    finally:
        os.unlink(temp_file)


def test_bash_script_detection():
    """Test Bash script CLI detection."""
    bash_script = """#!/bin/bash
# cron: 0 2 * * *

echo "Running nightly backup"
tar -czf backup.tar.gz /var/www/html
"""

    # Create in scripts directory
    temp_dir = tempfile.mkdtemp(suffix='scripts')
    temp_file = os.path.join(temp_dir, 'backup.sh')

    with open(temp_file, 'w') as f:
        f.write(bash_script)

    try:
        entry_points = detect_entrypoints([temp_file])

        # Should detect CLI script
        cli_scripts = [ep for ep in entry_points if ep.type == EntryPointType.CLI_SCRIPT]
        assert len(cli_scripts) >= 1, "Should detect bash script as CLI"

        # Should detect cron schedule
        cron_jobs = [ep for ep in entry_points if ep.type == EntryPointType.CRON_JOB]
        assert len(cron_jobs) >= 1, "Should detect cron schedule"

        if cron_jobs:
            assert '0 2 * * *' in cron_jobs[0].schedule

        print("✓ Bash script and cron detection passed")

    finally:
        os.unlink(temp_file)
        os.rmdir(temp_dir)


def test_format_output():
    """Test output formatting."""
    entry_points = [
        EntryPoint(
            file='/app/routes.py',
            type=EntryPointType.WEB_ROUTE,
            route='/api/users',
            methods=['GET', 'POST'],
            auth_required=True,
            line=10,
            framework='flask'
        ),
        EntryPoint(
            file='/scripts/backup.sh',
            type=EntryPointType.CRON_JOB,
            schedule='0 2 * * *',
            line=2
        ),
        EntryPoint(
            file='/scripts/manage.py',
            type=EntryPointType.CLI_SCRIPT,
            command='python manage.py',
            metadata={'entry_type': '__main__'}
        ),
    ]

    output = format_output(entry_points)

    assert len(output['web_routes']) == 1
    assert len(output['cron_jobs']) == 1
    assert len(output['cli_scripts']) == 1

    # Check structure
    web_route = output['web_routes'][0]
    assert web_route['file'] == '/app/routes.py'
    assert web_route['route'] == '/api/users'
    assert web_route['auth_required'] is True
    assert 'GET' in web_route['methods']

    cron_job = output['cron_jobs'][0]
    assert cron_job['schedule'] == '0 2 * * *'

    cli_script = output['cli_scripts'][0]
    assert cli_script['command'] == 'python manage.py'

    print("✓ Output formatting passed")


def test_auth_detection():
    """Test authentication decorator detection."""
    flask_auth = """
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route('/admin')
@login_required
def admin():
    return "Admin"

@app.route('/public')
def public():
    return "Public"

@app.route('/api/protected')
@jwt_required
def protected():
    return "Protected"
"""

    temp_file = create_temp_file(flask_auth, '.py')

    try:
        with open(temp_file, 'r') as f:
            content = f.read()

        routes = detect_flask_routes(temp_file, content)

        # Check auth detection
        admin_route = [r for r in routes if r.route == '/admin'][0]
        assert admin_route.auth_required is True, "/admin should require auth"

        public_route = [r for r in routes if r.route == '/public'][0]
        assert public_route.auth_required is False, "/public should not require auth"

        protected_route = [r for r in routes if r.route == '/api/protected'][0]
        assert protected_route.auth_required is True, "/api/protected should require auth"

        print("✓ Authentication detection passed")

    finally:
        os.unlink(temp_file)


def run_all_tests():
    """Run all tests."""
    tests = [
        test_flask_routes,
        test_django_routes,
        test_express_routes,
        test_php_direct_access,
        test_cli_script_detection,
        test_bash_script_detection,
        test_format_output,
        test_auth_detection,
    ]

    print("Running entry point detection tests...\n")

    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")

    print("\n" + "=" * 60)
    print("All tests completed!")


if __name__ == '__main__':
    run_all_tests()
