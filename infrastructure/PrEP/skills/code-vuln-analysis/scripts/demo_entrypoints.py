#!/usr/bin/env python3
"""
Demo script showing entry point detection capabilities.

Creates sample files and demonstrates detection across multiple frameworks.
"""

import tempfile
import os
import json
from pathlib import Path
from entrypoints import detect_entrypoints, format_output


def create_demo_files():
    """Create temporary demo files demonstrating various patterns."""
    demo_dir = tempfile.mkdtemp(prefix='entrypoint_demo_')

    # Flask app
    flask_app = os.path.join(demo_dir, 'app.py')
    with open(flask_app, 'w') as f:
        f.write("""
from flask import Flask, request
from flask_login import login_required

app = Flask(__name__)

@app.route('/api/users', methods=['GET', 'POST'])
def users():
    return jsonify(users)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin.html')

@app.route('/products/<int:product_id>')
def product_detail(product_id):
    return get_product(product_id)

if __name__ == '__main__':
    app.run(debug=True)
""")

    # Django URLs
    django_urls = os.path.join(demo_dir, 'urls.py')
    with open(django_urls, 'w') as f:
        f.write("""
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('api/posts/', views.post_list),
    path('api/posts/<int:pk>/', views.post_detail),
    re_path(r'^search/(?P<query>[a-z0-9]+)/$', views.search),
]
""")

    # Express routes
    express_routes = os.path.join(demo_dir, 'routes.js')
    with open(express_routes, 'w') as f:
        f.write("""
const express = require('express');
const router = express.Router();

router.get('/api/comments', (req, res) => {
    res.json(comments);
});

router.post('/api/login', (req, res) => {
    res.json({token: generateToken()});
});

router.use('/admin', adminRouter);

module.exports = router;
""")

    # PHP file
    php_dir = os.path.join(demo_dir, 'public')
    os.makedirs(php_dir, exist_ok=True)
    php_file = os.path.join(php_dir, 'upload.php')
    with open(php_file, 'w') as f:
        f.write("""<?php
require_once '../config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $file = $_FILES['upload'];
    move_uploaded_file($file['tmp_name'], './uploads/' . $file['name']);
}
?>""")

    # CLI script
    scripts_dir = os.path.join(demo_dir, 'scripts')
    os.makedirs(scripts_dir, exist_ok=True)
    backup_script = os.path.join(scripts_dir, 'backup.sh')
    with open(backup_script, 'w') as f:
        f.write("""#!/bin/bash
# cron: 0 2 * * *

echo "Running nightly backup..."
tar -czf /backups/app-$(date +%Y%m%d).tar.gz /var/www/html
""")

    # Python CLI tool
    cli_tool = os.path.join(scripts_dir, 'migrate.py')
    with open(cli_tool, 'w') as f:
        f.write("""#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser(description='Database migration tool')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()

    if args.apply:
        apply_migrations()

if __name__ == '__main__':
    main()
""")

    return demo_dir


def demo():
    """Run the demonstration."""
    print("=" * 70)
    print("Entry Point Detection Demo")
    print("=" * 70)
    print()

    # Create demo files
    print("[1] Creating sample application files...")
    demo_dir = create_demo_files()
    print(f"    Demo directory: {demo_dir}")
    print()

    # Collect all files
    all_files = []
    for root, dirs, files in os.walk(demo_dir):
        for file in files:
            all_files.append(os.path.join(root, file))

    print(f"[2] Scanning {len(all_files)} files...")
    print()

    # Detect entry points
    entry_points = detect_entrypoints(all_files)
    print(f"[3] Found {len(entry_points)} entry points")
    print()

    # Format output
    output = format_output(entry_points)

    # Display results
    print("=" * 70)
    print("Web Routes")
    print("=" * 70)
    for route in output['web_routes']:
        auth_indicator = "[AUTH]" if route['auth_required'] else "[OPEN]"
        methods = ",".join(route['methods'])
        print(f"{auth_indicator} {methods:12} {route['route']:30} ({route['framework']})")
        print(f"         → {route['file']}:{route['line']}")
        print()

    print("=" * 70)
    print("API Endpoints")
    print("=" * 70)
    for endpoint in output['api_endpoints']:
        methods = ",".join(endpoint['methods'])
        print(f"{methods:12} {endpoint['route']:30} ({endpoint['framework']})")
        print(f"         → {endpoint['file']}:{endpoint['line']}")
        print()

    print("=" * 70)
    print("CLI Scripts")
    print("=" * 70)
    for script in output['cli_scripts']:
        print(f"Command: {script['command']}")
        print(f"    → {script['file']}")
        metadata = script.get('metadata', {})
        if metadata:
            print(f"    Metadata: {metadata}")
        print()

    print("=" * 70)
    print("Cron Jobs")
    print("=" * 70)
    for cron in output['cron_jobs']:
        print(f"Schedule: {cron['schedule']}")
        print(f"    → {cron['file']}:{cron['line']}")
        print()

    # Summary statistics
    print("=" * 70)
    print("Summary Statistics")
    print("=" * 70)
    total_web = len(output['web_routes']) + len(output['api_endpoints'])
    auth_required = sum(1 for r in output['web_routes'] if r['auth_required'])
    open_routes = total_web - auth_required

    print(f"Total Entry Points:     {len(entry_points)}")
    print(f"  Web Routes:           {len(output['web_routes'])}")
    print(f"  API Endpoints:        {len(output['api_endpoints'])}")
    print(f"  CLI Scripts:          {len(output['cli_scripts'])}")
    print(f"  Cron Jobs:            {len(output['cron_jobs'])}")
    print()
    print(f"Authentication Status:")
    print(f"  Open (no auth):       {open_routes}")
    print(f"  Protected (auth):     {auth_required}")
    print()

    # JSON output
    print("=" * 70)
    print("JSON Output (for agent consumption)")
    print("=" * 70)
    print(json.dumps(output, indent=2))
    print()

    # Cleanup
    print("=" * 70)
    print(f"[4] Cleaning up demo directory: {demo_dir}")
    import shutil
    shutil.rmtree(demo_dir)
    print("    Done!")


if __name__ == '__main__':
    demo()
