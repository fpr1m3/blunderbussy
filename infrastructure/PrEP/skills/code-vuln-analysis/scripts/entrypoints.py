#!/usr/bin/env python3
"""
Entry Point Detection for Code Vulnerability Analysis
======================================================

Identifies application entry points (web routes, CLI scripts, cron jobs) to map
the attack surface during reconnaissance phase.

This module detects:
- Web routes (Flask, Django, Express, PHP routing)
- CLI scripts (shebangs, __main__ blocks)
- Direct web endpoints (PHP files, CGI scripts)
- API endpoints (REST routes, GraphQL resolvers)

Usage:
    from entrypoints import detect_entrypoints, EntryPoint, EntryPointType

    files = glob.glob("**/*.php", recursive=True)
    entry_points = detect_entrypoints(files)

    for ep in entry_points:
        print(f"{ep.type}: {ep.route} in {ep.file}")
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Dict, Any


class EntryPointType(str, Enum):
    """Types of application entry points."""
    WEB_ROUTE = "web_route"           # Framework-defined routes
    WEB_DIRECT = "web_direct"         # Direct file access (PHP, CGI)
    CLI_SCRIPT = "cli_script"         # Command-line scripts
    CRON_JOB = "cron_job"             # Scheduled tasks
    API_ENDPOINT = "api_endpoint"     # API routes
    WEBSOCKET = "websocket"           # WebSocket handlers
    GRAPHQL = "graphql"               # GraphQL resolvers
    UNKNOWN = "unknown"


@dataclass
class EntryPoint:
    """Represents an application entry point."""
    file: str
    type: EntryPointType
    route: str = ""                    # URL path or pattern
    pattern: str = ""                  # Regex pattern if dynamic
    methods: List[str] = field(default_factory=list)  # HTTP methods
    auth_required: bool = False        # Whether auth is detected
    line: Optional[int] = None         # Line number in source
    function: Optional[str] = None     # Handler function name
    framework: Optional[str] = None    # Detected framework
    schedule: Optional[str] = None     # Cron schedule if applicable
    command: Optional[str] = None      # CLI command/entrypoint
    metadata: Dict[str, Any] = field(default_factory=dict)


# Framework detection patterns
FRAMEWORK_PATTERNS = {
    'flask': re.compile(r'@app\.route|@bp\.route|from flask import'),
    'django': re.compile(r'urlpatterns\s*=|path\(|re_path\(|from django'),
    'express': re.compile(r"(?:app|router)\.(get|post|put|delete|patch|use)|express\(\)|require\(['\"]express['\"]"),
    'fastapi': re.compile(r'@app\.(get|post|put|delete|patch)|from fastapi'),
    'laravel': re.compile(r'Route::(get|post|put|delete|patch)|Illuminate\\Routing'),
    'symfony': re.compile(r'@Route\(|use Symfony\\Component\\Routing'),
}


def detect_entrypoints(files: List[str]) -> List[EntryPoint]:
    """
    Main entry point detection function.

    Args:
        files: List of file paths to analyze

    Returns:
        List of detected EntryPoint objects
    """
    entry_points = []

    for file_path in files:
        try:
            language = detect_language(file_path)

            # CLI script detection
            if is_cli_script(file_path):
                cli_eps = detect_cli_scripts(file_path)
                entry_points.extend(cli_eps)

            # Web route detection
            if language in ('python', 'javascript', 'typescript', 'php', 'ruby'):
                web_eps = detect_web_routes(file_path, language)
                entry_points.extend(web_eps)

            # Cron job detection
            if language == 'python' or file_path.endswith('.sh'):
                cron_eps = detect_cron_indicators(file_path)
                entry_points.extend(cron_eps)

        except Exception as e:
            # Skip files that can't be read or parsed
            continue

    return entry_points


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.java': 'java',
        '.cs': 'csharp',
        '.sh': 'shell',
        '.bash': 'shell',
    }
    suffix = Path(file_path).suffix.lower()
    return ext_map.get(suffix, 'unknown')


def detect_web_routes(file_path: str, language: str) -> List[EntryPoint]:
    """
    Detect web routes based on framework patterns.

    Args:
        file_path: Path to source file
        language: Programming language

    Returns:
        List of detected web route entry points
    """
    entry_points = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return entry_points

    # Detect framework
    framework = detect_framework(content)

    if language == 'python':
        if 'flask' in framework.lower():
            entry_points.extend(detect_flask_routes(file_path, content))
        elif 'django' in framework.lower():
            entry_points.extend(detect_django_routes(file_path, content))
        elif 'fastapi' in framework.lower():
            entry_points.extend(detect_fastapi_routes(file_path, content))

    elif language in ('javascript', 'typescript'):
        if 'express' in framework.lower():
            entry_points.extend(detect_express_routes(file_path, content))

    elif language == 'php':
        entry_points.extend(detect_php_routes(file_path, content))

    return entry_points


def detect_framework(content: str) -> str:
    """Detect web framework from file content."""
    for framework, pattern in FRAMEWORK_PATTERNS.items():
        if pattern.search(content):
            return framework
    return 'unknown'


def detect_flask_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect Flask route decorators."""
    entry_points = []

    # Pattern: @app.route('/path', methods=['GET', 'POST'])
    # More flexible to handle various spacing and quote styles
    route_pattern = re.compile(
        r"@(?:app|bp)\.route\s*\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*methods\s*=\s*\[([^\]]+)\])?\s*\)",
        re.MULTILINE
    )

    for match in route_pattern.finditer(content):
        route = match.group(1)
        methods_str = match.group(2)

        if methods_str:
            # Parse methods from list
            methods = [m.strip().strip("'\"") for m in methods_str.split(',')]
        else:
            # Default to GET if no methods specified
            methods = ['GET']

        line_num = content[:match.start()].count('\n') + 1

        # Detect auth decorators (check both before AND after the route decorator)
        auth_required = detect_auth_decorator_flask(content, match.start(), match.end())

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.WEB_ROUTE,
            route=route,
            methods=methods,
            auth_required=auth_required,
            line=line_num,
            framework='flask'
        ))

    return entry_points


def detect_django_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect Django URL patterns."""
    entry_points = []

    # Pattern: path('route/', view_function) or re_path(r'^pattern$', view)
    # Also handle views.function_name pattern and raw strings (r'...')
    path_pattern = re.compile(
        r"(?:path|re_path)\s*\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*(?:views\.)?(\w+)",
        re.MULTILINE
    )

    for match in path_pattern.finditer(content):
        route = match.group(1)
        view_func = match.group(2)
        line_num = content[:match.start()].count('\n') + 1

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.WEB_ROUTE,
            route=route,
            function=view_func,
            line=line_num,
            framework='django',
            methods=['GET', 'POST']  # Django views handle multiple methods
        ))

    return entry_points


def detect_fastapi_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect FastAPI route decorators."""
    entry_points = []

    # Pattern: @app.get('/path')
    route_pattern = re.compile(
        r"@app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)",
        re.MULTILINE
    )

    for match in route_pattern.finditer(content):
        method = match.group(1).upper()
        route = match.group(2)
        line_num = content[:match.start()].count('\n') + 1

        auth_required = detect_auth_decorator(content, match.start())

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.API_ENDPOINT,
            route=route,
            methods=[method],
            auth_required=auth_required,
            line=line_num,
            framework='fastapi'
        ))

    return entry_points


def detect_express_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect Express.js routes."""
    entry_points = []

    # Pattern: app.get('/path', handler)
    route_pattern = re.compile(
        r"(?:app|router)\.(get|post|put|delete|patch|use)\(['\"]([^'\"]+)['\"]\s*,",
        re.MULTILINE
    )

    for match in route_pattern.finditer(content):
        method = match.group(1).upper()
        route = match.group(2)
        line_num = content[:match.start()].count('\n') + 1

        # 'use' can be any method
        methods = [method] if method != 'USE' else ['GET', 'POST', 'PUT', 'DELETE']

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.WEB_ROUTE,
            route=route,
            methods=methods,
            line=line_num,
            framework='express'
        ))

    return entry_points


def detect_php_routes(file_path: str, content: str) -> List[EntryPoint]:
    """Detect PHP routes and direct access patterns."""
    entry_points = []

    # Direct file access (PHP files are entry points)
    if file_path.endswith('.php'):
        # Check if it's in a web-accessible directory
        web_dirs = ['public', 'www', 'html', 'web', 'htdocs']
        is_web_accessible = any(d in file_path.lower() for d in web_dirs)

        if is_web_accessible or 'index.php' in file_path:
            # Derive URL from file path
            route = Path(file_path).name

            entry_points.append(EntryPoint(
                file=file_path,
                type=EntryPointType.WEB_DIRECT,
                route=f'/{route}',
                methods=['GET', 'POST'],
                framework='php'
            ))

    # Manual routing via $_SERVER['REQUEST_URI']
    routing_pattern = re.compile(
        r"\$_SERVER\[['\"]REQUEST_URI['\"]\]",
        re.MULTILINE
    )

    if routing_pattern.search(content):
        # PHP does manual routing - mark as route handler
        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.WEB_ROUTE,
            route='/*',  # Dynamic routing
            methods=['GET', 'POST'],
            framework='php',
            metadata={'routing_type': 'manual'}
        ))

    # Laravel routes
    laravel_pattern = re.compile(
        r"Route::(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\s*,",
        re.MULTILINE
    )

    for match in laravel_pattern.finditer(content):
        method = match.group(1).upper()
        route = match.group(2)
        line_num = content[:match.start()].count('\n') + 1

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.WEB_ROUTE,
            route=route,
            methods=[method],
            line=line_num,
            framework='laravel'
        ))

    return entry_points


def detect_cli_scripts(file_path: str) -> List[EntryPoint]:
    """Detect CLI script entry points."""
    entry_points = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return entry_points

    # Python __main__ block
    main_pattern = re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']', re.MULTILINE)
    if main_pattern.search(content):
        command = Path(file_path).name
        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.CLI_SCRIPT,
            command=f'python {command}',
            metadata={'entry_type': '__main__'}
        ))

    # Shebang detection
    if content.startswith('#!'):
        shebang_line = content.split('\n')[0]
        interpreter = shebang_line.strip('#!').strip()
        command = Path(file_path).name

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.CLI_SCRIPT,
            command=f'./{command}',
            line=1,
            metadata={'shebang': interpreter}
        ))

    # Argparse/Click detection (Python CLI frameworks)
    if 'argparse.ArgumentParser' in content or 'import click' in content:
        if not any(ep.type == EntryPointType.CLI_SCRIPT for ep in entry_points):
            entry_points.append(EntryPoint(
                file=file_path,
                type=EntryPointType.CLI_SCRIPT,
                command=f'python {Path(file_path).name}',
                metadata={'cli_framework': 'argparse/click'}
            ))

    return entry_points


def detect_cron_indicators(file_path: str) -> List[EntryPoint]:
    """Detect cron job indicators in scripts."""
    entry_points = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return entry_points

    # Look for cron schedule comments
    cron_comment_pattern = re.compile(
        r'#\s*cron:\s*(.+?)(?:\n|$)',
        re.MULTILINE | re.IGNORECASE
    )

    for match in cron_comment_pattern.finditer(content):
        schedule = match.group(1).strip()
        line_num = content[:match.start()].count('\n') + 1

        entry_points.append(EntryPoint(
            file=file_path,
            type=EntryPointType.CRON_JOB,
            schedule=schedule,
            line=line_num,
            command=Path(file_path).name
        ))

    return entry_points


def is_cli_script(file_path: str) -> bool:
    """Check if file is likely a CLI script."""
    # Check extension
    cli_extensions = ['.py', '.sh', '.bash', '.pl', '.rb']
    if not any(file_path.endswith(ext) for ext in cli_extensions):
        return False

    # Check if in typical CLI script directories OR has script-like name
    cli_dirs = ['bin', 'scripts', 'cli', 'commands', 'tools']
    path_parts = [p.lower() for p in Path(file_path).parts]

    # Also check for common script names
    filename = Path(file_path).name.lower()
    script_names = ['manage', 'run', 'setup', 'install', 'deploy', 'backup', 'test']

    has_cli_dir = any(d in path_parts for d in cli_dirs)
    has_script_name = any(name in filename for name in script_names)

    return has_cli_dir or has_script_name


def detect_auth_decorator(content: str, position: int) -> bool:
    """
    Detect authentication decorators before a route.

    Looks for decorators like @login_required, @require_auth, etc.
    within 5 lines before the position.
    """
    lines_before = content[:position].split('\n')[-5:]
    auth_patterns = [
        '@login_required',
        '@require_auth',
        '@authenticated',
        '@require_permission',
        '@authorize',
        '@jwt_required',
        '@token_required',
    ]

    for line in lines_before:
        # Only match if it's a decorator (starts with @)
        if any(pattern in line for pattern in auth_patterns):
            return True

    return False


def detect_auth_decorator_flask(content: str, route_start: int, route_end: int) -> bool:
    """
    Detect authentication decorators for Flask routes.

    Checks both BEFORE the @app.route decorator and BETWEEN the @app.route
    and the function definition, since auth decorators can appear in either position.

    Looks for decorators in the decorator chain leading up to the function def.
    """
    auth_patterns = [
        '@login_required',
        '@require_auth',
        '@authenticated',
        '@require_permission',
        '@authorize',
        '@jwt_required',
        '@token_required',
    ]

    # Check lines AFTER the route decorator up to the function definition
    # This is where auth decorators typically appear in Flask
    lines_after_route = content[route_end:].split('\n')[:10]

    found_def = False
    for line in lines_after_route:
        stripped = line.strip()

        # Stop at function definition
        if stripped.startswith('def '):
            found_def = True
            break

        # Skip blank lines (they're part of the decorator chain)
        if not stripped:
            continue

        # Check for auth decorators
        if any(pattern in stripped for pattern in auth_patterns):
            return True

        # Stop if we hit non-decorator code (but not blank lines or def)
        if stripped and not stripped.startswith('@'):
            break

    # Also check lines immediately BEFORE route decorator
    # (some styles put all decorators before @app.route)
    lines_before = content[:route_start].split('\n')

    # Walk backwards from route_start
    for line in reversed(lines_before):
        stripped = line.strip()

        # Skip blank lines
        if not stripped:
            continue

        # Stop at non-decorator lines (function defs, other code)
        if not stripped.startswith('@'):
            break

        # Check for auth decorators
        if any(pattern in stripped for pattern in auth_patterns):
            return True

    return False


def format_output(entry_points: List[EntryPoint]) -> Dict[str, Any]:
    """
    Format entry points into YAML-compatible output structure.

    Matches the format specified in SKILL.md lines 75-78:
        entry_points:
          web_routes: [{file, methods, auth_required}]
          cron_jobs: [{file, schedule}]
          cli_scripts: [{file, command}]
    """
    output = {
        'web_routes': [],
        'cron_jobs': [],
        'cli_scripts': [],
        'api_endpoints': [],
    }

    for ep in entry_points:
        if ep.type in (EntryPointType.WEB_ROUTE, EntryPointType.WEB_DIRECT):
            output['web_routes'].append({
                'file': ep.file,
                'route': ep.route,
                'methods': ep.methods,
                'auth_required': ep.auth_required,
                'line': ep.line,
                'framework': ep.framework,
            })

        elif ep.type == EntryPointType.API_ENDPOINT:
            output['api_endpoints'].append({
                'file': ep.file,
                'route': ep.route,
                'methods': ep.methods,
                'auth_required': ep.auth_required,
                'line': ep.line,
                'framework': ep.framework,
            })

        elif ep.type == EntryPointType.CRON_JOB:
            output['cron_jobs'].append({
                'file': ep.file,
                'schedule': ep.schedule,
                'line': ep.line,
            })

        elif ep.type == EntryPointType.CLI_SCRIPT:
            output['cli_scripts'].append({
                'file': ep.file,
                'command': ep.command,
                'metadata': ep.metadata,
            })

    return output


if __name__ == '__main__':
    # Demo: Detect entry points in current directory
    import glob
    import json

    patterns = ['**/*.py', '**/*.php', '**/*.js']
    all_files = []

    for pattern in patterns:
        all_files.extend(glob.glob(pattern, recursive=True))

    print(f"Scanning {len(all_files)} files for entry points...")
    entry_points = detect_entrypoints(all_files)

    output = format_output(entry_points)

    print(f"\nFound {len(entry_points)} entry points:")
    print(f"  Web routes: {len(output['web_routes'])}")
    print(f"  API endpoints: {len(output['api_endpoints'])}")
    print(f"  CLI scripts: {len(output['cli_scripts'])}")
    print(f"  Cron jobs: {len(output['cron_jobs'])}")

    print("\n" + "=" * 60)
    print(json.dumps(output, indent=2))
