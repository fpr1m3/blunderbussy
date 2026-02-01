#!/usr/bin/env python3
"""
Dependency Graph Builder for Code Vulnerability Analysis
=========================================================

Parses source files to extract import/include statements and builds a
dependency graph showing which files depend on which others.

Output format matches SKILL.md lines 70-76 (dependency_graph.includes).
This data is consumed by chunker.py (lines 436-451) to group related files.

Key features:
- Multi-language support: PHP, Python, JavaScript/TypeScript
- Relative path resolution to project-relative paths
- YAML export matching recon agent schema
- Reverse dependency tracking (what imports what)

Supported patterns:

PHP:
  - include "file.php"
  - include_once('file.php')
  - require "file.php"
  - require_once('file.php')

Python:
  - import module
  - from module import something
  - from .relative import something

JavaScript/TypeScript:
  - import { thing } from './module'
  - import thing from 'module'
  - const x = require('./module')
  - require('module')

Usage:
    from dependencies import parse_imports, build_dependency_graph, to_yaml

    # Parse single file
    imports = parse_imports("path/to/file.php", "php")

    # Build full graph
    files = ["file1.php", "file2.php", "file3.js"]
    graph = build_dependency_graph(files, project_root="/var/www")

    # Export to YAML
    yaml_output = to_yaml(graph)
"""

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import yaml


# Language detection by extension
LANGUAGE_EXTENSIONS = {
    'php': {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7'},
    'python': {'.py', '.pyw', '.pyx'},
    'javascript': {'.js', '.jsx', '.mjs', '.cjs'},
    'typescript': {'.ts', '.tsx'},
}


# Regex patterns for import detection
# PHP patterns - capture file paths from include/require statements
PHP_PATTERNS = [
    # include "file.php", include('file.php'), include 'file.php'
    re.compile(r'include\s*[\(\s]+["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'include_once\s*[\(\s]+["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'require\s*[\(\s]+["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'require_once\s*[\(\s]+["\']([^"\']+)["\']', re.IGNORECASE),
]

# Python patterns - capture module names from import statements
PYTHON_PATTERNS = [
    # from module import something, from .relative import something
    re.compile(r'^from\s+([\w.]+)\s+import\s+', re.MULTILINE),
    # import module, import module.submodule
    re.compile(r'^import\s+([\w.]+)', re.MULTILINE),
]

# JavaScript/TypeScript patterns - capture module paths from imports
JS_PATTERNS = [
    # import { thing } from './module', import thing from 'module'
    re.compile(r'import\s+(?:[\w{},\s*]+\s+from\s+)?["\']([^"\']+)["\']'),
    # const x = require('./module'), require('module')
    re.compile(r'require\s*\(["\']([^"\']+)["\']\)'),
]


def detect_language(file_path: str) -> Optional[str]:
    """
    Detect programming language from file extension.

    Args:
        file_path: Path to the source file

    Returns:
        Language name ("php", "python", "javascript", "typescript") or None
    """
    suffix = Path(file_path).suffix.lower()
    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        if suffix in extensions:
            return lang
    return None


def parse_imports(file_path: str, language: Optional[str] = None) -> List[str]:
    """
    Extract import/include statements from a source file.

    Args:
        file_path: Path to the source file
        language: Programming language (auto-detected if None)

    Returns:
        List of imported file paths/module names
    """
    if language is None:
        language = detect_language(file_path)

    if language is None:
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, IOError):
        return []

    imports: Set[str] = set()

    if language == 'php':
        for pattern in PHP_PATTERNS:
            matches = pattern.findall(content)
            imports.update(matches)

    elif language == 'python':
        for pattern in PYTHON_PATTERNS:
            matches = pattern.findall(content)
            # Convert module paths to file paths (module.submodule -> module/submodule.py)
            for match in matches:
                # Handle relative imports (. and ..)
                if match.startswith('.'):
                    # Keep relative imports as-is for now, resolver will handle
                    imports.add(match)
                else:
                    # Convert module.name to module/name.py
                    file_path = match.replace('.', '/') + '.py'
                    imports.add(file_path)

    elif language in ('javascript', 'typescript'):
        for pattern in JS_PATTERNS:
            matches = pattern.findall(content)
            imports.update(matches)

    return sorted(list(imports))


def resolve_path(
    from_file: str,
    import_path: str,
    project_root: str,
    language: str
) -> Optional[str]:
    """
    Resolve an import path to a project-relative path.

    Args:
        from_file: File containing the import statement
        import_path: The imported path (may be relative)
        project_root: Root directory of the project
        language: Programming language for language-specific resolution

    Returns:
        Project-relative path or None if unresolvable
    """
    project_path = Path(project_root).resolve()
    from_path = Path(from_file).resolve()

    # Handle relative paths
    if import_path.startswith('.'):
        # Relative to the importing file's directory
        base_dir = from_path.parent
        target = (base_dir / import_path).resolve()

        # Try with and without extension
        candidates = [target]
        if language == 'python':
            candidates.extend([
                target.with_suffix('.py'),
                target / '__init__.py',
            ])
        elif language in ('javascript', 'typescript'):
            candidates.extend([
                target.with_suffix('.js'),
                target.with_suffix('.jsx'),
                target.with_suffix('.ts'),
                target.with_suffix('.tsx'),
                target / 'index.js',
                target / 'index.ts',
            ])
        elif language == 'php':
            if not target.suffix:
                candidates.append(target.with_suffix('.php'))

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                try:
                    return str(candidate.relative_to(project_path))
                except ValueError:
                    # Path is outside project root
                    return None

    # Absolute path within project
    else:
        target = (project_path / import_path).resolve()

        # Try with and without language-specific extensions
        candidates = [target]
        if language == 'python' and not target.suffix:
            candidates.append(target.with_suffix('.py'))
        elif language in ('javascript', 'typescript') and not target.suffix:
            candidates.extend([
                target.with_suffix('.js'),
                target.with_suffix('.ts'),
            ])
        elif language == 'php' and not target.suffix:
            candidates.append(target.with_suffix('.php'))

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                try:
                    return str(candidate.relative_to(project_path))
                except ValueError:
                    return None

    return None


def build_dependency_graph(
    files: List[str],
    project_root: Optional[str] = None
) -> Dict[str, List[str]]:
    """
    Build a dependency graph for a list of source files.

    Args:
        files: List of file paths to analyze
        project_root: Root directory for resolving relative paths (uses CWD if None)

    Returns:
        Dictionary mapping file paths to their list of imported files
        Format: {from_file: [imported_file1, imported_file2, ...]}
    """
    if project_root is None:
        project_root = str(Path.cwd())

    graph: Dict[str, List[str]] = {}
    project_path = Path(project_root).resolve()

    for file_path in files:
        # Normalize to project-relative path
        abs_path = Path(file_path).resolve()
        try:
            relative_path = str(abs_path.relative_to(project_path))
        except ValueError:
            # File outside project root, use as-is
            relative_path = file_path

        language = detect_language(file_path)
        if language is None:
            continue

        raw_imports = parse_imports(file_path, language)
        resolved_imports: List[str] = []

        for import_path in raw_imports:
            resolved = resolve_path(file_path, import_path, project_root, language)
            if resolved:
                resolved_imports.append(resolved)
            else:
                # Keep unresolved imports (external modules, missing files)
                # These may still be useful for understanding dependencies
                resolved_imports.append(import_path)

        if resolved_imports:
            graph[relative_path] = resolved_imports

    return graph


def to_yaml(graph: Dict[str, List[str]]) -> str:
    """
    Export dependency graph to YAML format matching recon schema.

    Output format (SKILL.md lines 70-76):
        dependency_graph:
          includes:
            - from: admin.php
              imports: [config.php, db.php]

    Args:
        graph: Dependency graph from build_dependency_graph()

    Returns:
        YAML-formatted string
    """
    includes = []
    for from_file, imports in sorted(graph.items()):
        includes.append({
            'from': from_file,
            'imports': imports
        })

    output = {
        'dependency_graph': {
            'includes': includes
        }
    }

    return yaml.dump(output, default_flow_style=False, sort_keys=False)


def get_reverse_dependencies(graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Build reverse dependency mapping (what imports each file).

    Args:
        graph: Forward dependency graph

    Returns:
        Dictionary mapping files to their list of importers
        Format: {imported_file: [file_that_imports_it1, ...]}
    """
    reverse: Dict[str, List[str]] = {}

    for from_file, imports in graph.items():
        for imported in imports:
            if imported not in reverse:
                reverse[imported] = []
            reverse[imported].append(from_file)

    return reverse


def find_dependency_cycles(graph: Dict[str, List[str]]) -> List[List[str]]:
    """
    Detect circular dependencies in the graph.

    Args:
        graph: Dependency graph

    Returns:
        List of cycles, where each cycle is a list of files forming the cycle
    """
    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node: str, path: List[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, path.copy())
            elif neighbor in rec_stack:
                # Found a cycle
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                cycles.append(cycle)

        rec_stack.remove(node)

    for node in graph:
        if node not in visited:
            dfs(node, [])

    return cycles


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="Build dependency graph from source files"
    )
    parser.add_argument(
        'files',
        nargs='+',
        help='Source files to analyze'
    )
    parser.add_argument(
        '--root',
        default='.',
        help='Project root directory for path resolution (default: current directory)'
    )
    parser.add_argument(
        '--reverse',
        action='store_true',
        help='Show reverse dependencies (what imports what)'
    )
    parser.add_argument(
        '--cycles',
        action='store_true',
        help='Detect and show circular dependencies'
    )

    args = parser.parse_args()

    # Build dependency graph
    graph = build_dependency_graph(args.files, args.root)

    if args.cycles:
        cycles = find_dependency_cycles(graph)
        if cycles:
            print("Circular dependencies detected:")
            for i, cycle in enumerate(cycles, 1):
                print(f"\n  Cycle {i}: {' -> '.join(cycle)}")
        else:
            print("No circular dependencies found.")
        sys.exit(0)

    if args.reverse:
        reverse = get_reverse_dependencies(graph)
        print("Reverse dependencies (what imports each file):")
        for file, importers in sorted(reverse.items()):
            print(f"\n{file}:")
            for importer in importers:
                print(f"  <- {importer}")
        sys.exit(0)

    # Output YAML
    print(to_yaml(graph))
