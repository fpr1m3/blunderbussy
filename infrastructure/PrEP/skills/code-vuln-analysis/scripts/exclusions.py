#!/usr/bin/env python3
"""
File Exclusion Logic for Code Vulnerability Analysis
=====================================================

Filters out files that aren't worth analyzing during the recon phase,
reducing token usage and focusing analysis on custom application code.

Categories:
- Static assets (CSS, images, fonts)
- Vendor/dependency directories
- Build artifacts
- Test files
- Config/metadata files

Files in vendor directories are flagged for SCA (Software Composition Analysis)
rather than static analysis, as they should be checked against CVE databases.

Usage:
    from exclusions import should_exclude, filter_files, ExclusionResult

    # Check single file
    result = should_exclude("node_modules/express/index.js")
    if result.excluded:
        print(f"Excluded: {result.reason}")
    elif result.recommendation:
        print(f"SCA recommended: {result.recommendation}")

    # Batch filter
    files = ["app.php", "vendor/monolog.php", "styles.css"]
    included, excluded = filter_files(files)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional
import re


@dataclass
class ExclusionResult:
    """Result of file exclusion check."""
    excluded: bool
    reason: str
    recommendation: str = ""


# Static asset extensions
STATIC_EXTENSIONS = {
    # Stylesheets
    '.css', '.scss', '.sass', '.less', '.styl',
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Media
    '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flac',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
}

# Build artifact patterns
BUILD_ARTIFACTS = {
    '.min.js',      # Minified JavaScript
    '.bundle.js',   # Bundled JavaScript
    '.min.css',     # Minified CSS
    '.chunk.js',    # Webpack chunks
    '.map',         # Source maps
    '.d.ts',        # TypeScript declarations (generated)
}

# Vendor/dependency directory names
VENDOR_DIRS = {
    'vendor',           # PHP Composer
    'node_modules',     # npm/yarn
    'bower_components', # Bower
    'jspm_packages',    # JSPM
    'site-packages',    # Python
    'packages',         # NuGet, Go
    'deps',             # Erlang/Elixir
    'lib',              # Generic (common false positive, use cautiously)
    'third_party',      # Generic vendor code
    'external',         # External dependencies
}

# Build output directories
BUILD_DIRS = {
    'dist',
    'build',
    'out',
    'target',      # Java/Rust
    'bin',         # Compiled binaries
    'obj',         # Object files
    '.next',       # Next.js
    '.nuxt',       # Nuxt.js
    '__pycache__', # Python
    '.cache',      # Various
}

# Test file patterns
TEST_PATTERNS = [
    # Python
    re.compile(r'.*_test\.py$'),
    re.compile(r'.*test_.*\.py$'),
    re.compile(r'.*/tests?/.*'),
    re.compile(r'.*/testing/.*'),
    # JavaScript/TypeScript
    re.compile(r'.*\.test\.(js|ts|jsx|tsx)$'),
    re.compile(r'.*\.spec\.(js|ts|jsx|tsx)$'),
    re.compile(r'.*/__tests__/.*'),
    # Ruby
    re.compile(r'.*_spec\.rb$'),
    re.compile(r'.*/spec/.*'),
    # Go
    re.compile(r'.*_test\.go$'),
    # Java
    re.compile(r'.*Test\.java$'),
    re.compile(r'.*/test/.*'),
    # PHP
    re.compile(r'.*Test\.php$'),
    re.compile(r'.*/tests/.*'),
    # Generic
    re.compile(r'.*/fixtures/.*'),
    re.compile(r'.*/mocks?/.*'),
]

# Config/metadata files (exact matches)
CONFIG_FILES = {
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'composer.json',
    'composer.lock',
    'Gemfile',
    'Gemfile.lock',
    'requirements.txt',
    'Pipfile',
    'Pipfile.lock',
    'go.mod',
    'go.sum',
    'Cargo.toml',
    'Cargo.lock',
    '.gitignore',
    '.gitattributes',
    '.dockerignore',
    '.editorconfig',
    '.prettierrc',
    '.eslintrc',
    '.eslintrc.js',
    '.eslintrc.json',
    'tsconfig.json',
    'webpack.config.js',
    'rollup.config.js',
    'vite.config.js',
    'babel.config.js',
    '.babelrc',
    'README.md',
    'README.txt',
    'LICENSE',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
}

# Documentation directories
DOC_DIRS = {
    'docs',
    'documentation',
    'doc',
    'man',
    'examples',
    'samples',
}


def _is_vendor_file(file_path: str) -> bool:
    """Check if file is in a vendor/dependency directory."""
    path_parts = Path(file_path).parts
    return any(vendor_dir in path_parts for vendor_dir in VENDOR_DIRS)


def _is_build_artifact(file_path: str) -> bool:
    """Check if file is a build artifact."""
    path_parts = Path(file_path).parts
    file_lower = file_path.lower()

    # Check build directories
    if any(build_dir in path_parts for build_dir in BUILD_DIRS):
        return True

    # Check build artifact extensions
    return any(file_lower.endswith(pattern) for pattern in BUILD_ARTIFACTS)


def _is_test_file(file_path: str) -> bool:
    """Check if file is a test file."""
    return any(pattern.match(file_path) for pattern in TEST_PATTERNS)


def _is_static_asset(file_path: str) -> bool:
    """Check if file is a static asset."""
    return Path(file_path).suffix.lower() in STATIC_EXTENSIONS


def _is_config_file(file_path: str) -> bool:
    """Check if file is a config/metadata file."""
    return Path(file_path).name in CONFIG_FILES


def _is_documentation(file_path: str) -> bool:
    """Check if file is in documentation directory."""
    path_parts = Path(file_path).parts
    return any(doc_dir in path_parts for doc_dir in DOC_DIRS)


def should_exclude(file_path: str) -> ExclusionResult:
    """
    Determine if a file should be excluded from vulnerability analysis.

    Args:
        file_path: Path to the file (relative or absolute)

    Returns:
        ExclusionResult with exclusion decision, reason, and recommendation

    Examples:
        >>> should_exclude("app/controllers/admin.php")
        ExclusionResult(excluded=False, reason="", recommendation="")

        >>> should_exclude("vendor/symfony/http-kernel/HttpKernel.php")
        ExclusionResult(excluded=False, reason="",
                       recommendation="SCA: Check CVE databases for symfony/http-kernel")

        >>> should_exclude("public/images/logo.png")
        ExclusionResult(excluded=True, reason="Static asset: images", recommendation="")
    """
    # Normalize path separators
    normalized_path = file_path.replace('\\', '/')

    # Check for vendor files (flag for SCA, don't exclude)
    if _is_vendor_file(normalized_path):
        path_parts = Path(normalized_path).parts

        # Try to extract package name for SCA recommendation
        vendor_idx = None
        for i, part in enumerate(path_parts):
            if part in VENDOR_DIRS:
                vendor_idx = i
                break

        if vendor_idx is not None and len(path_parts) > vendor_idx + 1:
            # Extract package info (e.g., "symfony/http-kernel")
            package_parts = path_parts[vendor_idx + 1:vendor_idx + 3]
            package_name = '/'.join(package_parts) if len(package_parts) > 1 else package_parts[0]
            recommendation = f"SCA: Check CVE databases for {package_name}"
        else:
            recommendation = "SCA: Third-party code - check CVE databases"

        return ExclusionResult(
            excluded=False,
            reason="",
            recommendation=recommendation
        )

    # Check for static assets
    if _is_static_asset(normalized_path):
        ext = Path(normalized_path).suffix.lower()
        category = "images" if ext in {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp'} else \
                   "fonts" if ext in {'.woff', '.woff2', '.ttf', '.otf', '.eot'} else \
                   "stylesheets" if ext in {'.css', '.scss', '.sass', '.less'} else \
                   "media" if ext in {'.mp4', '.mp3', '.wav'} else \
                   "documents"
        return ExclusionResult(
            excluded=True,
            reason=f"Static asset: {category}",
            recommendation=""
        )

    # Check for build artifacts
    if _is_build_artifact(normalized_path):
        return ExclusionResult(
            excluded=True,
            reason="Build artifact (minified/bundled code)",
            recommendation=""
        )

    # Check for test files
    if _is_test_file(normalized_path):
        return ExclusionResult(
            excluded=True,
            reason="Test file (not production code)",
            recommendation=""
        )

    # Check for config/metadata files
    if _is_config_file(normalized_path):
        return ExclusionResult(
            excluded=True,
            reason="Configuration/metadata file",
            recommendation=""
        )

    # Check for documentation
    if _is_documentation(normalized_path):
        return ExclusionResult(
            excluded=True,
            reason="Documentation directory",
            recommendation=""
        )

    # File should be included in analysis
    return ExclusionResult(
        excluded=False,
        reason="",
        recommendation=""
    )


def filter_files(files: List[str]) -> Tuple[List[str], List[dict]]:
    """
    Batch filter files for vulnerability analysis.

    Args:
        files: List of file paths to filter

    Returns:
        Tuple of (included_files, exclusion_details)
        - included_files: List of files to analyze
        - exclusion_details: List of dicts with exclusion info for reporting

    Example:
        >>> files = ["app.php", "vendor/lib.php", "test.css"]
        >>> included, excluded = filter_files(files)
        >>> included
        ['app.php']
        >>> excluded
        [{'file': 'vendor/lib.php', 'action': 'sca', 'reason': 'SCA: Check CVE databases for lib.php'},
         {'file': 'test.css', 'action': 'excluded', 'reason': 'Static asset: stylesheets'}]
    """
    included = []
    exclusions = []

    for file_path in files:
        result = should_exclude(file_path)

        if result.excluded:
            exclusions.append({
                'file': file_path,
                'action': 'excluded',
                'reason': result.reason,
            })
        elif result.recommendation:
            # File included but flagged for SCA
            included.append(file_path)
            exclusions.append({
                'file': file_path,
                'action': 'sca',
                'reason': result.recommendation,
            })
        else:
            # Normal inclusion
            included.append(file_path)

    return included, exclusions


def get_exclusion_summary(files: List[str]) -> dict:
    """
    Generate summary statistics for file exclusions.

    Args:
        files: List of file paths

    Returns:
        Dict with exclusion statistics and breakdowns

    Example:
        >>> summary = get_exclusion_summary(["app.php", "test.js", "style.css"])
        >>> summary['total_files']
        3
        >>> summary['excluded_count']
        2
        >>> summary['included_count']
        1
    """
    included, exclusions = filter_files(files)

    # Count exclusion reasons
    reason_counts = {}
    sca_count = 0

    for exc in exclusions:
        if exc['action'] == 'excluded':
            reason = exc['reason']
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        elif exc['action'] == 'sca':
            sca_count += 1

    return {
        'total_files': len(files),
        'included_count': len(included),
        'excluded_count': len([e for e in exclusions if e['action'] == 'excluded']),
        'sca_flagged_count': sca_count,
        'exclusion_breakdown': reason_counts,
        'efficiency_gain': f"{(len(exclusions) / len(files) * 100):.1f}% reduction" if files else "0%",
    }


if __name__ == "__main__":
    # Demo: Test exclusion logic on common file patterns
    test_files = [
        # Should be included
        "app/controllers/AdminController.php",
        "src/models/User.js",
        "lib/custom_auth.py",  # 'lib' can be ambiguous, but at root it's likely custom

        # Vendor (SCA recommended)
        "vendor/symfony/http-kernel/HttpKernel.php",
        "node_modules/express/lib/router.js",
        "bower_components/jquery/dist/jquery.js",

        # Static assets (excluded)
        "public/css/style.css",
        "assets/images/logo.png",
        "fonts/OpenSans.woff2",

        # Build artifacts (excluded)
        "dist/app.min.js",
        "build/bundle.js",
        ".next/static/chunks/main.js",

        # Tests (excluded)
        "tests/test_auth.py",
        "src/components/__tests__/Button.test.jsx",
        "spec/models/user_spec.rb",

        # Config (excluded)
        "package.json",
        "composer.lock",
        "README.md",
    ]

    print("File Exclusion Demo")
    print("=" * 60)

    included, exclusions = filter_files(test_files)

    print(f"\nIncluded for analysis ({len(included)}):")
    for f in included:
        result = should_exclude(f)
        if result.recommendation:
            print(f"  ✓ {f} [{result.recommendation}]")
        else:
            print(f"  ✓ {f}")

    print(f"\nExcluded ({len([e for e in exclusions if e['action'] == 'excluded'])}):")
    for exc in exclusions:
        if exc['action'] == 'excluded':
            print(f"  ✗ {exc['file']} - {exc['reason']}")

    print(f"\nSummary:")
    summary = get_exclusion_summary(test_files)
    print(f"  Total files: {summary['total_files']}")
    print(f"  Included: {summary['included_count']}")
    print(f"  Excluded: {summary['excluded_count']}")
    print(f"  SCA flagged: {summary['sca_flagged_count']}")
    print(f"  Efficiency: {summary['efficiency_gain']}")

    if summary['exclusion_breakdown']:
        print(f"\n  Exclusion breakdown:")
        for reason, count in sorted(summary['exclusion_breakdown'].items(), key=lambda x: x[1], reverse=True):
            print(f"    - {reason}: {count}")
