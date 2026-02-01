#!/usr/bin/env python3
"""
Example usage of exclusions.py in the recon agent workflow.

This demonstrates how the recon agent should use file exclusions
to reduce analysis scope and focus on custom application code.
"""

from exclusions import should_exclude, filter_files, get_exclusion_summary
from pathlib import Path


def example_recon_workflow():
    """
    Simulates a recon agent discovering files in a repository
    and filtering them for vulnerability analysis.
    """
    print("=" * 70)
    print("RECON AGENT: File Discovery and Filtering")
    print("=" * 70)

    # Simulated file discovery (would come from glob/find in real scenario)
    discovered_files = [
        # Application code (should be analyzed)
        "app/controllers/AdminController.php",
        "app/controllers/UserController.php",
        "app/models/User.php",
        "app/lib/Database.php",
        "public/api/upload.php",
        "public/api/download.php",
        "public/index.php",
        "config/database.php",
        "includes/auth.php",

        # Vendor code (flag for SCA)
        "vendor/phpmailer/phpmailer/src/PHPMailer.php",
        "vendor/symfony/http-kernel/HttpKernel.php",
        "vendor/monolog/monolog/src/Logger.php",

        # Static assets (exclude)
        "public/css/bootstrap.min.css",
        "public/css/style.css",
        "public/js/jquery.min.js",
        "public/js/app.js",  # This might be custom JS
        "public/images/logo.png",
        "public/fonts/OpenSans.woff2",

        # Tests (exclude)
        "tests/AdminTest.php",
        "tests/UserTest.php",
        "tests/fixtures/sample_data.json",

        # Build artifacts (exclude)
        "dist/bundle.min.js",
        "build/app.js",

        # Config files (exclude)
        "composer.json",
        "composer.lock",
        "package.json",
        ".gitignore",
        "README.md",

        # Documentation (exclude)
        "docs/installation.md",
        "docs/api.md",
    ]

    print(f"\n📁 Discovered {len(discovered_files)} files in repository\n")

    # Filter files using exclusion logic
    included, exclusions = filter_files(discovered_files)

    # Separate SCA and excluded
    sca_files = [e for e in exclusions if e['action'] == 'sca']
    excluded_files = [e for e in exclusions if e['action'] == 'excluded']

    # Display results
    print(f"✅ FILES TO ANALYZE ({len(included)}):")
    print("-" * 70)
    for f in included:
        result = should_exclude(f)
        if result.recommendation:
            print(f"  {f} [SCA: {result.recommendation}]")
        else:
            print(f"  {f}")

    print(f"\n🔍 SCA RECOMMENDED ({len(sca_files)}):")
    print("-" * 70)
    for exc in sca_files:
        print(f"  {exc['file']}")
        print(f"    → {exc['reason']}")

    print(f"\n⏭️  EXCLUDED ({len(excluded_files)}):")
    print("-" * 70)
    # Group by reason
    by_reason = {}
    for exc in excluded_files:
        reason = exc['reason']
        by_reason.setdefault(reason, []).append(exc['file'])

    for reason, files in sorted(by_reason.items()):
        print(f"  {reason} ({len(files)} files):")
        for f in files[:3]:  # Show first 3
            print(f"    - {f}")
        if len(files) > 3:
            print(f"    ... and {len(files) - 3} more")

    # Generate summary for triage output
    summary = get_exclusion_summary(discovered_files)
    print(f"\n📊 EFFICIENCY SUMMARY:")
    print("-" * 70)
    print(f"  Total files discovered: {summary['total_files']}")
    print(f"  Files to analyze: {summary['included_count']}")
    print(f"  Files excluded: {summary['excluded_count']}")
    print(f"  SCA flags: {summary['sca_flagged_count']}")
    print(f"  Efficiency gain: {summary['efficiency_gain']}")

    # Show what would go into the recon output
    print(f"\n📝 RECON OUTPUT STRUCTURE:")
    print("-" * 70)
    recon_output = {
        "manifest": {
            "total_files": len(discovered_files),
            "analysis_targets": included,
            "languages": {"php": 9, "js": 1}  # Simplified
        },
        "excluded": [
            {
                "file": exc['file'],
                "reason": exc['reason']
            }
            for exc in excluded_files
        ],
        "sca_recommendations": [
            {
                "file": exc['file'],
                "action": exc['reason']
            }
            for exc in sca_files
        ],
        "efficiency": {
            "reduction_percentage": summary['efficiency_gain'],
            "files_analyzed": summary['included_count'],
            "files_skipped": summary['excluded_count']
        }
    }

    import json
    print(json.dumps(recon_output, indent=2))


def example_individual_checks():
    """
    Examples of checking individual files.
    """
    print("\n" + "=" * 70)
    print("INDIVIDUAL FILE CHECKS")
    print("=" * 70 + "\n")

    test_cases = [
        ("app/controllers/AdminController.php", "Custom application code"),
        ("vendor/monolog/monolog/src/Logger.php", "Third-party library"),
        ("public/css/style.css", "Static stylesheet"),
        ("tests/AdminTest.php", "Test file"),
        ("node_modules/express/lib/router.js", "npm dependency"),
        ("dist/app.min.js", "Build artifact"),
    ]

    for file_path, description in test_cases:
        result = should_exclude(file_path)

        status = "❌ EXCLUDE" if result.excluded else \
                "🔍 SCA" if result.recommendation else \
                "✅ ANALYZE"

        print(f"{status}: {file_path}")
        print(f"  Description: {description}")
        if result.excluded:
            print(f"  Reason: {result.reason}")
        if result.recommendation:
            print(f"  Recommendation: {result.recommendation}")
        print()


if __name__ == "__main__":
    example_recon_workflow()
    example_individual_checks()
