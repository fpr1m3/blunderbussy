#!/usr/bin/env python3
"""
Unit tests for exclusions.py

Tests all exclusion categories and edge cases to ensure correct
filtering behavior for the code vulnerability analysis pipeline.
"""

try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False

from exclusions import (
    should_exclude,
    filter_files,
    get_exclusion_summary,
    ExclusionResult,
)


class TestStaticAssets:
    """Test exclusion of static assets."""

    def test_css_excluded(self):
        result = should_exclude("public/css/style.css")
        assert result.excluded
        assert "stylesheets" in result.reason.lower()

    def test_scss_excluded(self):
        result = should_exclude("assets/sass/main.scss")
        assert result.excluded
        assert "stylesheets" in result.reason.lower()

    def test_images_excluded(self):
        for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp']:
            result = should_exclude(f"images/logo{ext}")
            assert result.excluded, f"Failed to exclude {ext}"
            assert "images" in result.reason.lower()

    def test_fonts_excluded(self):
        for ext in ['.woff', '.woff2', '.ttf', '.otf', '.eot']:
            result = should_exclude(f"fonts/OpenSans{ext}")
            assert result.excluded, f"Failed to exclude {ext}"
            assert "fonts" in result.reason.lower()

    def test_media_excluded(self):
        result = should_exclude("media/video.mp4")
        assert result.excluded
        assert "media" in result.reason.lower()


class TestVendorDirectories:
    """Test SCA recommendations for vendor code."""

    def test_vendor_php_flagged_for_sca(self):
        result = should_exclude("vendor/symfony/http-kernel/HttpKernel.php")
        assert not result.excluded  # Included but flagged
        assert result.recommendation != ""
        assert "SCA" in result.recommendation
        assert "symfony/http-kernel" in result.recommendation

    def test_node_modules_flagged_for_sca(self):
        result = should_exclude("node_modules/express/lib/router.js")
        assert not result.excluded
        assert "SCA" in result.recommendation
        assert "express/lib" in result.recommendation

    def test_bower_components_flagged_for_sca(self):
        result = should_exclude("bower_components/jquery/dist/jquery.js")
        assert not result.excluded
        assert "SCA" in result.recommendation

    def test_site_packages_flagged_for_sca(self):
        result = should_exclude("site-packages/requests/api.py")
        assert not result.excluded
        assert "SCA" in result.recommendation

    def test_nested_vendor_paths(self):
        result = should_exclude("app/vendor/monolog/monolog/src/Logger.php")
        assert not result.excluded
        assert "SCA" in result.recommendation


class TestBuildArtifacts:
    """Test exclusion of build artifacts."""

    def test_minified_js_excluded(self):
        result = should_exclude("dist/app.min.js")
        assert result.excluded
        assert "build artifact" in result.reason.lower()

    def test_bundled_js_excluded(self):
        result = should_exclude("build/bundle.js")
        assert result.excluded
        assert "build artifact" in result.reason.lower()

    def test_webpack_chunks_excluded(self):
        result = should_exclude("dist/chunks/main.chunk.js")
        assert result.excluded
        assert "build artifact" in result.reason.lower()

    def test_source_maps_excluded(self):
        result = should_exclude("dist/app.js.map")
        assert result.excluded
        assert "build artifact" in result.reason.lower()

    def test_typescript_declarations_excluded(self):
        result = should_exclude("types/index.d.ts")
        assert result.excluded
        assert "build artifact" in result.reason.lower()

    def test_dist_directory_excluded(self):
        result = should_exclude("dist/index.js")
        assert result.excluded

    def test_build_directory_excluded(self):
        result = should_exclude("build/output.js")
        assert result.excluded

    def test_nextjs_build_excluded(self):
        result = should_exclude(".next/static/chunks/main.js")
        assert result.excluded

    def test_pycache_excluded(self):
        result = should_exclude("app/__pycache__/models.cpython-39.pyc")
        assert result.excluded


class TestTestFiles:
    """Test exclusion of test files."""

    def test_python_test_suffix(self):
        result = should_exclude("tests/test_auth.py")
        assert result.excluded
        assert "test" in result.reason.lower()

    def test_python_test_prefix(self):
        result = should_exclude("app/test_models.py")
        assert result.excluded

    def test_javascript_test_extension(self):
        result = should_exclude("src/components/Button.test.js")
        assert result.excluded
        assert "test" in result.reason.lower()

    def test_javascript_spec_extension(self):
        result = should_exclude("src/utils/helpers.spec.ts")
        assert result.excluded

    def test_ruby_spec_files(self):
        result = should_exclude("spec/models/user_spec.rb")
        assert result.excluded

    def test_go_test_files(self):
        result = should_exclude("pkg/auth/auth_test.go")
        assert result.excluded

    def test_java_test_files(self):
        result = should_exclude("src/test/java/com/example/AppTest.java")
        assert result.excluded

    def test_tests_directory(self):
        result = should_exclude("tests/integration/api_test.py")
        assert result.excluded

    def test_jest_tests_directory(self):
        result = should_exclude("src/__tests__/component.test.jsx")
        assert result.excluded

    def test_fixtures_excluded(self):
        result = should_exclude("tests/fixtures/sample_data.json")
        assert result.excluded

    def test_mocks_excluded(self):
        result = should_exclude("tests/mocks/api_responses.js")
        assert result.excluded


class TestConfigFiles:
    """Test exclusion of configuration/metadata files."""

    def test_package_json_excluded(self):
        result = should_exclude("package.json")
        assert result.excluded
        assert "configuration" in result.reason.lower()

    def test_composer_json_excluded(self):
        result = should_exclude("composer.json")
        assert result.excluded

    def test_lockfiles_excluded(self):
        for lockfile in ["package-lock.json", "yarn.lock", "composer.lock", "Gemfile.lock"]:
            result = should_exclude(lockfile)
            assert result.excluded, f"Failed to exclude {lockfile}"

    def test_gitignore_excluded(self):
        result = should_exclude(".gitignore")
        assert result.excluded

    def test_eslintrc_excluded(self):
        result = should_exclude(".eslintrc.json")
        assert result.excluded

    def test_tsconfig_excluded(self):
        result = should_exclude("tsconfig.json")
        assert result.excluded

    def test_webpack_config_excluded(self):
        result = should_exclude("webpack.config.js")
        assert result.excluded

    def test_readme_excluded(self):
        result = should_exclude("README.md")
        assert result.excluded

    def test_license_excluded(self):
        result = should_exclude("LICENSE")
        assert result.excluded


class TestDocumentation:
    """Test exclusion of documentation directories."""

    def test_docs_directory_excluded(self):
        result = should_exclude("docs/api.md")
        assert result.excluded
        assert "documentation" in result.reason.lower()

    def test_examples_directory_excluded(self):
        result = should_exclude("examples/basic_usage.php")
        assert result.excluded


class TestIncludedFiles:
    """Test that legitimate source files are included."""

    def test_php_controller_included(self):
        result = should_exclude("app/controllers/AdminController.php")
        assert not result.excluded
        assert result.recommendation == ""

    def test_javascript_module_included(self):
        result = should_exclude("src/models/User.js")
        assert not result.excluded

    def test_python_module_included(self):
        result = should_exclude("app/auth.py")
        assert not result.excluded

    def test_ruby_controller_included(self):
        result = should_exclude("app/controllers/application_controller.rb")
        assert not result.excluded

    def test_go_source_included(self):
        result = should_exclude("internal/handlers/auth.go")
        assert not result.excluded

    def test_java_source_included(self):
        result = should_exclude("src/main/java/com/example/App.java")
        assert not result.excluded

    def test_typescript_source_included(self):
        result = should_exclude("src/services/api.ts")
        assert not result.excluded

    def test_jsx_component_included(self):
        result = should_exclude("src/components/Dashboard.jsx")
        assert not result.excluded


class TestFilterFiles:
    """Test batch file filtering."""

    def test_filter_files_returns_correct_counts(self):
        files = [
            "app.php",           # Include
            "vendor/lib.php",    # Include + SCA
            "style.css",         # Exclude
            "test_auth.py",      # Exclude (test file)
        ]
        included, exclusions = filter_files(files)

        assert len(included) == 2
        assert "app.php" in included
        assert "vendor/lib.php" in included

        assert len(exclusions) == 3  # 1 SCA + 2 excluded

    def test_filter_files_exclusion_structure(self):
        files = ["app.js", "style.css", "vendor/lib.js"]
        included, exclusions = filter_files(files)

        # Check exclusion structure
        css_exclusion = next((e for e in exclusions if e['file'] == 'style.css'), None)
        assert css_exclusion is not None
        assert css_exclusion['action'] == 'excluded'
        assert 'stylesheets' in css_exclusion['reason'].lower()

        vendor_exclusion = next((e for e in exclusions if e['file'] == 'vendor/lib.js'), None)
        assert vendor_exclusion is not None
        assert vendor_exclusion['action'] == 'sca'
        assert 'SCA' in vendor_exclusion['reason']


class TestExclusionSummary:
    """Test exclusion summary statistics."""

    def test_summary_counts_correct(self):
        files = [
            "app.php",
            "test.css",
            "vendor/lib.js",
            "test_file.py",
        ]
        summary = get_exclusion_summary(files)

        assert summary['total_files'] == 4
        assert summary['included_count'] == 2  # app.php, vendor/lib.js
        assert summary['excluded_count'] == 2  # test.css, test_file.py
        assert summary['sca_flagged_count'] == 1  # vendor/lib.js

    def test_summary_breakdown_accurate(self):
        files = [
            "style1.css",
            "style2.css",
            "test1.py",
            "package.json",
        ]
        summary = get_exclusion_summary(files)

        breakdown = summary['exclusion_breakdown']
        assert 'Static asset: stylesheets' in breakdown
        assert breakdown['Static asset: stylesheets'] == 2

    def test_efficiency_percentage(self):
        files = ["app.php", "test.css", "vendor/lib.js"]
        summary = get_exclusion_summary(files)

        # 2 exclusions out of 3 files = 66.7% reduction
        assert "66.7%" in summary['efficiency_gain']


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_windows_path_separators(self):
        result = should_exclude(r"vendor\symfony\http-kernel\HttpKernel.php")
        assert not result.excluded
        assert "SCA" in result.recommendation

    def test_mixed_path_separators(self):
        result = should_exclude("vendor/symfony\\http-kernel/HttpKernel.php")
        assert not result.excluded
        assert "SCA" in result.recommendation

    def test_case_sensitivity_in_extensions(self):
        result = should_exclude("image.PNG")
        assert result.excluded
        assert "images" in result.reason.lower()

    def test_deeply_nested_paths(self):
        result = should_exclude("a/b/c/d/e/f/g/vendor/lib/package/src/file.php")
        assert not result.excluded
        assert "SCA" in result.recommendation

    def test_lib_at_root_ambiguous(self):
        # 'lib' at root could be custom library, so it gets SCA flag
        result = should_exclude("lib/custom_auth.py")
        assert not result.excluded
        # This will be flagged for SCA due to 'lib' being in VENDOR_DIRS

    def test_empty_path(self):
        result = should_exclude("")
        assert not result.excluded  # Empty path doesn't match any exclusion

    def test_relative_path_with_dots(self):
        result = should_exclude("../../vendor/lib.php")
        assert not result.excluded
        assert "SCA" in result.recommendation


class TestIntegration:
    """Integration tests simulating real-world usage."""

    def test_typical_php_project(self):
        files = [
            "index.php",
            "admin.php",
            "config.php",
            "vendor/monolog/monolog/src/Logger.php",
            "vendor/symfony/http-kernel/HttpKernel.php",
            "public/css/style.css",
            "public/js/app.js",
            "public/images/logo.png",
            "tests/AdminTest.php",
            "composer.json",
            "README.md",
        ]

        included, exclusions = filter_files(files)

        # Should include: index.php, admin.php, config.php, vendor files, public/js/app.js
        assert "index.php" in included
        assert "admin.php" in included
        assert "config.php" in included
        assert "public/js/app.js" in included

        # Vendor files included but flagged
        vendor_files = [e for e in exclusions if e['action'] == 'sca']
        assert len(vendor_files) == 2

        # CSS, images, tests, config excluded
        excluded_files = [e for e in exclusions if e['action'] == 'excluded']
        assert len(excluded_files) >= 4

    def test_typical_nodejs_project(self):
        files = [
            "index.js",
            "src/routes/api.js",
            "src/models/User.js",
            "src/controllers/auth.js",
            "node_modules/express/lib/router.js",
            "node_modules/lodash/lodash.js",
            "dist/bundle.min.js",
            "src/__tests__/api.test.js",
            "package.json",
            "package-lock.json",
            ".eslintrc.json",
        ]

        included, exclusions = filter_files(files)

        # Should include source files
        assert "index.js" in included
        assert "src/routes/api.js" in included
        assert "src/models/User.js" in included

        # node_modules flagged for SCA
        sca_files = [e for e in exclusions if e['action'] == 'sca']
        assert len(sca_files) == 2

        # dist, tests, configs excluded
        excluded_files = [e for e in exclusions if e['action'] == 'excluded']
        assert any('bundle.min.js' in e['file'] for e in excluded_files)
        assert any('test.js' in e['file'] for e in excluded_files)


if __name__ == "__main__":
    if HAS_PYTEST:
        pytest.main([__file__, "-v", "--tb=short"])
    else:
        # Run tests manually
        test_classes = [
            TestStaticAssets,
            TestVendorDirectories,
            TestBuildArtifacts,
            TestTestFiles,
            TestConfigFiles,
            TestDocumentation,
            TestIncludedFiles,
            TestFilterFiles,
            TestExclusionSummary,
            TestEdgeCases,
            TestIntegration,
        ]

        total = 0
        passed = 0
        failed = 0

        for test_class in test_classes:
            print(f'\n{test_class.__name__}:')
            instance = test_class()
            for attr_name in dir(instance):
                if attr_name.startswith('test_'):
                    total += 1
                    try:
                        getattr(instance, attr_name)()
                        print(f'  ✓ {attr_name}')
                        passed += 1
                    except Exception as e:
                        print(f'  ✗ {attr_name}: {str(e)[:100]}')
                        failed += 1

        print(f'\n{"="*60}')
        print(f'Total: {total}, Passed: {passed}, Failed: {failed}')
        if failed > 0:
            exit(1)
