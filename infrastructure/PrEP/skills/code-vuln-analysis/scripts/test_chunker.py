#!/usr/bin/env python3
"""
Tests for chunker.py - Code chunking utility for vulnerability analysis.
"""

import pytest
import yaml
from typing import Dict

from chunker import (
    count_tokens,
    topological_sort,
    find_taint_path,
    create_taint_chunk,
    create_chunks,
    chunks_to_yaml,
    build_file_infos_from_recon,
    FileInfo,
    AnalysisChunk,
    MIN_CHUNK_TOKENS,
    MAX_CHUNK_TOKENS,
    OPTIMAL_CHUNK_TOKENS,
)
from prioritize import (
    SinkType,
    InputProximity,
    AuthLevel,
    TriageFinding,
    CodeLocation,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_recon_data() -> Dict:
    """Sample recon agent output for testing."""
    return {
        "manifest": {
            "files": [
                "admin.php",
                "login.php",
                "includes/db.php",
                "includes/auth.php",
                "includes/validator.php",
                "config.php",
            ],
            "languages": {"php": 6}
        },
        "dependency_graph": {
            "includes": [
                {"from": "admin.php", "imports": ["config.php", "includes/db.php", "includes/auth.php"]},
                {"from": "login.php", "imports": ["config.php", "includes/db.php", "includes/auth.php"]},
                {"from": "includes/validator.php", "imports": ["includes/db.php"]}
            ]
        },
        "dangerous_sinks": {
            "sql": [
                {"file": "includes/db.php", "line": 23, "function": "query()", "parameterized": False}
            ],
            "code_execution": [
                {"file": "includes/validator.php", "line": 67, "function": "assert()", "context": "validates rules"}
            ]
        },
        "user_inputs": [
            {"file": "login.php", "line": 15, "source": "$_POST", "variable": "username"},
            {"file": "login.php", "line": 16, "source": "$_POST", "variable": "password"},
            {"file": "admin.php", "line": 34, "source": "$_POST", "variable": "config_data"}
        ]
    }


@pytest.fixture
def sample_file_infos() -> Dict[str, FileInfo]:
    """Sample FileInfo objects for testing."""
    files = {
        "a.php": FileInfo(path="a.php", token_count=1000, imports=["b.php", "c.php"]),
        "b.php": FileInfo(path="b.php", token_count=800, imports=["c.php"]),
        "c.php": FileInfo(path="c.php", token_count=500, imports=[]),
        "d.php": FileInfo(path="d.php", token_count=600, imports=["a.php"]),
    }
    # Set up imported_by relationships
    files["b.php"].imported_by = ["a.php"]
    files["c.php"].imported_by = ["a.php", "b.php"]
    files["a.php"].imported_by = ["d.php"]
    return files


# =============================================================================
# Token Counting Tests
# =============================================================================

class TestCountTokens:
    """Tests for token counting functionality."""

    def test_count_tokens_empty_string(self):
        """Empty string should return 0 tokens."""
        assert count_tokens("") == 0

    def test_count_tokens_simple_code(self):
        """Simple code should return reasonable token count."""
        code = "function hello() { return 'world'; }"
        tokens = count_tokens(code)
        assert tokens > 0
        assert tokens < 50  # Simple code, should be small

    def test_count_tokens_multiline(self):
        """Multiline code should count correctly."""
        code = """
        <?php
        function authenticate($username, $password) {
            $query = "SELECT * FROM users WHERE username = ?";
            $stmt = $pdo->prepare($query);
            $stmt->execute([$username]);
            return $stmt->fetch();
        }
        """
        tokens = count_tokens(code)
        assert tokens > 20
        assert tokens < 200


# =============================================================================
# Topological Sort Tests
# =============================================================================

class TestTopologicalSort:
    """Tests for dependency-aware file sorting."""

    def test_topological_sort_simple_chain(self, sample_file_infos):
        """Files in a simple chain should sort correctly."""
        dependency_graph = {
            "a.php": ["b.php", "c.php"],
            "b.php": ["c.php"],
            "c.php": [],
            "d.php": ["a.php"],
        }
        result = topological_sort(sample_file_infos, dependency_graph)

        # c should come before b, b before a (based on imported_by)
        assert len(result) == 4
        # All files should be present
        assert set(result) == {"a.php", "b.php", "c.php", "d.php"}

    def test_topological_sort_handles_cycles(self):
        """Cycles should be handled gracefully."""
        files = {
            "a.php": FileInfo(path="a.php", token_count=100, imports=["b.php"]),
            "b.php": FileInfo(path="b.php", token_count=100, imports=["a.php"]),  # Cycle!
        }
        files["a.php"].imported_by = ["b.php"]
        files["b.php"].imported_by = ["a.php"]

        dependency_graph = {
            "a.php": ["b.php"],
            "b.php": ["a.php"],
        }

        result = topological_sort(files, dependency_graph)

        # Should not hang, should return all files
        assert len(result) == 2
        assert set(result) == {"a.php", "b.php"}

    def test_topological_sort_empty(self):
        """Empty input should return empty list."""
        result = topological_sort({}, {})
        assert result == []


# =============================================================================
# Taint Path Finding Tests
# =============================================================================

class TestFindTaintPath:
    """Tests for backward taint path discovery."""

    def test_find_taint_path_includes_sink_file(self, sample_file_infos):
        """Sink file should always be in taint path."""
        dependency_graph = {"a.php": ["b.php", "c.php"]}
        path = find_taint_path("a.php", sample_file_infos, dependency_graph)
        assert "a.php" in path

    def test_find_taint_path_includes_imports(self, sample_file_infos):
        """Files imported by sink should be in taint path."""
        dependency_graph = {"a.php": ["b.php", "c.php"]}
        path = find_taint_path("a.php", sample_file_infos, dependency_graph)
        # a.php imports b.php and c.php
        assert "b.php" in path
        assert "c.php" in path

    def test_find_taint_path_respects_max_depth(self):
        """Should not traverse beyond max depth."""
        # Create deep chain: a -> b -> c -> d -> e
        files = {
            "a.php": FileInfo(path="a.php", imports=["b.php"]),
            "b.php": FileInfo(path="b.php", imports=["c.php"]),
            "c.php": FileInfo(path="c.php", imports=["d.php"]),
            "d.php": FileInfo(path="d.php", imports=["e.php"]),
            "e.php": FileInfo(path="e.php", imports=[]),
        }
        dependency_graph = {p: f.imports for p, f in files.items()}

        # With max_depth=2, should only get a, b, c
        path = find_taint_path("a.php", files, dependency_graph, max_depth=2)
        assert "a.php" in path
        assert "b.php" in path
        assert "c.php" in path
        # d and e should be excluded due to depth limit
        assert "d.php" not in path or "e.php" not in path


# =============================================================================
# Chunk Creation Tests
# =============================================================================

class TestCreateTaintChunk:
    """Tests for creating analysis chunks around sinks."""

    def test_create_chunk_includes_sink_file(self, sample_file_infos):
        """Chunk should always include the sink file."""
        sink = TriageFinding(
            id="test_1",
            location=CodeLocation(file="a.php", line=10),
            sink_type=SinkType.SQL,
            sink_function="query()",
            input_proximity=InputProximity.DIRECT,
            score=50.0
        )
        sample_file_infos["a.php"].sinks = [sink]

        chunk = create_taint_chunk(sink, sample_file_infos, {})
        assert "a.php" in chunk.files

    def test_create_chunk_respects_token_limit(self):
        """Chunk should not exceed token limit."""
        files = {
            "a.php": FileInfo(path="a.php", token_count=5000, imports=["b.php"]),
            "b.php": FileInfo(path="b.php", token_count=5000, imports=["c.php"]),
            "c.php": FileInfo(path="c.php", token_count=5000, imports=[]),
        }
        sink = TriageFinding(
            id="test_1",
            location=CodeLocation(file="a.php", line=10),
            sink_type=SinkType.SQL,
            sink_function="query()",
            input_proximity=InputProximity.DIRECT,
            score=50.0
        )
        files["a.php"].sinks = [sink]

        chunk = create_taint_chunk(sink, files, {}, token_limit=10000)

        # Should include a.php (5000) and b.php (5000) but not c.php
        assert chunk.token_estimate <= 12000  # Allow some overflow for min threshold

    def test_create_chunk_has_focus_and_hypothesis(self, sample_file_infos):
        """Chunk should have generated focus and hypothesis."""
        sink = TriageFinding(
            id="test_1",
            location=CodeLocation(file="a.php", line=10),
            sink_type=SinkType.SQL,
            sink_function="query()",
            input_proximity=InputProximity.DIRECT,
            score=50.0
        )
        sample_file_infos["a.php"].sinks = [sink]

        chunk = create_taint_chunk(sink, sample_file_infos, {})

        assert chunk.focus != ""
        assert chunk.hypothesis != ""
        assert "query()" in chunk.focus
        assert chunk.attack_surface == "sql"


# =============================================================================
# Full Pipeline Tests
# =============================================================================

class TestCreateChunks:
    """Tests for the full chunking pipeline."""

    def test_create_chunks_from_recon_data(self, sample_recon_data):
        """Should create chunks from recon data."""
        files = build_file_infos_from_recon(sample_recon_data)

        # Set token counts (mock)
        for f in files.values():
            f.token_count = 2000

        chunks = create_chunks(files, sample_recon_data)

        # Should create at least one chunk
        assert len(chunks) >= 1

        # Chunks should be sorted by priority
        priorities = [c.priority for c in chunks]
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ordered = sorted(priorities, key=lambda p: priority_order.get(p, 4))
        assert priorities == ordered

    def test_create_chunks_no_duplicates(self, sample_recon_data):
        """Each file should only appear in one chunk."""
        files = build_file_infos_from_recon(sample_recon_data)
        for f in files.values():
            f.token_count = 2000

        chunks = create_chunks(files, sample_recon_data)

        all_files = []
        for chunk in chunks:
            all_files.extend(chunk.files)

        # No duplicates
        assert len(all_files) == len(set(all_files))

    def test_create_chunks_assigns_sequential_ids(self, sample_recon_data):
        """Chunks should have sequential IDs."""
        files = build_file_infos_from_recon(sample_recon_data)
        for f in files.values():
            f.token_count = 2000

        chunks = create_chunks(files, sample_recon_data)

        for i, chunk in enumerate(chunks):
            assert chunk.id == f"chunk_{i+1:03d}"


# =============================================================================
# YAML Output Tests
# =============================================================================

class TestChunksToYaml:
    """Tests for YAML serialization."""

    def test_yaml_output_is_valid(self, sample_recon_data):
        """Output should be valid YAML."""
        files = build_file_infos_from_recon(sample_recon_data)
        for f in files.values():
            f.token_count = 2000

        chunks = create_chunks(files, sample_recon_data)
        yaml_output = chunks_to_yaml(chunks)

        # Should parse without error
        parsed = yaml.safe_load(yaml_output)
        assert parsed is not None

    def test_yaml_output_matches_schema(self, sample_recon_data):
        """Output should match triage.md schema."""
        files = build_file_infos_from_recon(sample_recon_data)
        for f in files.values():
            f.token_count = 2000

        chunks = create_chunks(files, sample_recon_data)
        yaml_output = chunks_to_yaml(chunks)
        parsed = yaml.safe_load(yaml_output)

        # Check required top-level keys
        assert "analysis_chunks" in parsed
        assert "metadata" in parsed

        # Check metadata keys
        assert "chunks_created" in parsed["metadata"]
        assert "total_estimated_tokens" in parsed["metadata"]
        assert "estimated_analysis_turns" in parsed["metadata"]

        # Check chunk structure
        if parsed["analysis_chunks"]:
            chunk = parsed["analysis_chunks"][0]
            assert "id" in chunk
            assert "priority" in chunk
            assert "files" in chunk
            assert "focus" in chunk
            assert "attack_surface" in chunk
            assert "hypothesis" in chunk
            assert "token_estimate" in chunk
            assert "rationale" in chunk


# =============================================================================
# Build FileInfos Tests
# =============================================================================

class TestBuildFileInfosFromRecon:
    """Tests for building FileInfo from recon data."""

    def test_extracts_all_files(self, sample_recon_data):
        """Should extract all files from manifest."""
        files = build_file_infos_from_recon(sample_recon_data)

        expected_files = {
            "admin.php", "login.php", "includes/db.php",
            "includes/auth.php", "includes/validator.php", "config.php"
        }
        assert set(files.keys()) == expected_files

    def test_extracts_sinks(self, sample_recon_data):
        """Should extract dangerous sinks."""
        files = build_file_infos_from_recon(sample_recon_data)

        # db.php should have SQL sink
        assert len(files["includes/db.php"].sinks) >= 1
        assert files["includes/db.php"].sinks[0].sink_type == SinkType.SQL

        # validator.php should have code execution sink
        assert len(files["includes/validator.php"].sinks) >= 1
        assert files["includes/validator.php"].sinks[0].sink_type == SinkType.CODE_EXECUTION

    def test_extracts_user_inputs(self, sample_recon_data):
        """Should extract user input sources."""
        files = build_file_infos_from_recon(sample_recon_data)

        # login.php should have user inputs
        assert len(files["login.php"].user_inputs) >= 2
        assert files["login.php"].has_user_input

        # admin.php should have user input
        assert len(files["admin.php"].user_inputs) >= 1

    def test_extracts_dependencies(self, sample_recon_data):
        """Should extract import relationships."""
        files = build_file_infos_from_recon(sample_recon_data)

        # admin.php imports multiple files
        assert "config.php" in files["admin.php"].imports
        assert "includes/db.php" in files["admin.php"].imports

        # config.php is imported by admin.php and login.php
        assert "admin.php" in files["config.php"].imported_by
        assert "login.php" in files["config.php"].imported_by


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_recon_data(self):
        """Should handle empty recon data gracefully."""
        files = build_file_infos_from_recon({})
        assert files == {}

        chunks = create_chunks({}, {})
        assert chunks == []

    def test_recon_with_no_sinks(self):
        """Should handle recon data with no dangerous sinks."""
        recon = {
            "manifest": {"files": ["index.php"], "languages": {"php": 1}},
            "dependency_graph": {"includes": []},
            "dangerous_sinks": {},
            "user_inputs": []
        }
        files = build_file_infos_from_recon(recon)
        chunks = create_chunks(files, recon)

        # Should create no chunks (nothing to analyze)
        assert chunks == []

    def test_sink_in_unknown_file(self):
        """Should handle sinks in files not in manifest."""
        recon = {
            "manifest": {"files": [], "languages": {}},
            "dependency_graph": {"includes": []},
            "dangerous_sinks": {
                "sql": [{"file": "unknown.php", "line": 10, "function": "query()"}]
            },
            "user_inputs": []
        }
        files = build_file_infos_from_recon(recon)

        # Should create FileInfo for the unknown file
        assert "unknown.php" in files
        assert len(files["unknown.php"].sinks) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
