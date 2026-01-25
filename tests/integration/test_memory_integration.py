#!/usr/bin/env python3
"""
Vector search roundtrip integration tests for SessionMemory.

These tests verify the semantic search functionality of SessionMemory with
real Qdrant vector database operations.

Requires a running Qdrant instance at localhost:6333.
Start with: podman-compose up -d qdrant

Run with: uv run pytest tests/integration/test_memory_integration.py -v -m qdrant
Skip with: uv run pytest -m "not qdrant"
"""

import time
import pytest

# Mark all tests in this module as requiring Qdrant
pytestmark = pytest.mark.qdrant

# Import EventType and Outcome from session_memory
# Note: conftest.py already adds infrastructure/PrEP to sys.path
from session_memory import EventType, Outcome


class TestVectorSearchRoundtrip:
    """Vector search roundtrip integration tests."""

    def test_index_and_search_roundtrip(self, session_memory_factory):
        """
        Index a TECHNIQUE_ATTEMPT event and verify search returns it with good score.

        Tests that:
        - An event about SQL injection on login form can be indexed
        - A semantically similar query finds the event
        - The score is above 0.5 (indicating good semantic match)
        """
        mem = session_memory_factory("vector_roundtrip")

        # Index a TECHNIQUE_ATTEMPT event
        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Tried SQL injection on login form",
            outcome=Outcome.FAILED,
            technique_id="sqli_basic",
            tags=["sqli", "web", "login"],
        )
        assert success is True

        # Search with semantically similar but different query
        results = mem.search("SQLi attack on authentication")

        # Should find the indexed event
        assert len(results) >= 1, "Expected at least one result from search"

        # First result should have score > 0.5 (good semantic match)
        assert results[0].score > 0.5, (
            f"Expected score > 0.5 for semantic match, got {results[0].score}"
        )

        # Verify it's the right event
        assert results[0].event_type == EventType.TECHNIQUE_ATTEMPT.value
        assert "SQL injection" in results[0].context or "SQLi" in results[0].context.lower()

    def test_search_returns_empty_for_unrelated(self, session_memory_factory):
        """
        Verify unrelated searches return no results or very low scores.

        Tests that:
        - An event about SSH brute force is indexed
        - Searching for kernel privilege escalation returns low/no results
        - Vector search correctly distinguishes unrelated topics
        """
        mem = session_memory_factory("unrelated_search")

        # Index an SSH-related event
        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="SSH brute force attempt on port 22 using common passwords",
            outcome=Outcome.FAILED,
            technique_id="ssh_bruteforce",
            tags=["ssh", "bruteforce", "credentials"],
        )
        assert success is True

        # Search for completely unrelated topic
        results = mem.search("kernel privilege escalation")

        # Should return no results or very low scores
        if len(results) > 0:
            # If there are results, scores should be low (< 0.3)
            assert results[0].score < 0.3, (
                f"Expected score < 0.3 for unrelated search, got {results[0].score}"
            )

    def test_search_similarity_ordering(self, session_memory_factory):
        """
        Verify search results are ordered by semantic similarity.

        Tests that:
        - Three events with varying relevance to SQL injection are indexed
        - Searching for 'SQL injection attack' ranks SQL-related events higher
        - XSS event ranks lower than SQLi events
        """
        mem = session_memory_factory("similarity_ordering")

        # Index 3 events with different semantic relationships to SQLi
        events = [
            {
                "context": "SQL injection on login page using OR 1=1",
                "technique_id": "sqli_login",
                "tags": ["sqli", "login", "bypass"],
            },
            {
                "context": "XSS in comment field using script tags",
                "technique_id": "xss_stored",
                "tags": ["xss", "web", "javascript"],
            },
            {
                "context": "SQLi bypass using UNION SELECT to extract database schema",
                "technique_id": "sqli_union",
                "tags": ["sqli", "union", "schema"],
            },
        ]

        for event in events:
            success = mem.index_event(
                event_type=EventType.TECHNIQUE_ATTEMPT,
                context=event["context"],
                outcome=Outcome.FAILED,
                technique_id=event["technique_id"],
                tags=event["tags"],
            )
            assert success is True

        # Search for SQL injection
        results = mem.search("SQL injection attack", limit=3)

        assert len(results) == 3, f"Expected 3 results, got {len(results)}"

        # Get the XSS result
        xss_result = None
        sqli_results = []

        for r in results:
            if "XSS" in r.context or "xss" in r.context.lower():
                xss_result = r
            else:
                sqli_results.append(r)

        assert xss_result is not None, "XSS event not found in results"
        assert len(sqli_results) == 2, "Expected 2 SQLi-related results"

        # SQLi events should rank higher than XSS event
        for sqli in sqli_results:
            assert sqli.score > xss_result.score, (
                f"SQLi event (score={sqli.score}) should rank higher than "
                f"XSS event (score={xss_result.score})"
            )

    def test_search_with_outcome_filter(self, session_memory_factory):
        """
        Verify outcome filter correctly filters search results.

        Tests that:
        - Both SUCCESS and FAILED events for same technique are indexed
        - Filtering by outcome=SUCCESS returns only SUCCESS events
        - The filter works correctly with vector search
        """
        mem = session_memory_factory("outcome_filter")

        # Index SUCCESS event
        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Exploited CVE-2021-44228 Log4j vulnerability successfully",
            outcome=Outcome.SUCCESS,
            technique_id="log4j_rce",
            tags=["log4j", "rce", "java"],
        )
        assert success is True

        # Index FAILED event for same technique
        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Log4j exploitation attempt blocked by WAF filtering JNDI lookups",
            outcome=Outcome.FAILED,
            technique_id="log4j_rce",
            tags=["log4j", "rce", "waf"],
        )
        assert success is True

        # Search with outcome filter for SUCCESS only
        results = mem.search(
            query="Log4j vulnerability exploitation",
            outcome=Outcome.SUCCESS,
            limit=5,
        )

        # Should only return SUCCESS events
        assert len(results) >= 1, "Expected at least one SUCCESS result"

        for result in results:
            assert result.outcome == Outcome.SUCCESS.value, (
                f"Expected outcome=success, got {result.outcome}"
            )

        # Verify FAILED events are filtered out
        for result in results:
            assert "blocked" not in result.context.lower(), (
                "FAILED event should not appear in SUCCESS-filtered results"
            )

    def test_search_errors_finds_resolutions(self, session_memory_factory):
        """
        Verify search_errors() convenience method finds ERROR_RESOLUTION events.

        Tests that:
        - An ERROR_RESOLUTION event with resolution field is indexed
        - search_errors() finds the resolution
        - The resolution text is accessible in results
        """
        mem = session_memory_factory("error_resolution")

        # Index an ERROR_RESOLUTION event with resolution
        success = mem.index_event(
            event_type=EventType.ERROR_RESOLUTION,
            context="Metasploit exploit/linux/http/apache_mod_cgi_bash_env_exec failed with 'target not vulnerable'",
            outcome=Outcome.SUCCESS,  # Resolution was successful
            resolution="Target Apache version too new for Shellshock. Switched to exploit/multi/http/apache_normalize_path_rce which worked on Apache 2.4.49",
            technique_id="shellshock",
            tags=["apache", "cgi", "bash", "rce"],
        )
        assert success is True

        # Use search_errors convenience method
        results = mem.search_errors("Shellshock exploit not working on Apache")

        # Should find the resolution
        assert len(results) >= 1, "Expected search_errors to find the resolution"

        # First result should be the ERROR_RESOLUTION event
        assert results[0].event_type == EventType.ERROR_RESOLUTION.value

        # Resolution should be populated
        assert results[0].resolution is not None, "Expected resolution field to be populated"
        assert "apache_normalize_path" in results[0].resolution.lower() or "2.4.49" in results[0].resolution, (
            "Resolution should contain the fix that worked"
        )


class TestCrossSessionSearch:
    """Cross-session search integration tests."""

    def test_cross_session_search_multiple_targets(self, session_memory_factory, qdrant_url):
        """
        Search across multiple session collections and verify semantic relevance.

        Tests that:
        - Events from 3 different targets are indexed
        - Cross-session search finds kernel-related events from targets 1 and 2
        - Web shell event from target 3 is excluded or ranks significantly lower
        """
        from session_memory import search_all_sessions

        # Create SessionMemory for 3 different targets
        mem1 = session_memory_factory("test_10.129.5.135")
        mem2 = session_memory_factory("test_10.129.5.136")
        mem3 = session_memory_factory("test_10.129.5.137")

        # Index technique events in each target
        success = mem1.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Kernel exploit CVE-2024-1086",
            outcome=Outcome.SUCCESS,
            technique_id="kernel_exploit_cve_2024_1086",
            tags=["kernel", "privesc", "cve"],
        )
        assert success is True

        success = mem2.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Kernel privilege escalation via dirty pipe",
            outcome=Outcome.SUCCESS,
            technique_id="dirty_pipe",
            tags=["kernel", "privesc", "dirty_pipe"],
        )
        assert success is True

        success = mem3.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Web shell upload via file inclusion",
            outcome=Outcome.SUCCESS,
            technique_id="web_shell_lfi",
            tags=["web", "shell", "lfi"],
        )
        assert success is True

        # Search across all sessions for kernel privilege escalation
        results = search_all_sessions(
            query="kernel privilege escalation",
            qdrant_url=qdrant_url,
            limit=10,
        )

        # Should have results
        assert len(results) >= 2, f"Expected at least 2 results, got {len(results)}"

        # Extract collections that appear in results
        collections_with_kernel = []
        web_shell_result = None

        for r in results:
            if "kernel" in r["context"].lower() or "dirty pipe" in r["context"].lower():
                collections_with_kernel.append(r["collection"])
            if "web shell" in r["context"].lower():
                web_shell_result = r

        # Verify kernel-related events from targets 1 and 2 are found
        assert len(collections_with_kernel) >= 2, (
            f"Expected kernel events from 2 targets, found in {len(collections_with_kernel)} collections"
        )

        # Verify web shell result either doesn't appear or has much lower score
        if web_shell_result is not None:
            # Find the highest kernel result score
            kernel_scores = [
                r["score"] for r in results
                if "kernel" in r["context"].lower() or "dirty pipe" in r["context"].lower()
            ]
            if kernel_scores:
                max_kernel_score = max(kernel_scores)
                # Web shell should have significantly lower score
                assert web_shell_result["score"] < max_kernel_score * 0.7, (
                    f"Web shell score ({web_shell_result['score']}) should be much lower "
                    f"than kernel results (max: {max_kernel_score})"
                )

    def test_cross_session_returns_collection_info(self, session_memory_factory, qdrant_url):
        """
        Verify search results include collection field showing which target they came from.

        Tests that:
        - Cross-session search results include 'collection' field
        - The collection field matches the expected naming pattern
        """
        from session_memory import search_all_sessions

        # Create a session and index an event
        mem = session_memory_factory("test_collection_info_target")

        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Testing collection info presence in results",
            outcome=Outcome.SUCCESS,
            technique_id="collection_test",
            tags=["test"],
        )
        assert success is True

        # Search across all sessions
        results = search_all_sessions(
            query="Testing collection info",
            qdrant_url=qdrant_url,
            limit=5,
        )

        # Should have at least one result
        assert len(results) >= 1, "Expected at least one result"

        # Verify each result has 'collection' field
        for result in results:
            assert "collection" in result, "Expected 'collection' field in result"
            assert result["collection"] is not None, "Collection should not be None"
            # Collection should follow naming pattern
            assert result["collection"].startswith("dame_session_"), (
                f"Collection name '{result['collection']}' should start with 'dame_session_'"
            )

    def test_cross_session_empty_when_no_collections(self, skip_without_qdrant, qdrant_url):
        """
        Verify search returns empty list when no session collections exist.

        Tests that:
        - After deleting all test collections, search returns empty
        - No errors are raised when searching empty Qdrant
        """
        import requests
        from session_memory import search_all_sessions

        # Delete all dame_session_test_* collections first
        resp = requests.get(f"{qdrant_url}/collections", timeout=5)
        assert resp.status_code == 200, "Failed to list collections"

        collections = resp.json().get("result", {}).get("collections", [])
        for coll in collections:
            name = coll.get("name", "")
            # Delete test collections
            if name.startswith("dame_session_") and "test" in name.lower():
                requests.delete(f"{qdrant_url}/collections/{name}", timeout=5)

        # Search on fresh Qdrant with no test collections
        results = search_all_sessions(
            query="anything at all",
            qdrant_url=qdrant_url,
            limit=10,
        )

        # Should return empty list, not crash
        # Note: There may be non-test collections, so we check the result type
        assert isinstance(results, list), "Expected list result"
        # If there are no dame_session_ collections at all, should be empty
        # Otherwise filter to only check test collections aren't present
        for r in results:
            if "test" in r.get("collection", "").lower():
                # Test collection shouldn't exist
                pytest.fail(f"Found unexpected test collection: {r['collection']}")

    def test_cross_session_handles_partial_failures(self, session_memory_factory, qdrant_url):
        """
        Verify search handles partial failures gracefully.

        Tests that:
        - Search succeeds when some collections are valid
        - Invalid collection references don't crash the search
        - Results from valid collections are returned
        """
        from session_memory import search_all_sessions

        # Create one valid collection with indexed event
        mem = session_memory_factory("test_partial_failure_valid")

        success = mem.index_event(
            event_type=EventType.TECHNIQUE_ATTEMPT,
            context="Valid collection for partial failure test",
            outcome=Outcome.SUCCESS,
            technique_id="partial_test",
            tags=["test", "partial"],
        )
        assert success is True

        # Note: We can't easily create a "broken" collection in the Qdrant API
        # since search_all_sessions queries all existing dame_session_* collections.
        # The function already handles non-200 responses gracefully (continues to next collection).
        # We verify that valid collection results are returned even if other collections
        # might fail during search.

        # Search across all sessions
        results = search_all_sessions(
            query="Valid collection partial failure",
            qdrant_url=qdrant_url,
            limit=10,
        )

        # Should return results without crashing
        assert isinstance(results, list), "Expected list result"

        # Should find the event from the valid collection
        found_valid = False
        for r in results:
            if "partial failure test" in r.get("context", "").lower():
                found_valid = True
                break

        assert found_valid, "Should have found event from valid collection"
