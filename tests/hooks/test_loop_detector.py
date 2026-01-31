"""Tests for loop_detector — AfterTool hook for thought loop detection."""

import sys
from pathlib import Path

import pytest

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "infrastructure" / "PrEP" / "hooks"))

from loop_detector import (
    shingle,
    minhash,
    jaccard_similarity,
    detect_loop,
    load_state,
    save_state,
    build_loop_warning,
    LEVEL_1_TURNS,
    LEVEL_2_TURNS,
    LEVEL_3_TURNS,
    SIMILARITY_THRESHOLD,
)


# =============================================================================
# MinHash — shingling
# =============================================================================


class TestShingle:
    def test_basic_shingling(self):
        shingles = shingle("the quick brown fox")
        assert len(shingles) > 0
        # With n=3, "the quick brown fox" (4 tokens) produces 2 shingles
        assert len(shingles) == 2

    def test_empty_string(self):
        assert shingle("") == set()

    def test_short_string(self):
        """Text shorter than shingle size returns the text itself."""
        result = shingle("hi")
        assert len(result) == 1


# =============================================================================
# MinHash — signature computation
# =============================================================================


class TestMinHash:
    def test_signature_length(self):
        sh = shingle("the quick brown fox jumps over the lazy dog")
        sig = minhash(sh, num_hashes=64)
        assert len(sig) == 64

    def test_empty_shingles(self):
        sig = minhash(set(), num_hashes=64)
        assert sig == [0] * 64

    def test_deterministic(self):
        sh = shingle("reproducible test input")
        sig1 = minhash(sh, num_hashes=32)
        sig2 = minhash(sh, num_hashes=32)
        assert sig1 == sig2


# =============================================================================
# Jaccard similarity estimation
# =============================================================================


class TestJaccardSimilarity:
    def test_identical_signatures(self):
        sig = minhash(shingle("identical text"), num_hashes=64)
        assert jaccard_similarity(sig, sig) == 1.0

    def test_different_signatures(self):
        sig_a = minhash(shingle("nmap scan of web server ports"), num_hashes=64)
        sig_b = minhash(
            shingle("completely unrelated topic about database design"), num_hashes=64
        )
        similarity = jaccard_similarity(sig_a, sig_b)
        assert similarity < 0.5  # Should be low

    def test_empty_signatures(self):
        assert jaccard_similarity([], []) == 0.0

    def test_mismatched_lengths(self):
        assert jaccard_similarity([1, 2, 3], [1, 2]) == 0.0


# =============================================================================
# Loop detection logic
# =============================================================================


class TestDetectLoop:
    def _fresh_state(self):
        return {
            "turn_hashes": [],
            "consecutive_similar": 0,
            "escalation_level": 0,
            "total_turns": 0,
        }

    def test_first_turn_no_loop(self):
        state = self._fresh_state()
        level, consecutive = detect_loop(state, "first turn text", 1)
        assert level == 0
        assert consecutive == 0

    def test_dissimilar_turns_no_loop(self):
        state = self._fresh_state()

        detect_loop(state, "analyzing web application security", 1)
        level, consecutive = detect_loop(
            state, "running nmap on different subnet", 1
        )

        assert level == 0

    def test_similar_turns_accumulate(self):
        state = self._fresh_state()

        # Feed identical text with zero tool count to simulate looping
        for i in range(LEVEL_1_TURNS + 1):
            level, consecutive = detect_loop(
                state,
                "thinking about SQL injection in the login form",
                0,  # zero tools = looping
            )

        assert level >= 1
        assert consecutive >= LEVEL_1_TURNS

    def test_tool_execution_breaks_loop(self):
        """Executing a tool with similar text should decrement the counter."""
        state = self._fresh_state()

        # Build up some consecutive similar turns
        for _ in range(2):
            detect_loop(state, "same thought pattern repeating", 0)

        # Now execute a tool with similar text
        level, consecutive = detect_loop(
            state, "same thought pattern repeating", 1  # has tool execution
        )

        # Should have decremented, not incremented
        assert consecutive < 2

    def test_level2_escalation(self):
        state = self._fresh_state()

        for i in range(LEVEL_2_TURNS + 1):
            level, consecutive = detect_loop(
                state,
                "looping thought about XSS exploitation vectors",
                0,
            )

        assert level >= 2

    def test_level3_escalation(self):
        state = self._fresh_state()

        for i in range(LEVEL_3_TURNS + 1):
            level, consecutive = detect_loop(
                state,
                "endless cycle of SQLi analysis without action",
                0,
            )

        assert level == 3


# =============================================================================
# State persistence
# =============================================================================


class TestStatePersistence:
    def test_load_missing_state_returns_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARTIFACTS_PATH", str(tmp_path))
        state = load_state("10.0.0.1")
        assert state["total_turns"] == 0
        assert state["consecutive_similar"] == 0

    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        """Test state round-trip using a temp directory.

        loop_detector uses STATE_FILE_TEMPLATE with /artifacts/{target}/...
        so we monkeypatch the module-level template to use tmp_path.
        """
        import loop_detector

        original = loop_detector.STATE_FILE_TEMPLATE
        monkeypatch.setattr(
            loop_detector, "STATE_FILE_TEMPLATE",
            str(tmp_path / "{target}" / "session" / "loop_state.json"),
        )

        state = {
            "turn_hashes": [],
            "consecutive_similar": 5,
            "escalation_level": 1,
            "total_turns": 10,
        }
        save_state("10.0.0.1", state)

        loaded = load_state("10.0.0.1")
        assert loaded["consecutive_similar"] == 5
        assert loaded["total_turns"] == 10


# =============================================================================
# Warning message building
# =============================================================================


class TestBuildLoopWarning:
    def test_level1_warning(self):
        msg = build_loop_warning(1, [], [], 3)
        assert "LOOP WARNING" in msg
        assert "3 consecutive" in msg

    def test_level2_with_failed_techniques(self):
        failed = ["- SQLi on login.php (blocked by WAF)"]
        msg = build_loop_warning(2, failed, [], 7)
        assert "CONTEXT RESET" in msg
        assert "SQLi on login.php" in msg
        assert "FAILED" in msg

    def test_level2_with_untried_surfaces(self):
        untried = ["- deserialization in upload.php (HIGH PRIORITY)"]
        msg = build_loop_warning(2, [], untried, 7)
        assert "Untried attack surfaces" in msg
        assert "upload.php" in msg

    def test_level3_kill(self):
        msg = build_loop_warning(3, [], [], 15)
        assert "LEVEL 3" in msg
        assert "terminated" in msg
