#!/usr/bin/env python3
"""
Unit Tests for Token Counting Utility
======================================

Tests token counting, file estimation, and budget tracking functionality.

Run with: python -m pytest test_tokens.py -v
"""

import pytest
import tempfile
import os
from pathlib import Path

from tokens import (
    count_tokens,
    estimate_file_tokens,
    estimate_text_tokens,
    TokenBudget,
    TIKTOKEN_AVAILABLE,
    CHARS_PER_TOKEN_CODE,
    CHARS_PER_TOKEN_COMMENT
)


class TestCountTokens:
    """Test count_tokens() function."""

    def test_count_empty_string(self):
        """Empty string should return 0 tokens."""
        assert count_tokens("") == 0

    def test_count_simple_text(self):
        """Simple text should return positive token count."""
        text = "Hello, world!"
        tokens = count_tokens(text)
        assert tokens > 0

    def test_count_code_sample(self):
        """Code sample should be tokenized correctly."""
        code = '''
        def hello(name):
            return f"Hello, {name}!"
        '''
        tokens = count_tokens(code)
        assert tokens > 0

        # Should be roughly len(code) / 4 if using fallback
        if not TIKTOKEN_AVAILABLE:
            expected_approx = len(code) / 3.92  # Weighted average
            assert abs(tokens - expected_approx) < 5

    def test_count_with_different_models(self):
        """Test with different encoding models."""
        text = "Test string"

        # Default model
        tokens_default = count_tokens(text)
        assert tokens_default > 0

        # Explicit model
        tokens_explicit = count_tokens(text, model="cl100k_base")
        assert tokens_explicit > 0

        # Should be equal for same model
        if TIKTOKEN_AVAILABLE:
            assert tokens_default == tokens_explicit

    def test_count_large_text(self):
        """Large text should be handled efficiently."""
        large_text = "x" * 100000
        tokens = count_tokens(large_text)
        assert tokens > 0

    def test_count_unicode(self):
        """Unicode characters should be handled."""
        unicode_text = "Hello 世界 🌍"
        tokens = count_tokens(unicode_text)
        assert tokens > 0

    def test_fallback_estimation(self):
        """Test fallback estimation when tiktoken unavailable."""
        text = "Sample code with comments"
        tokens = count_tokens(text)

        # If tiktoken available, should be exact
        # If not, should be character-based estimate
        assert tokens > 0


class TestEstimateFileTokens:
    """Test estimate_file_tokens() function."""

    def test_estimate_valid_file(self):
        """Valid file should return accurate token estimate."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write("def test():\n    return 42\n")
            temp_path = f.name

        try:
            tokens = estimate_file_tokens(temp_path)
            assert tokens > 0
            assert tokens < 100  # Small file
        finally:
            os.unlink(temp_path)

    def test_estimate_nonexistent_file(self):
        """Nonexistent file should return 0."""
        tokens = estimate_file_tokens("/path/that/does/not/exist.txt")
        assert tokens == 0

    def test_estimate_empty_file(self):
        """Empty file should return 0 tokens."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name

        try:
            tokens = estimate_file_tokens(temp_path)
            assert tokens == 0
        finally:
            os.unlink(temp_path)

    def test_estimate_large_file(self):
        """Large file should return proportional token count."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            # Write ~10KB of code
            for i in range(500):
                f.write(f"def function_{i}():\n    return {i}\n")
            temp_path = f.name

        try:
            tokens = estimate_file_tokens(temp_path)
            assert tokens > 1000  # Should be substantial
        finally:
            os.unlink(temp_path)

    def test_estimate_with_encoding(self):
        """Test different file encodings."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            f.write("UTF-8 content: éàü")
            temp_path = f.name

        try:
            tokens = estimate_file_tokens(temp_path, encoding='utf-8')
            assert tokens > 0
        finally:
            os.unlink(temp_path)

    def test_estimate_binary_file_ignored(self):
        """Binary file should be handled gracefully."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x00\x01\x02\x03')
            temp_path = f.name

        try:
            # Should use 'ignore' error handling
            tokens = estimate_file_tokens(temp_path)
            # May return 0 or small value depending on binary content
            assert tokens >= 0
        finally:
            os.unlink(temp_path)


class TestEstimateTextTokens:
    """Test estimate_text_tokens() backward compatibility."""

    def test_alias_works(self):
        """estimate_text_tokens should work as alias."""
        text = "Test string"
        tokens1 = count_tokens(text)
        tokens2 = estimate_text_tokens(text)
        assert tokens1 == tokens2


class TestTokenBudget:
    """Test TokenBudget dataclass."""

    def test_initialization(self):
        """Budget should initialize with correct defaults."""
        budget = TokenBudget()
        assert budget.turn_limit == 12000
        assert budget.phase_limit == 50000
        assert budget.consumed == 0
        assert budget.turn_count == 0
        assert budget.chunks_processed == 0

    def test_custom_limits(self):
        """Budget should accept custom limits."""
        budget = TokenBudget(turn_limit=10000, phase_limit=40000)
        assert budget.turn_limit == 10000
        assert budget.phase_limit == 40000

    def test_remaining_phase(self):
        """remaining_phase should calculate correctly."""
        budget = TokenBudget(phase_limit=50000)
        assert budget.remaining_phase == 50000

        budget.consumed = 10000
        assert budget.remaining_phase == 40000

        budget.consumed = 50000
        assert budget.remaining_phase == 0

        budget.consumed = 60000
        assert budget.remaining_phase == 0  # Can't be negative

    def test_remaining_turn(self):
        """remaining_turn should calculate correctly."""
        budget = TokenBudget(turn_limit=12000)
        assert budget.remaining_turn == 12000

        budget.turn_history = [5000]
        assert budget.remaining_turn == 7000

        budget.turn_history = [12000]
        assert budget.remaining_turn == 0

    def test_phase_exhausted(self):
        """phase_exhausted should detect when budget is depleted."""
        budget = TokenBudget(phase_limit=10000)
        assert not budget.phase_exhausted

        budget.consumed = 9999
        assert not budget.phase_exhausted

        budget.consumed = 10000
        assert budget.phase_exhausted

        budget.consumed = 15000
        assert budget.phase_exhausted

    def test_turn_exhausted(self):
        """turn_exhausted should detect when turn budget is depleted."""
        budget = TokenBudget(turn_limit=12000)
        assert not budget.turn_exhausted

        budget.turn_history = [11999]
        assert not budget.turn_exhausted

        budget.turn_history = [12000]
        assert budget.turn_exhausted

    def test_consume_basic(self):
        """consume() should track token usage."""
        budget = TokenBudget(phase_limit=50000)
        result = budget.consume(5000)

        assert result is True
        assert budget.consumed == 5000
        assert budget.chunks_processed == 1
        assert len(budget.turn_history) == 1
        assert budget.turn_history[0] == 5000

    def test_consume_multiple(self):
        """Multiple consume() calls should accumulate."""
        budget = TokenBudget(phase_limit=50000, turn_limit=12000)

        budget.consume(5000)
        budget.consume(3000)
        budget.consume(6000)

        assert budget.consumed == 14000
        assert budget.chunks_processed == 3

    def test_consume_exceeds_phase(self):
        """consume() should fail when phase exhausted."""
        budget = TokenBudget(phase_limit=10000)
        budget.consumed = 10000

        result = budget.consume(1000)
        assert result is False
        assert budget.consumed == 10000  # Should not increase

    def test_consume_auto_advance_turn(self):
        """consume() should auto-advance turn when limit reached."""
        budget = TokenBudget(turn_limit=10000)

        budget.consume(6000)
        assert budget.turn_count == 0
        assert len(budget.turn_history) == 1

        budget.consume(5000)  # Total 11000, exceeds turn limit
        assert budget.turn_count == 1
        assert len(budget.turn_history) == 2

    def test_next_turn(self):
        """next_turn() should reset turn budget."""
        budget = TokenBudget(turn_limit=12000)
        budget.turn_history = [8000]

        budget.next_turn()

        assert budget.turn_count == 1
        assert len(budget.turn_history) == 2
        assert budget.turn_history[1] == 0

    def test_can_fit_phase(self):
        """can_fit() should check phase budget."""
        budget = TokenBudget(phase_limit=50000)
        budget.consumed = 40000

        assert budget.can_fit(5000) is True
        assert budget.can_fit(10000) is True
        assert budget.can_fit(15000) is False

    def test_can_fit_turn(self):
        """can_fit() should check turn budget when requested."""
        budget = TokenBudget(turn_limit=12000)
        budget.turn_history = [8000]

        assert budget.can_fit(3000, in_current_turn=True) is True
        assert budget.can_fit(4000, in_current_turn=True) is True
        assert budget.can_fit(5000, in_current_turn=True) is False

        # Should still fit in phase (next turn)
        assert budget.can_fit(5000, in_current_turn=False) is True

    def test_summary(self):
        """summary() should provide comprehensive statistics."""
        budget = TokenBudget(turn_limit=12000, phase_limit=50000)
        budget.consume(6000)
        budget.consume(8000)
        budget.next_turn()
        budget.consume(5000)

        summary = budget.summary()

        assert summary["consumed"] == 19000
        assert summary["remaining"] == 31000
        assert summary["turns_used"] == 2
        assert summary["chunks_processed"] == 3
        assert summary["avg_tokens_per_chunk"] == 19000 // 3
        assert summary["phase_limit"] == 50000
        assert summary["turn_limit"] == 12000
        assert "utilization" in summary

    def test_summary_no_division_by_zero(self):
        """summary() should handle empty budget."""
        budget = TokenBudget()
        summary = budget.summary()

        assert summary["consumed"] == 0
        assert summary["chunks_processed"] == 0
        assert summary["avg_tokens_per_chunk"] == 0


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_realistic_workflow(self):
        """Test realistic chunk processing workflow."""
        # Create temporary files
        files = []
        for i in range(5):
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
                # Write varying amounts of code
                for j in range((i + 1) * 100):
                    f.write(f"x = {j}\n")
                files.append(f.name)

        try:
            # Estimate tokens for each file
            budget = TokenBudget(turn_limit=12000, phase_limit=50000)

            for file_path in files:
                tokens = estimate_file_tokens(file_path)
                if budget.can_fit(tokens):
                    budget.consume(tokens)

            # Verify reasonable results
            assert budget.chunks_processed > 0
            assert budget.consumed > 0
            assert not budget.phase_exhausted

        finally:
            for f in files:
                os.unlink(f)

    def test_budget_enforcement(self):
        """Test budget enforcement across chunks."""
        budget = TokenBudget(turn_limit=10000, phase_limit=30000)

        chunks = [6000, 5000, 8000, 7000, 10000]
        processed = []

        for chunk_size in chunks:
            if budget.can_fit(chunk_size):
                budget.consume(chunk_size)
                processed.append(chunk_size)
            else:
                break

        # Should process chunks until budget exhausted
        assert sum(processed) <= 30000
        assert budget.phase_exhausted or len(processed) == len(chunks)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_zero_token_consumption(self):
        """Consuming zero tokens should work."""
        budget = TokenBudget()
        result = budget.consume(0)
        assert result is True
        assert budget.consumed == 0

    def test_negative_token_check(self):
        """Negative token counts should be handled."""
        budget = TokenBudget()
        # This is technically invalid input, but shouldn't crash
        result = budget.can_fit(-100)
        assert isinstance(result, bool)

    def test_very_large_limits(self):
        """Very large limits should work."""
        budget = TokenBudget(turn_limit=1000000, phase_limit=10000000)
        result = budget.consume(500000)
        assert result is True
        assert not budget.phase_exhausted

    def test_empty_turn_history(self):
        """Empty turn history should be handled."""
        budget = TokenBudget()
        assert budget.remaining_turn == 12000
        assert not budget.turn_exhausted


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
