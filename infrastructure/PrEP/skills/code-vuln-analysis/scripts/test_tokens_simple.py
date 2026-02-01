#!/usr/bin/env python3
"""
Simple Token Tests (No pytest dependency)
==========================================

Basic tests for token counting functionality.
Run with: python3 test_tokens_simple.py
"""

import tempfile
import os
from tokens import (
    count_tokens,
    estimate_file_tokens,
    estimate_text_tokens,
    TokenBudget,
    TIKTOKEN_AVAILABLE
)


def test_count_tokens():
    """Test basic token counting."""
    print("Testing count_tokens()...")

    # Empty string
    assert count_tokens("") == 0, "Empty string should return 0"

    # Simple text
    tokens = count_tokens("Hello, world!")
    assert tokens > 0, "Simple text should have tokens"

    # Code sample
    code = '''
    def hello(name):
        return f"Hello, {name}!"
    '''
    tokens = count_tokens(code)
    assert tokens > 0, "Code should have tokens"

    print("  ✓ count_tokens() works correctly")


def test_estimate_file_tokens():
    """Test file token estimation."""
    print("Testing estimate_file_tokens()...")

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
        f.write("def test():\n    return 42\n")
        temp_path = f.name

    try:
        tokens = estimate_file_tokens(temp_path)
        assert tokens > 0, "Valid file should have tokens"
        assert tokens < 100, "Small file should have few tokens"
    finally:
        os.unlink(temp_path)

    # Nonexistent file
    tokens = estimate_file_tokens("/nonexistent/file.txt")
    assert tokens == 0, "Nonexistent file should return 0"

    print("  ✓ estimate_file_tokens() works correctly")


def test_token_budget_basic():
    """Test TokenBudget basic functionality."""
    print("Testing TokenBudget basics...")

    budget = TokenBudget()
    assert budget.turn_limit == 12000, "Default turn limit should be 12000"
    assert budget.phase_limit == 50000, "Default phase limit should be 50000"
    assert budget.consumed == 0, "Initial consumption should be 0"
    assert budget.remaining_phase == 50000, "Initial remaining should equal limit"

    print("  ✓ TokenBudget initialization works")


def test_token_budget_consumption():
    """Test TokenBudget consumption tracking."""
    print("Testing TokenBudget consumption...")

    budget = TokenBudget(phase_limit=50000, turn_limit=12000)

    # Consume tokens
    result = budget.consume(5000)
    assert result is True, "Consumption should succeed"
    assert budget.consumed == 5000, "Consumed should be tracked"
    assert budget.chunks_processed == 1, "Chunk count should increment"

    # Consume more
    budget.consume(3000)
    assert budget.consumed == 8000, "Consumption should accumulate"
    assert budget.chunks_processed == 2, "Chunk count should increment"

    print("  ✓ TokenBudget consumption works")


def test_token_budget_limits():
    """Test TokenBudget limit enforcement."""
    print("Testing TokenBudget limits...")

    budget = TokenBudget(phase_limit=10000, turn_limit=12000)

    # Fill budget
    budget.consumed = 10000
    result = budget.consume(1000)
    assert result is False, "Should reject when budget exhausted"
    assert budget.consumed == 10000, "Consumption should not increase"

    print("  ✓ TokenBudget limits enforced")


def test_token_budget_can_fit():
    """Test TokenBudget can_fit() checks."""
    print("Testing TokenBudget can_fit()...")

    budget = TokenBudget(phase_limit=50000, turn_limit=12000)
    budget.consumed = 40000

    assert budget.can_fit(5000) is True, "Should fit small amount"
    assert budget.can_fit(10000) is True, "Should fit exactly remaining"
    assert budget.can_fit(15000) is False, "Should not fit over limit"

    print("  ✓ TokenBudget can_fit() works")


def test_token_budget_turn_tracking():
    """Test TokenBudget turn advancement."""
    print("Testing TokenBudget turn tracking...")

    budget = TokenBudget(turn_limit=10000)

    # First chunk
    budget.consume(6000)
    assert budget.turn_count == 0, "Should still be on first turn"

    # Second chunk exceeds turn limit
    budget.consume(5000)
    assert budget.turn_count == 1, "Should advance to second turn"

    print("  ✓ TokenBudget turn tracking works")


def test_token_budget_summary():
    """Test TokenBudget summary output."""
    print("Testing TokenBudget summary()...")

    budget = TokenBudget(turn_limit=12000, phase_limit=50000)
    budget.consume(6000)
    budget.consume(8000)

    summary = budget.summary()
    assert "consumed" in summary, "Summary should have consumed"
    assert "remaining" in summary, "Summary should have remaining"
    assert "turns_used" in summary, "Summary should have turns_used"
    assert "utilization" in summary, "Summary should have utilization"

    assert summary["consumed"] == 14000, "Consumed should be tracked"
    assert summary["chunks_processed"] == 2, "Chunks should be tracked"

    print("  ✓ TokenBudget summary() works")


def test_estimate_text_tokens_alias():
    """Test estimate_text_tokens() alias."""
    print("Testing estimate_text_tokens() alias...")

    text = "Test string"
    tokens1 = count_tokens(text)
    tokens2 = estimate_text_tokens(text)
    assert tokens1 == tokens2, "Alias should return same result"

    print("  ✓ estimate_text_tokens() alias works")


def test_realistic_workflow():
    """Test realistic workflow."""
    print("Testing realistic workflow...")

    # Create temporary files
    files = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            for j in range((i + 1) * 50):
                f.write(f"x = {j}\n")
            files.append(f.name)

    try:
        budget = TokenBudget(turn_limit=12000, phase_limit=50000)

        for file_path in files:
            tokens = estimate_file_tokens(file_path)
            if budget.can_fit(tokens):
                budget.consume(tokens)

        assert budget.chunks_processed > 0, "Should process some chunks"
        assert budget.consumed > 0, "Should consume some tokens"

        print("  ✓ Realistic workflow works")

    finally:
        for f in files:
            os.unlink(f)


def main():
    """Run all tests."""
    print("=" * 60)
    print("Token Counting Tests")
    print("=" * 60)
    print(f"Tiktoken available: {TIKTOKEN_AVAILABLE}")
    print()

    tests = [
        test_count_tokens,
        test_estimate_file_tokens,
        test_token_budget_basic,
        test_token_budget_consumption,
        test_token_budget_limits,
        test_token_budget_can_fit,
        test_token_budget_turn_tracking,
        test_token_budget_summary,
        test_estimate_text_tokens_alias,
        test_realistic_workflow,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
