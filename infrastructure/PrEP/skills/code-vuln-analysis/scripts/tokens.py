#!/usr/bin/env python3
"""
Token Counting Utility
======================

Provides accurate token counting using tiktoken with fallback to character-based
estimation. Used for chunk size budgeting in multi-turn analysis phases.

Key features:
- Accurate token counting via tiktoken (cl100k_base encoding)
- Graceful fallback to char-based estimation
- TokenBudget dataclass for turn/phase budget tracking
- File token estimation utilities

Usage:
    from tokens import count_tokens, estimate_file_tokens, TokenBudget

    tokens = count_tokens(source_code)
    file_tokens = estimate_file_tokens("path/to/file.py")

    budget = TokenBudget(turn_limit=12000, phase_limit=50000)
    budget.consume(chunk_tokens)
"""

from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False

# Token estimation constants
CHARS_PER_TOKEN_CODE = 4.0
CHARS_PER_TOKEN_COMMENT = 3.5


def count_tokens(text: str, model: str = "cl100k_base") -> int:
    """
    Count tokens in text using tiktoken.

    Falls back to character-based estimation if tiktoken unavailable.

    Args:
        text: Source code or text to count
        model: Encoding name (cl100k_base for Claude/GPT-4)

    Returns:
        Estimated token count
    """
    if TIKTOKEN_AVAILABLE:
        try:
            enc = tiktoken.get_encoding(model)
            return len(enc.encode(text))
        except Exception:
            pass

    # Fallback: estimate based on character count
    # Code averages ~4 chars/token, comments ~3.5 chars/token
    # Use weighted average assuming 20% comments
    avg_chars_per_token = (CHARS_PER_TOKEN_CODE * 0.8) + (CHARS_PER_TOKEN_COMMENT * 0.2)
    return int(len(text) / avg_chars_per_token)


def estimate_file_tokens(file_path: str, encoding: str = "utf-8") -> int:
    """
    Estimate token count for a source file.

    Args:
        file_path: Path to the file
        encoding: File encoding (default: utf-8)

    Returns:
        Estimated token count, or 0 if file cannot be read
    """
    try:
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            content = f.read()
        return count_tokens(content)
    except (OSError, IOError):
        return 0


@dataclass
class TokenBudget:
    """
    Track token consumption across turns and phases.

    Used to enforce budget constraints from SKILL.md:
    - Turn limit: 5-12k tokens per LLM turn (optimal: 10k)
    - Phase limit: Total tokens for a pipeline phase

    Example:
        budget = TokenBudget(turn_limit=12000, phase_limit=50000)
        budget.consume(6000)  # First chunk
        budget.consume(8000)  # Second chunk
        print(budget.remaining_phase)  # 36000
    """
    turn_limit: int = 12000  # Max tokens per turn (from SKILL.md)
    phase_limit: int = 50000  # Max tokens per phase
    consumed: int = 0
    turn_count: int = 0
    chunks_processed: int = 0

    # History tracking
    turn_history: list = field(default_factory=list)

    @property
    def remaining_phase(self) -> int:
        """Tokens remaining in phase budget."""
        return max(0, self.phase_limit - self.consumed)

    @property
    def remaining_turn(self) -> int:
        """Tokens remaining in current turn budget."""
        current_turn_tokens = sum(self.turn_history[-1:]) if self.turn_history else 0
        return max(0, self.turn_limit - current_turn_tokens)

    @property
    def phase_exhausted(self) -> bool:
        """Check if phase budget is exhausted."""
        return self.remaining_phase <= 0

    @property
    def turn_exhausted(self) -> bool:
        """Check if current turn budget is exhausted."""
        return self.remaining_turn <= 0

    def consume(self, tokens: int) -> bool:
        """
        Consume tokens from budget.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if consumption succeeded, False if budget exhausted
        """
        if self.phase_exhausted:
            return False

        self.consumed += tokens
        self.chunks_processed += 1

        # Track turn consumption
        if not self.turn_history:
            self.turn_history.append(0)

        self.turn_history[-1] += tokens

        # Auto-advance turn if current turn exceeds limit
        if self.turn_history[-1] >= self.turn_limit:
            self.next_turn()

        return True

    def next_turn(self) -> None:
        """Advance to next turn, resetting turn budget."""
        self.turn_count += 1
        self.turn_history.append(0)

    def can_fit(self, tokens: int, in_current_turn: bool = False) -> bool:
        """
        Check if tokens can fit in budget.

        Args:
            tokens: Number of tokens to check
            in_current_turn: If True, check if fits in current turn (not next)

        Returns:
            True if tokens can be accommodated
        """
        if tokens > self.remaining_phase:
            return False

        if in_current_turn and tokens > self.remaining_turn:
            return False

        return True

    def summary(self) -> dict:
        """
        Get budget consumption summary.

        Returns:
            Dict with consumption statistics
        """
        return {
            "consumed": self.consumed,
            "remaining": self.remaining_phase,
            "turns_used": self.turn_count + (1 if self.turn_history else 0),
            "chunks_processed": self.chunks_processed,
            "avg_tokens_per_chunk": self.consumed // self.chunks_processed if self.chunks_processed else 0,
            "avg_tokens_per_turn": self.consumed // max(1, self.turn_count + 1),
            "phase_limit": self.phase_limit,
            "turn_limit": self.turn_limit,
            "utilization": f"{(self.consumed / self.phase_limit * 100):.1f}%"
        }


def estimate_text_tokens(text: str) -> int:
    """
    Alias for count_tokens() for backward compatibility.

    Args:
        text: Text to count

    Returns:
        Token count
    """
    return count_tokens(text)


if __name__ == "__main__":
    # Demo usage
    sample_code = '''
    def example_function(user_input):
        """Process user input."""
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        return db.execute(query)
    '''

    print("Token Counting Demo")
    print("=" * 50)

    tokens = count_tokens(sample_code)
    print(f"Sample code tokens: {tokens}")
    print(f"Tiktoken available: {TIKTOKEN_AVAILABLE}")

    # Budget tracking demo
    print("\nBudget Tracking Demo")
    print("=" * 50)

    budget = TokenBudget(turn_limit=12000, phase_limit=50000)
    print(f"Initial budget: {budget.summary()}\n")

    # Simulate chunk processing
    chunks = [6000, 8000, 7000, 5000, 10000]
    for i, chunk_size in enumerate(chunks, 1):
        if budget.can_fit(chunk_size):
            budget.consume(chunk_size)
            print(f"Chunk {i}: {chunk_size} tokens consumed")
            print(f"  Remaining phase: {budget.remaining_phase}")
            print(f"  Remaining turn: {budget.remaining_turn}")
            print(f"  Turns used: {budget.turn_count + 1}\n")
        else:
            print(f"Chunk {i}: {chunk_size} tokens - BUDGET EXHAUSTED")
            break

    print("Final Summary:")
    print(budget.summary())
