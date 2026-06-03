"""Avalanche effect experiments.

Owner: M2
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple


@dataclass(frozen=True)
class AvalancheResult:
    """Aggregate statistics for avalanche tests."""

    bit_flips_mean: float
    bit_flips_std: float
    samples: int


def run_avalanche_tests(messages: Iterable[bytes], key: bytes) -> AvalancheResult:
    """Run avalanche tests for the modified SHA-512 implementation."""
    raise NotImplementedError("Implement avalanche experiment runner.")


def diff_bits(a: bytes, b: bytes) -> int:
    """Count differing bits between two byte strings."""
    raise NotImplementedError("Implement bit difference counter.")
