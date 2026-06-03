"""Bit independence criterion (BIC) experiments.

Owner: M2
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class BICResult:
    """Aggregate statistics for BIC tests."""

    independence_mean: float
    independence_std: float
    samples: int


def run_bic_tests(messages: Iterable[bytes], key: bytes) -> BICResult:
    """Run BIC tests for the modified SHA-512 implementation."""
    raise NotImplementedError("Implement BIC experiment runner.")
