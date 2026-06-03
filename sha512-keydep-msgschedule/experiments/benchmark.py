"""Benchmarking for SHA-512 variants.

Owner: M3
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class BenchmarkResult:
    """Benchmark results for hashing performance."""

    bytes_per_sec: float
    samples: int


def run_benchmarks(messages: Iterable[bytes], key: bytes) -> BenchmarkResult:
    """Run performance benchmarks for the modified SHA-512 implementation."""
    raise NotImplementedError("Implement benchmark runner.")
