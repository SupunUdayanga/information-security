"""Benchmarking for SHA-512 variants.

Measures hashing throughput (bytes/second) for both the original SHA-512 and
the key-dependent variant across a range of message sizes.  Overhead is
expressed as the percentage slowdown of the modified variant relative to the
original.

Methodology
-----------
For each message size S ∈ {64, 256, 1 KiB, 4 KiB, 16 KiB}:
    - Generate N_WARMUP hashes to warm up the interpreter.
    - Time N_TIMING hashes, record wall-clock elapsed.
    - Throughput = (N_TIMING × S) / elapsed_seconds

The benchmark uses Python's time.perf_counter() for high resolution timing.

Owner: M3
"""

from __future__ import annotations

import os
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sha512_original import sha512_hash
from src.sha512_modified import sha512_keydep_hash


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    """Benchmark results for hashing performance."""

    bytes_per_sec: float          # Throughput in bytes/second
    samples: int                  # Number of timing iterations
    message_size: int             # Input message size in bytes
    elapsed_sec: float            # Total elapsed time


@dataclass
class BenchmarkSuite:
    """Results across multiple message sizes."""

    original: Dict[int, BenchmarkResult] = field(default_factory=dict)
    modified: Dict[int, BenchmarkResult] = field(default_factory=dict)

    def overhead_pct(self, size: int) -> float:
        """Percentage overhead of modified vs original for a given message size."""
        orig = self.original[size].bytes_per_sec
        mod  = self.modified[size].bytes_per_sec
        return ((orig - mod) / orig) * 100.0


# ---------------------------------------------------------------------------
# Internal timing helper
# ---------------------------------------------------------------------------

def _time_hash_fn(
    hash_fn: Callable[[bytes], object],
    message: bytes,
    n_warmup: int = 5,
    n_timing: int = 200,
) -> BenchmarkResult:
    """Time *hash_fn* on *message* for *n_timing* iterations.

    Parameters
    ----------
    hash_fn:
        A callable that takes a single bytes argument.
    message:
        The message to hash.
    n_warmup:
        Number of warm-up calls (discarded).
    n_timing:
        Number of timed calls.

    Returns
    -------
    BenchmarkResult
    """
    # Warm up
    for _ in range(n_warmup):
        hash_fn(message)

    # Timed run
    start = time.perf_counter()
    for _ in range(n_timing):
        hash_fn(message)
    elapsed = time.perf_counter() - start

    throughput = (n_timing * len(message)) / elapsed
    return BenchmarkResult(
        bytes_per_sec=throughput,
        samples=n_timing,
        message_size=len(message),
        elapsed_sec=elapsed,
    )


# ---------------------------------------------------------------------------
# Public experiment runners
# ---------------------------------------------------------------------------

def run_benchmarks(
    messages: Iterable[bytes],
    key: bytes,
    n_warmup: int = 5,
    n_timing: int = 200,
) -> BenchmarkResult:
    """Run performance benchmarks for the modified SHA-512 implementation.

    Parameters
    ----------
    messages:
        Iterable of messages to hash.  The *first* message is used for timing.
    key:
        Secret key for the key-dependent variant.
    n_warmup:
        Warm-up iterations.
    n_timing:
        Timed iterations.

    Returns
    -------
    BenchmarkResult
        Throughput statistics for the modified SHA-512.
    """
    msg_list = list(messages)
    message = msg_list[0] if msg_list else b'\x00' * 256

    def keydep_fn(m: bytes) -> object:
        return sha512_keydep_hash(m, key)

    return _time_hash_fn(keydep_fn, message, n_warmup=n_warmup, n_timing=n_timing)


def run_benchmark_suite(
    key: bytes,
    sizes: Optional[List[int]] = None,
    n_warmup: int = 5,
    n_timing: int = 300,
) -> BenchmarkSuite:
    """Run benchmarks across multiple message sizes for both variants.

    Parameters
    ----------
    key:
        Secret key for the key-dependent variant.
    sizes:
        List of message sizes in bytes.  Defaults to [64, 256, 1024, 4096, 16384].
    n_warmup:
        Warm-up iterations.
    n_timing:
        Timed iterations per size.

    Returns
    -------
    BenchmarkSuite
    """
    if sizes is None:
        sizes = [64, 256, 1024, 4096, 16384]

    suite = BenchmarkSuite()
    rng = random.Random(99)

    for size in sizes:
        msg = bytes(rng.randint(0, 255) for _ in range(size))

        orig_result = _time_hash_fn(sha512_hash, msg, n_warmup=n_warmup, n_timing=n_timing)
        suite.original[size] = orig_result

        def keydep_fn(m: bytes) -> object:
            return sha512_keydep_hash(m, key)

        mod_result = _time_hash_fn(keydep_fn, msg, n_warmup=n_warmup, n_timing=n_timing)
        suite.modified[size] = mod_result

        overhead = suite.overhead_pct(size)
        print(
            f"  Size={size:>6} B | "
            f"Orig: {orig_result.bytes_per_sec/1024:.1f} KB/s | "
            f"Mod: {mod_result.bytes_per_sec/1024:.1f} KB/s | "
            f"Overhead: {overhead:+.2f}%"
        )

    return suite


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import json

    KEY = b'ec6204-secret-key-benchmark'

    print("Running benchmark suite …\n")
    suite = run_benchmark_suite(KEY, n_warmup=5, n_timing=200)

    print("\nSummary:")
    for size in sorted(suite.original.keys()):
        print(f"  {size:>6} bytes → overhead {suite.overhead_pct(size):+.2f}%")

    out = {
        "sizes": sorted(suite.original.keys()),
        "original_bps": [suite.original[s].bytes_per_sec for s in sorted(suite.original)],
        "modified_bps": [suite.modified[s].bytes_per_sec for s in sorted(suite.modified)],
        "overhead_pct": [suite.overhead_pct(s) for s in sorted(suite.original)],
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'benchmark_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {out_path}")
