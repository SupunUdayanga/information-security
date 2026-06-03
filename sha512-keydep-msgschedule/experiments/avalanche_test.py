"""Avalanche effect experiments.

Measures the average number of output bits that change when a single input bit
is flipped.  Tests are run for both the original SHA-512 and the modified
key-dependent variant so results can be compared side-by-side.

Methodology
-----------
For each message m (uniformly random bytes):
  For each bit position b in m:
    m' = m with bit b flipped
    AvalancheRatio = popcount(H(m) XOR H(m')) / 512

The mean and std-dev of AvalancheRatio over (samples × bits_per_message)
trials gives the avalanche statistics.

Owner: M2
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Allow running as a script from the project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sha512_original import sha512_hash
from src.sha512_modified import sha512_keydep_hash


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class AvalancheResult:
    """Aggregate statistics for avalanche tests."""

    bit_flips_mean: float          # Average fraction of output bits changed
    bit_flips_std: float           # Standard deviation
    samples: int                   # Number of messages tested
    total_trials: int              # Total (message × bit-flip) trials
    raw_ratios: List[float] = field(default_factory=list)  # per-trial values


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def diff_bits(a: bytes, b: bytes) -> int:
    """Count differing bits between two equal-length byte strings.

    Parameters
    ----------
    a, b:
        Byte strings of equal length.

    Returns
    -------
    int
        Hamming distance (number of bit positions that differ).
    """
    if len(a) != len(b):
        raise ValueError(f"Byte strings must be equal length ({len(a)} vs {len(b)})")
    count = 0
    for x, y in zip(a, b):
        xor = x ^ y
        # Brian Kernighan's bit-count
        while xor:
            count += 1
            xor &= xor - 1
    return count


def _flip_bit(msg: bytes, bit_index: int) -> bytes:
    """Return a copy of *msg* with the bit at *bit_index* flipped."""
    byte_idx = bit_index // 8
    bit_offset = 7 - (bit_index % 8)
    ba = bytearray(msg)
    ba[byte_idx] ^= 1 << bit_offset
    return bytes(ba)


def _compute_ratios(
    hash_fn: Callable[[bytes], bytes],
    messages: List[bytes],
    bits_per_message: Optional[int] = None,
) -> List[float]:
    """Core trial loop – returns one ratio per (message, bit) pair."""
    ratios: List[float] = []
    for msg in messages:
        n_bits = bits_per_message if bits_per_message else len(msg) * 8
        h_orig = hash_fn(msg)
        for bit in range(n_bits):
            h_flipped = hash_fn(_flip_bit(msg, bit))
            ratio = diff_bits(h_orig, h_flipped) / 512.0
            ratios.append(ratio)
    return ratios


def _stats(values: List[float]) -> Tuple[float, float]:
    """Return (mean, std) of a list of floats."""
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return mean, variance ** 0.5


# ---------------------------------------------------------------------------
# Public experiment runners
# ---------------------------------------------------------------------------

def run_avalanche_tests(
    messages: Iterable[bytes],
    key: bytes,
    bits_per_message: Optional[int] = None,
) -> AvalancheResult:
    """Run avalanche tests for the modified SHA-512 implementation.

    Parameters
    ----------
    messages:
        Collection of random byte strings used as test inputs.
    key:
        Secret key for the key-dependent variant.
    bits_per_message:
        Number of bit-flip positions to test per message.  Defaults to
        testing all bits (``len(msg) * 8``).

    Returns
    -------
    AvalancheResult
        Statistics for the modified SHA-512 variant.
    """
    msg_list = list(messages)

    def keydep_fn(m: bytes) -> bytes:
        return sha512_keydep_hash(m, key).digest_bytes

    ratios = _compute_ratios(keydep_fn, msg_list, bits_per_message)
    mean, std = _stats(ratios)
    return AvalancheResult(
        bit_flips_mean=mean,
        bit_flips_std=std,
        samples=len(msg_list),
        total_trials=len(ratios),
        raw_ratios=ratios,
    )


def run_avalanche_tests_original(
    messages: Iterable[bytes],
    bits_per_message: Optional[int] = None,
) -> AvalancheResult:
    """Run avalanche tests for the standard (original) SHA-512.

    Parameters
    ----------
    messages:
        Collection of random byte strings used as test inputs.
    bits_per_message:
        Number of bit-flip positions to test per message.

    Returns
    -------
    AvalancheResult
        Statistics for the original SHA-512 variant.
    """
    msg_list = list(messages)

    def orig_fn(m: bytes) -> bytes:
        return sha512_hash(m).digest_bytes

    ratios = _compute_ratios(orig_fn, msg_list, bits_per_message)
    mean, std = _stats(ratios)
    return AvalancheResult(
        bit_flips_mean=mean,
        bit_flips_std=std,
        samples=len(msg_list),
        total_trials=len(ratios),
        raw_ratios=ratios,
    )


# ---------------------------------------------------------------------------
# Entry point (standalone execution)
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import json

    N_MESSAGES = 200          # messages to test
    MSG_LEN = 32              # bytes per message
    BITS_PER_MSG = 32         # bit-flip positions per message (subset for speed)
    KEY = b'ec6204-secret-key-avalanche'

    rng = random.Random(42)
    test_messages = [
        bytes(rng.randint(0, 255) for _ in range(MSG_LEN))
        for _ in range(N_MESSAGES)
    ]

    print(f"Running avalanche tests on {N_MESSAGES} messages × {BITS_PER_MSG} bits …")

    orig_result = run_avalanche_tests_original(test_messages, bits_per_message=BITS_PER_MSG)
    mod_result  = run_avalanche_tests(test_messages, KEY, bits_per_message=BITS_PER_MSG)

    print(f"\nOriginal SHA-512:")
    print(f"  Mean ratio : {orig_result.bit_flips_mean:.6f}  (ideal = 0.500000)")
    print(f"  Std-dev    : {orig_result.bit_flips_std:.6f}")
    print(f"  Trials     : {orig_result.total_trials}")

    print(f"\nModified SHA-512 (key-dependent):")
    print(f"  Mean ratio : {mod_result.bit_flips_mean:.6f}  (ideal = 0.500000)")
    print(f"  Std-dev    : {mod_result.bit_flips_std:.6f}")
    print(f"  Trials     : {mod_result.total_trials}")

    results = {
        "original": {
            "mean": orig_result.bit_flips_mean,
            "std": orig_result.bit_flips_std,
            "trials": orig_result.total_trials,
        },
        "modified": {
            "mean": mod_result.bit_flips_mean,
            "std": mod_result.bit_flips_std,
            "trials": mod_result.total_trials,
        },
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'avalanche_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")
