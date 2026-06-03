"""Bit Independence Criterion (BIC) experiments.

The BIC tests whether, for a given input bit flip, different output bits
respond *independently* of one another.  Specifically, for each pair of output
bit positions (i, j):

    BIC(i, j) = |Pr[Δout_i = 1 | input bit b flipped] - 0.5|
                + |Pr[Δout_j = 1 | input bit b flipped] - 0.5|
                - |Pr[Δout_i = 1 ∧ Δout_j = 1 | input bit b flipped] - 0.25|

We simplify to the per-output-bit *flip probability* approach used in practice:
  For each output bit position p (0..511) and each message m:
      flip_count[p] += 1  if H(m')[bit p] ≠ H(m)[bit p]
  BIC score = fraction of output bit pairs whose flip probability is in [0.45, 0.55].

The experiment produces:
  - independence_mean: average probability across output bit positions
  - independence_std:  std-dev of per-bit probabilities
  - bic_score:         fraction of bits with probability in the ideal ±5% band

Owner: M2
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sha512_original import sha512_hash
from src.sha512_modified import sha512_keydep_hash
from experiments.avalanche_test import _flip_bit, diff_bits


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class BICResult:
    """Aggregate statistics for BIC tests."""

    independence_mean: float     # Mean flip probability across 512 output bits
    independence_std: float      # Std-dev of per-bit flip probabilities
    bic_score: float             # Fraction of bits within [0.45, 0.55]
    samples: int                 # Number of (message, bit-flip) trials
    per_bit_probs: List[float] = field(default_factory=list)  # 512 values


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_bit(data: bytes, pos: int) -> int:
    """Return the value (0 or 1) of bit *pos* in *data* (big-endian bit order)."""
    byte_idx = pos // 8
    bit_offset = 7 - (pos % 8)
    return (data[byte_idx] >> bit_offset) & 1


def _compute_per_bit_flip_probs(
    hash_fn: Callable[[bytes], bytes],
    messages: List[bytes],
    bits_to_flip: Optional[int] = None,
) -> List[float]:
    """Compute the per-output-bit flip probability over all trial pairs."""
    output_bits = 512
    flip_count = [0] * output_bits
    trials = 0

    for msg in messages:
        n_input_bits = bits_to_flip if bits_to_flip else len(msg) * 8
        h_orig = hash_fn(msg)
        for bit in range(n_input_bits):
            h_flip = hash_fn(_flip_bit(msg, bit))
            for p in range(output_bits):
                if _get_bit(h_orig, p) != _get_bit(h_flip, p):
                    flip_count[p] += 1
            trials += 1

    return [c / trials for c in flip_count]


def _stats(values: List[float]):
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return mean, variance ** 0.5


# ---------------------------------------------------------------------------
# Public experiment runners
# ---------------------------------------------------------------------------

def run_bic_tests(
    messages: Iterable[bytes],
    key: bytes,
    bits_to_flip: Optional[int] = None,
) -> BICResult:
    """Run BIC tests for the modified SHA-512 implementation.

    Parameters
    ----------
    messages:
        Test input messages.
    key:
        Secret key for the key-dependent variant.
    bits_to_flip:
        Number of input-bit positions to flip per message (subset for speed).

    Returns
    -------
    BICResult
    """
    msg_list = list(messages)

    def keydep_fn(m: bytes) -> bytes:
        return sha512_keydep_hash(m, key).digest_bytes

    probs = _compute_per_bit_flip_probs(keydep_fn, msg_list, bits_to_flip)
    mean, std = _stats(probs)
    bic_score = sum(1 for p in probs if 0.45 <= p <= 0.55) / len(probs)
    return BICResult(
        independence_mean=mean,
        independence_std=std,
        bic_score=bic_score,
        samples=len(msg_list),
        per_bit_probs=probs,
    )


def run_bic_tests_original(
    messages: Iterable[bytes],
    bits_to_flip: Optional[int] = None,
) -> BICResult:
    """Run BIC tests for the standard SHA-512.

    Parameters
    ----------
    messages:
        Test input messages.
    bits_to_flip:
        Number of input-bit positions to flip per message.

    Returns
    -------
    BICResult
    """
    msg_list = list(messages)

    def orig_fn(m: bytes) -> bytes:
        return sha512_hash(m).digest_bytes

    probs = _compute_per_bit_flip_probs(orig_fn, msg_list, bits_to_flip)
    mean, std = _stats(probs)
    bic_score = sum(1 for p in probs if 0.45 <= p <= 0.55) / len(probs)
    return BICResult(
        independence_mean=mean,
        independence_std=std,
        bic_score=bic_score,
        samples=len(msg_list),
        per_bit_probs=probs,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import json

    N_MESSAGES = 100
    MSG_LEN = 32
    BITS_PER_MSG = 24
    KEY = b'ec6204-secret-key-bic'

    rng = random.Random(7)
    test_messages = [
        bytes(rng.randint(0, 255) for _ in range(MSG_LEN))
        for _ in range(N_MESSAGES)
    ]

    print(f"Running BIC tests on {N_MESSAGES} messages × {BITS_PER_MSG} bit flips …")

    orig_result = run_bic_tests_original(test_messages, bits_to_flip=BITS_PER_MSG)
    mod_result  = run_bic_tests(test_messages, KEY, bits_to_flip=BITS_PER_MSG)

    print(f"\nOriginal SHA-512:")
    print(f"  Flip-prob mean : {orig_result.independence_mean:.6f}  (ideal = 0.500)")
    print(f"  Flip-prob std  : {orig_result.independence_std:.6f}")
    print(f"  BIC score      : {orig_result.bic_score*100:.2f}%  (fraction of bits in [0.45, 0.55])")

    print(f"\nModified SHA-512 (key-dependent):")
    print(f"  Flip-prob mean : {mod_result.independence_mean:.6f}  (ideal = 0.500)")
    print(f"  Flip-prob std  : {mod_result.independence_std:.6f}")
    print(f"  BIC score      : {mod_result.bic_score*100:.2f}%  (fraction of bits in [0.45, 0.55])")

    out = {
        "original": {
            "flip_prob_mean": orig_result.independence_mean,
            "flip_prob_std": orig_result.independence_std,
            "bic_score": orig_result.bic_score,
            "per_bit_probs": orig_result.per_bit_probs,
        },
        "modified": {
            "flip_prob_mean": mod_result.independence_mean,
            "flip_prob_std": mod_result.independence_std,
            "bic_score": mod_result.bic_score,
            "per_bit_probs": mod_result.per_bit_probs,
        },
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'bic_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {out_path}")
