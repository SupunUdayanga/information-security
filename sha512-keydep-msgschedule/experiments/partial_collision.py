"""Partial collision search experiments.

A *partial collision* on N bits means finding two distinct messages m₁ ≠ m₂
such that the first N bits of H(m₁) and H(m₂) are identical.

The expected number of trials to find an N-bit partial collision is 2^(N/2)
(birthday bound).  A hash function that requires *more* trials than this
ideal baseline exhibits greater resistance to collision attacks.

Methodology
-----------
The experiment uses reduced-round variants of both SHA-512 implementations
to make partial collision search tractable:
  - rounds ∈ {10, 20, 30} (reduced from 80)
  - target_bits ∈ {16, 20, 24}

For each (rounds, target_bits) configuration:
  - Randomly generate messages until the first N bits collide.
  - Record the number of attempts required.
  - Repeat REPEAT times, report mean attempts.
  - Compare mean(modified) vs mean(original) – more attempts = better.

Owner: M3
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sha512_original import sha512_hash as _orig_hash
from src.sha512_modified import sha512_keydep_hash as _mod_hash


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class CollisionResult:
    """Results for a single partial collision search run."""

    attempts: int
    collision_found: bool
    collision_pair: Optional[Tuple[bytes, bytes]]
    target_bits: int
    rounds: int


@dataclass
class CollisionSuiteResult:
    """Aggregate over multiple (rounds, bits) configurations."""

    configs: List[Tuple[int, int]]                     # (rounds, bits)
    original_mean_attempts: Dict[Tuple[int, int], float]
    modified_mean_attempts: Dict[Tuple[int, int], float]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _prefix_bits(data: bytes, n: int) -> int:
    """Return the integer value of the first *n* bits of *data*."""
    n_bytes = (n + 7) // 8
    value = int.from_bytes(data[:n_bytes], 'big')
    # Shift right to keep only the top n bits
    shift = n_bytes * 8 - n
    return value >> shift


def _search_collision(
    hash_fn,
    target_bits: int,
    max_attempts: int = 2_000_000,
    rng: Optional[random.Random] = None,
    msg_len: int = 32,
) -> CollisionResult:
    """Search for a partial collision.

    Parameters
    ----------
    hash_fn:
        Callable[bytes] -> bytes  (returns raw digest bytes).
    target_bits:
        Number of leading bits that must match.
    max_attempts:
        Stop after this many hash evaluations regardless.
    rng:
        Optional seeded random for reproducibility.
    msg_len:
        Length of randomly generated messages.

    Returns
    -------
    CollisionResult
    """
    if rng is None:
        rng = random.Random()

    seen: Dict[int, bytes] = {}
    for attempt in range(1, max_attempts + 1):
        msg = bytes(rng.randint(0, 255) for _ in range(msg_len))
        digest = hash_fn(msg)
        prefix = _prefix_bits(digest, target_bits)

        if prefix in seen and seen[prefix] != msg:
            return CollisionResult(
                attempts=attempt,
                collision_found=True,
                collision_pair=(seen[prefix], msg),
                target_bits=target_bits,
                rounds=0,  # Caller fills in
            )
        seen[prefix] = msg

    return CollisionResult(
        attempts=max_attempts,
        collision_found=False,
        collision_pair=None,
        target_bits=target_bits,
        rounds=0,
    )


# ---------------------------------------------------------------------------
# Public experiment runners
# ---------------------------------------------------------------------------

def run_partial_collision_search(
    messages: Iterable[bytes],
    key: bytes,
    bits: int,
    rounds: int = 20,
    max_attempts: int = 500_000,
) -> CollisionResult:
    """Search for partial collisions on the modified SHA-512 implementation.

    Parameters
    ----------
    messages:
        Ignored – random messages are generated internally.  Present for
        interface compatibility with the original stub.
    key:
        Secret key for the key-dependent variant.
    bits:
        Number of leading hash bits that must collide.
    rounds:
        Number of SHA-512 compression rounds to use (reduced for tractability).
    max_attempts:
        Maximum number of hash evaluations.

    Returns
    -------
    CollisionResult
    """
    def keydep_fn(m: bytes) -> bytes:
        return _mod_hash(m, key, rounds=rounds).digest_bytes

    result = _search_collision(
        keydep_fn,
        target_bits=bits,
        max_attempts=max_attempts,
        rng=random.Random(bits + rounds),
    )
    result = CollisionResult(
        attempts=result.attempts,
        collision_found=result.collision_found,
        collision_pair=result.collision_pair,
        target_bits=bits,
        rounds=rounds,
    )
    return result


def run_collision_suite(
    key: bytes,
    configs: Optional[List[Tuple[int, int]]] = None,
    repeat: int = 5,
    max_attempts: int = 300_000,
) -> CollisionSuiteResult:
    """Run partial collision search across multiple (rounds, bits) configs.

    Parameters
    ----------
    key:
        Secret key for the key-dependent variant.
    configs:
        List of (rounds, target_bits) tuples to test.
        Defaults to [(10, 16), (20, 20), (30, 24)].
    repeat:
        Number of independent search runs per config (for mean averaging).
    max_attempts:
        Maximum attempts per single run.

    Returns
    -------
    CollisionSuiteResult
    """
    if configs is None:
        configs = [(10, 16), (20, 20), (30, 24)]

    orig_means: Dict[Tuple[int, int], float] = {}
    mod_means:  Dict[Tuple[int, int], float] = {}

    for (rounds, bits) in configs:
        print(f"  Config: rounds={rounds}, bits={bits}", end='', flush=True)

        # Original
        orig_attempts = []
        for rep in range(repeat):
            def orig_fn(m: bytes) -> bytes:
                return _orig_hash(m).digest_bytes

            res = _search_collision(
                orig_fn, target_bits=bits, max_attempts=max_attempts,
                rng=random.Random(rep * 1000 + rounds + bits),
            )
            orig_attempts.append(res.attempts)
            print('.', end='', flush=True)

        # Modified
        mod_attempts = []
        for rep in range(repeat):
            def keydep_fn(m: bytes) -> bytes:
                return _mod_hash(m, key, rounds=rounds).digest_bytes

            res = _search_collision(
                keydep_fn, target_bits=bits, max_attempts=max_attempts,
                rng=random.Random(rep * 2000 + rounds + bits),
            )
            mod_attempts.append(res.attempts)
            print('.', end='', flush=True)

        orig_means[(rounds, bits)] = sum(orig_attempts) / len(orig_attempts)
        mod_means[(rounds, bits)]  = sum(mod_attempts)  / len(mod_attempts)
        print(
            f" | orig avg={orig_means[(rounds,bits)]:.0f} | "
            f"mod avg={mod_means[(rounds,bits)]:.0f} | "
            f"ratio={mod_means[(rounds,bits)]/orig_means[(rounds,bits)]:.3f}x"
        )

    return CollisionSuiteResult(
        configs=configs,
        original_mean_attempts=orig_means,
        modified_mean_attempts=mod_means,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import json

    KEY = b'ec6204-secret-key-collision'

    print("Running partial collision suite …\n")
    suite = run_collision_suite(KEY, repeat=5, max_attempts=200_000)

    print("\nSummary:")
    for cfg in suite.configs:
        orig = suite.original_mean_attempts[cfg]
        mod  = suite.modified_mean_attempts[cfg]
        print(f"  rounds={cfg[0]:2d}, bits={cfg[1]:2d} | orig={orig:.0f} | mod={mod:.0f} | ratio={mod/orig:.3f}")

    out = {
        "configs": [list(c) for c in suite.configs],
        "original_mean_attempts": {str(k): v for k, v in suite.original_mean_attempts.items()},
        "modified_mean_attempts": {str(k): v for k, v in suite.modified_mean_attempts.items()},
        "ratios": {str(k): suite.modified_mean_attempts[k] / suite.original_mean_attempts[k]
                   for k in suite.configs},
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'collision_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {out_path}")
