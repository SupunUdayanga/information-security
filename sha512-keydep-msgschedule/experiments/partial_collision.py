"""Partial collision search experiments.

Owner: M3
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple


@dataclass(frozen=True)
class CollisionResult:
    """Results for partial collision experiments."""

    attempts: int
    collision_found: bool
    collision_pair: Tuple[bytes, bytes] | None


def run_partial_collision_search(messages: Iterable[bytes], key: bytes, bits: int) -> CollisionResult:
    """Search for partial collisions on the modified SHA-512 implementation."""
    raise NotImplementedError("Implement partial collision search.")
