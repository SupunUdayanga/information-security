"""SHA-512 reference implementation wrapper.

Owner: M1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SHA512Digest:
    """Result container for SHA-512 digests."""

    hexdigest: str
    digest_bytes: bytes


def sha512_hash(message: bytes) -> SHA512Digest:
    """Compute the standard SHA-512 digest for the given message."""
    raise NotImplementedError("Implement the standard SHA-512 hash.")


def hash_stream(chunks: Iterable[bytes]) -> SHA512Digest:
    """Hash a stream of chunks using standard SHA-512."""
    raise NotImplementedError("Implement streaming SHA-512 hashing.")
