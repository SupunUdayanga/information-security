"""Key-dependent message schedule utilities.

Derives dynamic rotation constants r₀(K) and r₁(K) from a secret key K and
exposes helpers used by both the modified SHA-512 implementation and the
experiment runners.

Design (from the proposal):
    r₀(K) = (K_int  mod 19) + 1      ← replaces ROTR 1  in σ₀
    r₁(K) = (K_int  mod 61) + 1      ← replaces ROTR 19 in σ₁

    where K_int is the big-endian integer of the first 8 bytes (64 bits) of
    the SHA-512 hash of the raw key material.  Using the hash of the key
    ensures that even short / low-entropy keys produce well-spread constants.

    The shift amounts (7 and 6) in the original σ₀/σ₁ are left fixed because
    they are pure right-shifts (not rotations) and varying them independently
    is not part of the stated proposal.

Owner: M1
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Iterable, List, Tuple

_MASK64 = 0xFFFFFFFFFFFFFFFF
_BLOCK_SIZE = 128  # SHA-512 block size in bytes


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScheduleConfig:
    """Configuration for the key-dependent schedule.

    Attributes
    ----------
    rounds:
        Number of SHA-512 compression rounds (always 80 for standard use).
    seed_words:
        Number of initial message words (always 16 for SHA-512).
    r0:
        Key-dependent rotation amount that replaces ROTR(1) in σ₀.
    r1:
        Key-dependent rotation amount that replaces ROTR(19) in σ₁.
    r0_secondary:
        Rotation amount that replaces ROTR(8) in σ₀  (fixed at 8 by default).
    r1_secondary:
        Rotation amount that replaces ROTR(61) in σ₁ (fixed at 61 by default).
    """

    rounds: int
    seed_words: int
    r0: int
    r1: int
    r0_secondary: int = 8
    r1_secondary: int = 61


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_rotation_constants(key: bytes) -> Tuple[int, int]:
    """Derive (r₀, r₁) rotation constants from key material.

    Parameters
    ----------
    key:
        Arbitrary-length secret key.

    Returns
    -------
    (r0, r1)
        r₀ ∈ [1, 19], r₁ ∈ [1, 61]
    """
    # Hash the key with SHA-512 to get uniformly distributed key material.
    key_hash = hashlib.sha512(key).digest()
    # Use the first 8 bytes as a 64-bit big-endian integer.
    k_int = struct.unpack('>Q', key_hash[:8])[0]
    r0 = (k_int % 19) + 1   # ∈ {1 … 19}
    r1 = (k_int % 61) + 1   # ∈ {1 … 61}
    return r0, r1


def build_schedule_config(key: bytes) -> ScheduleConfig:
    """Build a complete ScheduleConfig from a key.

    Parameters
    ----------
    key:
        Arbitrary-length secret key bytes.
    """
    r0, r1 = derive_rotation_constants(key)
    return ScheduleConfig(rounds=80, seed_words=16, r0=r0, r1=r1)


# ---------------------------------------------------------------------------
# Message padding & blocking
# ---------------------------------------------------------------------------

def _pad_message(message: bytes) -> bytes:
    """Apply SHA-512 Merkle-Damgård padding."""
    msg_len_bits = len(message) * 8
    message += b'\x80'
    while len(message) % _BLOCK_SIZE != 112:
        message += b'\x00'
    message += struct.pack('>QQ', 0, msg_len_bits)
    return message


def iter_message_blocks(message: bytes, block_size: int = 128) -> Iterable[bytes]:
    """Yield padded message blocks for SHA-512 processing.

    Parameters
    ----------
    message:
        Raw input message (will be padded according to SHA-512 spec).
    block_size:
        Block size in bytes; must be 128 for SHA-512 (default).

    Yields
    ------
    bytes
        Successive 128-byte blocks.
    """
    padded = _pad_message(message)
    for i in range(0, len(padded), block_size):
        yield padded[i: i + block_size]


# ---------------------------------------------------------------------------
# Schedule derivation
# ---------------------------------------------------------------------------

def derive_schedule_words(
    message_block: bytes,
    key: bytes,
    config: ScheduleConfig,
) -> List[int]:
    """Derive message schedule words from a 128-byte block and key.

    Parameters
    ----------
    message_block:
        Exactly 128 bytes (one SHA-512 block, already padded).
    key:
        Secret key; used only to read rotation constants from *config*.
    config:
        A ScheduleConfig produced by :func:`build_schedule_config`.

    Returns
    -------
    List[int]
        80 64-bit message schedule words W[0..79].
    """
    if len(message_block) != 128:
        raise ValueError(f"Expected 128-byte block, got {len(message_block)}")

    # Parse 16 seed words
    W: List[int] = list(struct.unpack('>16Q', message_block))

    r0 = config.r0              # replaces ROTR(1)
    r1 = config.r1              # replaces ROTR(19)
    r0s = config.r0_secondary   # ROTR(8)  – kept fixed
    r1s = config.r1_secondary   # ROTR(61) – kept fixed

    # Extend to 80 words using KEY-DEPENDENT σ₀/σ₁
    for t in range(16, 80):
        x = W[t - 2]
        s1 = (((x >> r1) | (x << (64 - r1))) & _MASK64) ^ \
             (((x >> r1s) | (x << (64 - r1s))) & _MASK64) ^ \
             (x >> 6)

        x = W[t - 15]
        s0 = (((x >> r0) | (x << (64 - r0))) & _MASK64) ^ \
             (((x >> r0s) | (x << (64 - r0s))) & _MASK64) ^ \
             (x >> 7)

        W.append((s1 + W[t - 7] + s0 + W[t - 16]) & _MASK64)

    return W
