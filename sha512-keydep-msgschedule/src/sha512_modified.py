"""Modified SHA-512 implementation with key-dependent message schedule.

The only algorithmic difference from standard SHA-512 is that the message
schedule expansion (W[16..79]) uses rotation constants derived from a secret
key rather than the fixed ROTR(1, 8) / ROTR(19, 61) constants specified in
FIPS 180-4.

All compression-round constants (K₀–K₇₉) and initial hash values remain
unchanged.

Usage
-----
    from src.sha512_modified import sha512_keydep_hash

    digest = sha512_keydep_hash(b"hello", key=b"my-secret-key")
    print(digest.hexdigest)

Owner: M1
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional

from src.key_schedule import (
    ScheduleConfig,
    build_schedule_config,
    derive_schedule_words,
    iter_message_blocks,
)

# ---------------------------------------------------------------------------
# SHA-512 constants (identical to the original)
# ---------------------------------------------------------------------------

_H0: List[int] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]

_K: List[int] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]

_MASK64 = 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Internal helpers (unchanged from the standard)
# ---------------------------------------------------------------------------

def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _MASK64


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z) & _MASK64


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0_upper(x: int) -> int:
    return _rotr64(x, 28) ^ _rotr64(x, 34) ^ _rotr64(x, 39)


def _sigma1_upper(x: int) -> int:
    return _rotr64(x, 14) ^ _rotr64(x, 18) ^ _rotr64(x, 41)


# ---------------------------------------------------------------------------
# Modified compression
# ---------------------------------------------------------------------------

def _compress_keydep(
    state: List[int],
    W: List[int],
    rounds: int = 80,
) -> List[int]:
    """Run the SHA-512 compression function with a pre-expanded schedule W."""
    a, b, c, d, e, f, g, h = state

    for t in range(rounds):
        T1 = (h + _sigma1_upper(e) + _ch(e, f, g) + _K[t] + W[t]) & _MASK64
        T2 = (_sigma0_upper(a) + _maj(a, b, c)) & _MASK64
        h = g
        g = f
        f = e
        e = (d + T1) & _MASK64
        d = c
        c = b
        b = a
        a = (T1 + T2) & _MASK64

    return [
        (state[i] + v) & _MASK64
        for i, v in enumerate([a, b, c, d, e, f, g, h])
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModifiedSHA512Digest:
    """Result container for the modified SHA-512 digests."""

    hexdigest: str
    digest_bytes: bytes
    r0: int   # rotation constant used for σ₀
    r1: int   # rotation constant used for σ₁


def sha512_keydep_hash(
    message: bytes,
    key: bytes,
    rounds: Optional[int] = None,
) -> ModifiedSHA512Digest:
    """Compute modified SHA-512 digest using a key-dependent message schedule.

    Parameters
    ----------
    message:
        Arbitrary input message.
    key:
        Secret key from which rotation constants are derived.
    rounds:
        Number of compression rounds (1–80).  Defaults to 80.  Values < 80
        are only used for the partial-collision experiments.

    Returns
    -------
    ModifiedSHA512Digest
        Contains the hex digest, raw bytes, and the rotation constants used.
    """
    config = build_schedule_config(key)
    effective_rounds = rounds if rounds is not None else config.rounds

    state = list(_H0)
    for block in iter_message_blocks(message):
        W = derive_schedule_words(block, key, config)
        state = _compress_keydep(state, W, rounds=effective_rounds)

    raw = struct.pack('>8Q', *state)
    return ModifiedSHA512Digest(
        hexdigest=raw.hex(),
        digest_bytes=raw,
        r0=config.r0,
        r1=config.r1,
    )


def hash_stream_keydep(
    chunks: Iterable[bytes],
    key: bytes,
    rounds: Optional[int] = None,
) -> ModifiedSHA512Digest:
    """Hash a stream of chunks using key-dependent SHA-512.

    Parameters
    ----------
    chunks:
        Iterable of byte strings; all chunks are concatenated before hashing.
    key:
        Secret key.
    rounds:
        Optional override for the number of compression rounds.
    """
    return sha512_keydep_hash(b''.join(chunks), key=key, rounds=rounds)
