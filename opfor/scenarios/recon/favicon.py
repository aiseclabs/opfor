"""Favicon hashing, the Shodan-compatible way, with no external dependency.

A company tends to serve the same favicon across its sites, so a favicon hash is
a cheap same-owner fingerprint. The hash matches Shodan and FOFA, which compute
mmh3 over the base64 of the icon bytes, so the value can be pasted straight into
`http.favicon.hash:<n>` to pivot to more hosts that share it. murmur3 is small,
so it is implemented here rather than pulled in as a dependency.
"""

from __future__ import annotations

import base64

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned signed, as Shodan and FOFA use it."""
    h = seed
    rounded = len(data) & ~3
    for i in range(0, rounded, 4):
        k = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k = (k * _C1) & _MASK
        k = ((k << 15) | (k >> 17)) & _MASK
        k = (k * _C2) & _MASK
        h ^= k
        h = ((h << 13) | (h >> 19)) & _MASK
        h = (h * 5 + 0xE6546B64) & _MASK
    k = 0
    rem = len(data) & 3
    if rem == 3:
        k ^= data[rounded + 2] << 16
    if rem >= 2:
        k ^= data[rounded + 1] << 8
    if rem >= 1:
        k ^= data[rounded]
        k = (k * _C1) & _MASK
        k = ((k << 15) | (k >> 17)) & _MASK
        k = (k * _C2) & _MASK
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _MASK
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _MASK
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(content: bytes) -> int:
    """Shodan-style favicon hash: mmh3 over the base64 of the icon bytes."""
    return murmur3_32(base64.encodebytes(content))
