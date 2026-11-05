from __future__ import annotations

import os
import time

CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_ulid(timestamp_ms: int | None = None) -> str:
    """Generate a 26-character ULID using Crockford's Base32.

    Composed of 48 bits of timestamp (milliseconds) + 80 bits of cryptographic randomness.
    """
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    ts = timestamp_ms & 0xFFFFFFFFFFFF
    rand = int.from_bytes(os.urandom(10), "big")
    val = (ts << 80) | rand

    chars = [CROCKFORD_BASE32[(val >> (5 * (25 - i))) & 0x1F] for i in range(26)]
    return "".join(chars)


def is_valid_ulid(val: str) -> bool:
    """Check if a string is a valid 26-character Crockford Base32 ULID."""
    if not isinstance(val, str) or len(val) != 26:
        return False
    upper = val.upper()
    return all(c in CROCKFORD_BASE32 for c in upper)


__all__ = ["CROCKFORD_BASE32", "generate_ulid", "is_valid_ulid"]
