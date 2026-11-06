from __future__ import annotations

import re

CSI_PATTERN = r"\x1b\[[0-?]*[ -/]*[@-~]"
OSC_PATTERN = r"\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\)?"
C0_PATTERN = r"[\x00-\x08\x0b-\x1f\x7f]"
BIDI_PATTERN = r"[\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]"

CONTROL_SEQUENCE = re.compile(f"(?:{OSC_PATTERN}|{CSI_PATTERN}|{C0_PATTERN}|{BIDI_PATTERN})")


def strip_control_characters(value: object) -> str:
    """Strip ANSI CSI, OSC sequences, ASCII control characters (CR, NUL, BEL, BS), and Bidi overrides.

    - Returns empty string if value is None.
    - Converts non-string types using str(value).
    - Preserves legitimate tabs (\\t) and newlines (\\n).
    - Cleans carriage return (\\r), isolated ESC (\\x1b), and C0 controls.
    - Preserves whitespace (does not perform .strip()).
    """
    if value is None:
        return ""
    return CONTROL_SEQUENCE.sub("", str(value))


def sanitize_terminal_text(value: object) -> str:
    """Semantic alias for strip_control_characters for terminal rendering contexts."""
    return strip_control_characters(value)


__all__ = [
    "BIDI_PATTERN",
    "C0_PATTERN",
    "CONTROL_SEQUENCE",
    "CSI_PATTERN",
    "OSC_PATTERN",
    "sanitize_terminal_text",
    "strip_control_characters",
]

