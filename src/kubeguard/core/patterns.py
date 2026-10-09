"""Shared detection patterns."""

from __future__ import annotations

import re

_SECRET_NAME = re.compile(r"(api[_-]?key|password|passwd|secret|token)", re.IGNORECASE)
# Names like DB_PASSWORD_FILE point at a file, not at the secret itself.
_REFERENCE_SUFFIXES = ("_FILE", "_PATH", "_FILENAME", "_DIR")


def looks_like_secret_name(name: str) -> bool:
    """True if an environment variable name suggests it holds a credential."""
    if name.upper().endswith(_REFERENCE_SUFFIXES):
        return False
    return bool(_SECRET_NAME.search(name))