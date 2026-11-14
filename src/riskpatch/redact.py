from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization|dsn)", re.I)
SECRET_VALUE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sw_[A-Za-z0-9_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"
)
URL_CREDS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.I)
ASSIGN = re.compile(r"(?i)\b([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)\s*([=:])\s*\S+")


def redact_text(value: str) -> str:
    value = URL_CREDS.sub(lambda m: f"{m.group(1)}{REDACTED}@", value)
    value = ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    return SECRET_VALUE.sub(REDACTED, value)


def redact(value: Any, key: str = "") -> Any:
    """Defense in depth: the collector already redacts, the server never trusts that."""
    if key and SECRET_KEY.search(key):
        return REDACTED if value not in (None, "", [], {}) else value
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
