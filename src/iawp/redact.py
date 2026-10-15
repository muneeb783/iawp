"""Strip secrets from command lines before any classifier sees them.

Errs toward over-redacting: a lost hint costs a little accuracy, a leaked
password cannot be taken back. Runs before every backend, including mock,
so `iawp explain` shows exactly what a model would receive.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"
MAX_ARG_LEN = 200
MAX_ARGS = 32
MAX_TOTAL_LEN = 1024

# Option or variable names that usually carry a secret value.
_SECRET_KEY = r"[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key|session[_-]?key|bearer|signature)[\w.-]*"

# --password=x, password=x, PGPASSWORD=x, token:x
_KEY_VALUE = re.compile(rf"(?i)^(-{{0,2}}{_SECRET_KEY})([=:])(.+)$")
# --password x (value is the next argument)
_KEY_ONLY = re.compile(rf"(?i)^-{{1,2}}{_SECRET_KEY}$")
# scheme://user:pass@host
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]*):[^/\s@]+@")
# ?token=x&... inside URLs or connection strings
_QUERY_SECRET = re.compile(rf"(?i)([?&;]{_SECRET_KEY}=)[^&;\s]+")
# Long opaque strings: likely keys/tokens. Letters and digits mixed, 24+ chars.
# '/' is excluded so file paths are judged segment by segment.
_OPAQUE = re.compile(r"[A-Za-z0-9+_=-]{24,}")
_HEADER_AUTH = re.compile(r"(?i)^(authorization:\s*\w+\s+).+$")


def redact_args(argv: tuple[str, ...] | list[str]) -> list[str]:
    """Return a redacted, length-limited copy of argv."""
    out: list[str] = []
    hide_next = False
    total = 0
    for i, arg in enumerate(argv):
        if i >= MAX_ARGS:
            out.append(f"<+{len(argv) - MAX_ARGS} args>")
            break
        if hide_next:
            arg, hide_next = REDACTED, False
        elif _KEY_ONLY.match(arg):
            hide_next = True
        else:
            arg = redact_arg(arg)
        if len(arg) > MAX_ARG_LEN:
            arg = arg[:MAX_ARG_LEN] + "…"
        total += len(arg) + 1
        if total > MAX_TOTAL_LEN:
            out.append("<truncated>")
            break
        out.append(arg)
    return out


def redact_arg(arg: str) -> str:
    if m := _HEADER_AUTH.match(arg):
        return m.group(1) + REDACTED
    if m := _KEY_VALUE.match(arg):
        return f"{m.group(1)}{m.group(2)}{REDACTED}"
    arg = _URL_USERINFO.sub(rf"\1:{REDACTED}@", arg)
    arg = _QUERY_SECRET.sub(rf"\1{REDACTED}", arg)
    return _OPAQUE.sub(_redact_if_opaque, arg)


def _redact_if_opaque(m: re.Match[str]) -> str:
    s = m.group(0)
    # Plain words and paths-with-dashes ("dist-packages-for-python") are hints worth
    # keeping; strings mixing letters and digits look like keys, hashes or tokens.
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    return REDACTED if has_digit and has_alpha else s
