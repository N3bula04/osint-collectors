"""One clock for timestamps, cache ages and certificate/domain age maths.

`set_fixed_time()` pins it (for reproducible offline runs); None restores real time.
"""

import datetime as _dt
from typing import Optional, Union

_FIXED_NOW: Optional[_dt.datetime] = None


def set_fixed_time(when: Union[None, str, _dt.datetime]) -> None:
    global _FIXED_NOW
    if isinstance(when, str):
        when = _dt.datetime.fromisoformat(when)
    if when is not None and when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    _FIXED_NOW = when


def utcnow() -> _dt.datetime:
    return _FIXED_NOW if _FIXED_NOW is not None else _dt.datetime.now(_dt.timezone.utc)


def today() -> _dt.date:
    return utcnow().date()


def now_iso() -> str:
    return utcnow().replace(microsecond=0).isoformat()
