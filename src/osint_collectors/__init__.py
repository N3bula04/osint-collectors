"""osint-collectors: cached, rate-limit-aware collectors for public DNS, CT and RDAP data.

The package only collects and caches. It does not rate, score or attribute
anything; that stays in the tools that use it.
"""

__version__ = "0.1.0"

# Statuses that are safe to cache. Timeouts, errors and skips are never
# cached, so a transient failure does not poison later runs.
CACHEABLE_STATUSES = frozenset({"ok", "empty", "nxdomain"})

__all__ = ["__version__", "CACHEABLE_STATUSES"]
