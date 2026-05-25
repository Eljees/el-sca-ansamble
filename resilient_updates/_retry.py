"""Shared retry/backoff policy.

Previously, retry parameters were read inline at each ``attempt_sources``
call site (`cli.py` for trivy / cve-bin-tool layers via
``config[...]["retry_backoff_policy"]``, and a HARDCODED 1/1/[429,5xx]
for grype's listing fetch).  Result: three slightly-different ways to
say "how many times do we retry", and a magic 1 in cli.py:269-270 that
diverged from the YAML defaults.

This module defines a single :class:`RetryPolicy` dataclass and a
factory that reads the YAML node from any tool's section.  Adopt it
gradually:

- new call sites pass ``policy.as_attempt_kwargs()`` to
  ``attempt_sources(...)``;
- existing call sites keep working until they're migrated.

See docs/audit/10-defects.md §10 and docs/audit/20-architecture.md §2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Sensible defaults for any caller that loads a partial / missing section.
# These mirror the grype listing-fetch values that were hardcoded in
# cli.update_grype before the refactor — short timeout, one retry,
# retry on rate-limit / transient 5xx only.
DEFAULT_RETRY_COUNT = 1
DEFAULT_BACKOFF_SECONDS = 1
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


@dataclass(frozen=True)
class RetryPolicy:
    """How long to wait, how many times to retry, on which status codes.

    Frozen so a single instance can be shared safely across threads
    (the scanners themselves are sequential today, but the pre-commit
    hook for type-checking expects immutable shared values).
    """

    retry_count: int = DEFAULT_RETRY_COUNT
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    retry_status_codes: tuple[int, ...] = field(default_factory=lambda: DEFAULT_RETRY_STATUS_CODES)

    @classmethod
    def from_yaml_node(cls, node: dict[str, Any] | None) -> "RetryPolicy":
        """Build from a YAML ``retry_backoff_policy`` (or partial) node.

        Missing keys fall back to defaults so callers never have to
        ``.get(...)`` with their own fallback.  Unknown keys are
        ignored on purpose — forward-compatible.
        """
        if not isinstance(node, dict):
            return cls()
        return cls(
            retry_count=int(node.get("retry_count", DEFAULT_RETRY_COUNT)),
            backoff_seconds=float(node.get("backoff_seconds", DEFAULT_BACKOFF_SECONDS)),
            timeout_seconds=float(node.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            retry_status_codes=tuple(node.get("retry_status_codes", DEFAULT_RETRY_STATUS_CODES)),
        )

    @classmethod
    def from_tool_config(cls, config: dict[str, Any], tool: str) -> "RetryPolicy":
        """Build from ``config[tool]['retry_backoff_policy']`` if present."""
        tool_cfg = config.get(tool) or {}
        return cls.from_yaml_node(tool_cfg.get("retry_backoff_policy"))

    def as_attempt_kwargs(self) -> dict[str, Any]:
        """Spread-into ``attempt_sources(**policy.as_attempt_kwargs())``."""
        return {
            "timeout": int(self.timeout_seconds),
            "retry_count": int(self.retry_count),
            "backoff_seconds": int(self.backoff_seconds),
            "retry_status_codes": list(self.retry_status_codes),
        }
