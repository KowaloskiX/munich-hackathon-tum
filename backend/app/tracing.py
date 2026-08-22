"""Thin Langfuse facade — traces the Devin loop for the pitch/debug.

Degrades to a no-op when Langfuse is not configured or the SDK is missing, so
nothing here can break the request path. One trace per anomaly loop; spans for
each agent session and oracle verdict nest under it.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any, Protocol

from .config import settings


class Span(Protocol):
    def update(self, **kwargs: Any) -> None: ...
    def end(self, **kwargs: Any) -> None: ...


class _NoopSpan:
    def update(self, **kwargs: Any) -> None:
        return None

    def end(self, **kwargs: Any) -> None:
        return None


class Trace(Protocol):
    def span(self, **kwargs: Any) -> Span: ...


class _NoopTrace:
    def span(self, **kwargs: Any) -> Span:
        return _NoopSpan()


_client: Any | None = None


def _get_client() -> Any | None:
    global _client
    if not settings.langfuse_enabled:
        return None
    if _client is None:
        try:
            from langfuse import Langfuse

            _client = Langfuse(
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
                host=settings.langfuse_host,
            )
        except Exception:
            _client = None
    return _client


def start_trace(name: str, **kwargs: Any) -> Trace:
    client = _get_client()
    if client is None:
        return _NoopTrace()
    try:
        return client.trace(name=name, **kwargs)
    except Exception:
        return _NoopTrace()


@contextlib.contextmanager
def span(trace: Trace, name: str, **kwargs: Any) -> Iterator[Span]:
    """Open a span on `trace`; always yields something with update()/end()."""
    try:
        s: Span = trace.span(name=name, **kwargs)
    except Exception:
        s = _NoopSpan()
    try:
        yield s
    finally:
        with contextlib.suppress(Exception):
            s.end()


def flush() -> None:
    client = _get_client()
    if client is not None:
        with contextlib.suppress(Exception):
            client.flush()
