"""Classifier backends."""

from __future__ import annotations

from pathlib import Path

from iawp.classify.base import Classification, Classifier, build_state
from iawp.classify.systemone import ClassifierError

BACKENDS = ("mock", "local", "hosted")


def get_backend(name: str, url: str | None = None, model: str | None = None,
                cache_path: Path | None = None) -> Classifier:
    """Build a backend. Model backends are cached at `cache_path` when given; mock never is."""
    if name == "mock":
        from iawp.classify.mock import MockClassifier

        return MockClassifier()
    if name in ("local", "hosted"):
        from iawp.classify import systemone

        backend = getattr(systemone, name)(url, model)
        if cache_path is None:
            return backend
        from iawp.classify.cache import Cache, CachedClassifier

        return CachedClassifier(backend, Cache(cache_path), backend.identity, systemone.QUESTIONS)
    raise ValueError(f"unknown backend {name!r}; choose from {', '.join(BACKENDS)}")


__all__ = ["BACKENDS", "Classification", "Classifier", "ClassifierError", "build_state", "get_backend"]
