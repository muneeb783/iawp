"""Classifier backends."""

from __future__ import annotations

from iawp.classify.base import Classification, Classifier, build_state
from iawp.classify.systemone import ClassifierError

BACKENDS = ("mock", "local", "hosted")


def get_backend(name: str, url: str | None = None, model: str | None = None) -> Classifier:
    if name == "mock":
        from iawp.classify.mock import MockClassifier

        return MockClassifier()
    if name in ("local", "hosted"):
        from iawp.classify import systemone

        return getattr(systemone, name)(url, model)
    raise ValueError(f"unknown backend {name!r}; choose from {', '.join(BACKENDS)}")


__all__ = ["BACKENDS", "Classification", "Classifier", "ClassifierError", "build_state", "get_backend"]
