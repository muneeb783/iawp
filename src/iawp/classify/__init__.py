"""Classifier backends."""

from __future__ import annotations

from iawp.classify.base import Classification, Classifier, build_state

BACKENDS = ("mock",)


def get_backend(name: str) -> Classifier:
    if name == "mock":
        from iawp.classify.mock import MockClassifier

        return MockClassifier()
    raise ValueError(f"unknown backend {name!r}; choose from {', '.join(BACKENDS)}")


__all__ = ["BACKENDS", "Classification", "Classifier", "build_state", "get_backend"]
