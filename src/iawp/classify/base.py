"""Classifier interface: state in, class probabilities out."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from iawp.collector import ProcessRecord
from iawp.redact import redact_args


@dataclass(frozen=True)
class Classification:
    cls: str  # most probable taxonomy class
    probabilities: dict[str, float]  # over every taxonomy class, sums to ~1
    enough_info: float  # P(yes) for "is there enough information here to tell?"
    model: str  # backend and model version, stored with cached answers

    @property
    def confidence(self) -> float:
        return self.probabilities.get(self.cls, 0.0)


class Classifier(Protocol):
    name: str

    def classify(self, state: dict[str, str]) -> Classification: ...


def build_state(r: ProcessRecord) -> dict[str, str]:
    """The exact, redacted facts a classifier sees about one process.

    Keys are human-readable because models read them. `iawp explain` prints
    this dict verbatim, so it is also the privacy contract.
    """
    return {
        "process_name": r.comm,
        "executable": r.exe or "(unreadable without root)",
        "command_line": " ".join(redact_args(r.cmdline)),
        "parent_process": r.parent_comm or "(none)",
        "cgroup": r.cgroup or "(none)",
        "user": r.user,
    }
