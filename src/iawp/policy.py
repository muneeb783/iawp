"""Turn raw classifier output into a placement decision.

Errors are asymmetric: wrongly promoting a batch job into `critical` hurts the
service it was meant to protect, while missing a critical task only leaves it
in `default` (today's status quo). So anything uncertain goes to `default`,
and `critical` demands the highest confidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from iawp.classify.base import Classification
from iawp.taxonomy import LAYER_OF, UNKNOWN


@dataclass(frozen=True)
class Thresholds:
    enough_info: float = 0.5  # min P("there is enough information to tell")
    # Chosen on the eval set's dev half (odd ids) with JevOS v5, checked on the even half.
    critical: float = 0.95  # min class probability to place into the critical layer
    other: float = 0.8  # min class probability for every other non-default layer


@dataclass(frozen=True)
class Decision:
    cls: str  # final class, UNKNOWN when not trusted
    layer: str
    reason: str  # why, for `scan` and `explain`


def decide(c: Classification, t: Thresholds = Thresholds()) -> Decision:
    if c.enough_info < t.enough_info:
        return Decision(UNKNOWN, LAYER_OF[UNKNOWN], f"not enough information ({c.enough_info:.2f} < {t.enough_info})")
    layer = LAYER_OF[c.cls]
    need = t.critical if layer == "critical" else t.other
    if c.confidence < need:
        return Decision(UNKNOWN, LAYER_OF[UNKNOWN], f"{c.cls} at {c.confidence:.2f} is below {need}")
    return Decision(c.cls, layer, f"{c.cls} at {c.confidence:.2f}")
