"""Score a classifier against a labelled process set (eval/processes.jsonl).

Records are scored on the final decision, after thresholds, because that is
what lands in the config. Raw probabilities are kept for calibration.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from iawp.classify.base import Classification, Classifier
from iawp.policy import Decision, Thresholds, decide
from iawp.taxonomy import CLASSES, LAYER_OF, UNKNOWN

LABELS = [*CLASSES, UNKNOWN]


@dataclass(frozen=True)
class Scored:
    record: dict
    result: Classification
    decision: Decision
    seconds: float

    @property
    def label(self) -> str:
        return self.record["label"]

    @property
    def correct(self) -> bool:
        return self.decision.cls == self.label


def load(path: Path) -> list[dict]:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for r in records:
        if r["label"] not in LABELS:
            raise ValueError(f"{r['id']}: unknown label {r['label']!r}")
    return records


def run(backend: Classifier, records: list[dict], thresholds: Thresholds, progress=None) -> list[Scored]:
    out = []
    for i, r in enumerate(records):
        start = time.perf_counter()
        result = backend.classify(r["state"])
        out.append(Scored(r, result, decide(result, thresholds), time.perf_counter() - start))
        if progress:
            progress(i + 1, len(records))
    return out


def metrics(scored: list[Scored]) -> dict:
    n = len(scored)
    decided = [s for s in scored if s.decision.cls != UNKNOWN]
    placed_critical = [s for s in scored if s.decision.layer == "critical"]
    truly_critical = [s for s in scored if LAYER_OF[s.label] == "critical"]
    # The error that hurts: something that is not latency-critical promoted into `critical`.
    harmful = [s for s in placed_critical if s.label != "latency-critical"]
    unknown_labelled = [s for s in scored if s.label == UNKNOWN]
    times = sorted(s.seconds for s in scored)
    return {
        "records": n,
        "accuracy": _ratio(sum(s.correct for s in scored), n),
        "coverage": _ratio(len(decided), n),
        "accuracy_when_decided": _ratio(sum(s.correct for s in decided), len(decided)),
        "critical_precision": _ratio(len(placed_critical) - len(harmful), len(placed_critical)),
        "critical_recall": _ratio(sum(s.decision.layer == "critical" for s in truly_critical), len(truly_critical)),
        "harmful_promotions": [s.record["id"] for s in harmful],
        "unknown_recognised": _ratio(sum(s.decision.cls == UNKNOWN for s in unknown_labelled), len(unknown_labelled)),
        "calibration": calibration(scored),
        "confusion": confusion(scored),
        "latency_ms": {"p50": _pct(times, 0.5) * 1000, "p95": _pct(times, 0.95) * 1000},
        "models": sorted({s.result.model for s in scored}),
    }


def calibration(scored: list[Scored], edges=(0.0, 0.5, 0.7, 0.9, 0.95, 1.01)) -> dict:
    """Is a p=0.9 answer right 90% of the time? Raw top-class probability vs. hit rate.

    Only records with a real class label count: `unknown` has no right class to hit.
    ECE is the gap between confidence and accuracy, averaged over records.
    """
    pts = [(s.result.confidence, s.result.cls == s.label) for s in scored if s.label != UNKNOWN]
    bins, ece = [], 0.0
    for lo, hi in zip(edges, edges[1:]):
        inside = [(c, ok) for c, ok in pts if lo <= c < hi]
        if not inside:
            continue
        conf = sum(c for c, _ in inside) / len(inside)
        acc = sum(ok for _, ok in inside) / len(inside)
        ece += len(inside) / len(pts) * abs(conf - acc)
        bins.append({"range": f"{lo:.2f}-{min(hi, 1.0):.2f}", "n": len(inside), "confidence": conf, "accuracy": acc})
    return {"ece": ece if pts else None, "bins": bins}


def confusion(scored: list[Scored]) -> dict[str, dict[str, int]]:
    m = {a: {b: 0 for b in LABELS} for a in LABELS}
    for s in scored:
        m[s.label][s.decision.cls] += 1
    return m


def report(scored: list[Scored], backend: str, path: Path, judgment: str) -> str:
    m = metrics(scored)
    pct = lambda x: "  n/a" if x is None else f"{x * 100:5.1f}%"  # noqa: E731
    lines = [
        f"{m['records']} records from {path} ({judgment}), backend {backend}, model {', '.join(m['models'])}",
        "",
        f"  critical precision   {pct(m['critical_precision'])}   placed in critical and belongs there",
        f"  harmful promotions   {len(m['harmful_promotions']):>5}    {' '.join(m['harmful_promotions'])}".rstrip(),
        f"  critical recall      {pct(m['critical_recall'])}   latency-critical processes that reached critical",
        f"  accuracy             {pct(m['accuracy'])}   final decision matches the label (unknown included)",
        f"  coverage             {pct(m['coverage'])}   decided a class instead of unknown",
        f"  accuracy if decided  {pct(m['accuracy_when_decided'])}",
        f"  unknown recognised   {pct(m['unknown_recognised'])}   'nobody could tell' records left as unknown",
        f"  latency              p50 {m['latency_ms']['p50']:.0f} ms, p95 {m['latency_ms']['p95']:.0f} ms",
        "",
    ]
    cal = m["calibration"]
    if cal["ece"] is not None:
        lines.append(f"  calibration (ECE {cal['ece']:.3f}; 0 is perfect)")
        lines.append("    confidence  records  avg conf  right")
        for b in cal["bins"]:
            lines.append(f"    {b['range']:<10}  {b['n']:>7}  {b['confidence']:8.2f}  {b['accuracy']:5.2f}")
        lines.append("")

    short = {c: c.split("-")[0][:5] for c in LABELS}
    lines.append("  confusion (rows: label, columns: decision)")
    lines.append("    " + " " * 17 + "".join(f"{short[c]:>7}" for c in LABELS))
    for a, row in m["confusion"].items():
        lines.append(f"    {a:<17}" + "".join(f"{row[b] or '.':>7}" for b in LABELS))
    return "\n".join(lines)


def errors(scored: list[Scored]) -> str:
    lines = []
    for s in scored:
        if s.correct:
            continue
        flag = " [judgment]" if s.record.get("judgment") else ""
        lines.append(f"  {s.record['id']} {s.label} -> {s.decision.cls} ({s.decision.reason}){flag}")
        lines.append(f"       {s.record['state']['process_name']}: {s.record['state']['command_line'][:100]}")
    return "\n".join(lines)


def dump(scored: list[Scored], path: Path, backend: str) -> None:
    """Per-record results plus metrics, to compare models later without rerunning them."""
    data = {
        "backend": backend,
        "metrics": metrics(scored),
        "results": [{
            "id": s.record["id"], "label": s.label, "decision": s.decision.cls, "layer": s.decision.layer,
            "probabilities": s.result.probabilities, "enough_info": s.result.enough_info,
            "model": s.result.model, "seconds": s.seconds,
        } for s in scored],
    }
    path.write_text(json.dumps(data, indent=1) + "\n")


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def _pct(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    return sorted_values[min(len(sorted_values) - 1, int(q * len(sorted_values)))]
