import json
import subprocess
import sys
from pathlib import Path

import pytest

from iawp import evaluate
from iawp.classify.base import Classification
from iawp.cli import main
from iawp.policy import Thresholds

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "eval" / "processes.jsonl"


class Fixed:
    """Answers by process name from a table: (class, top probability, enough_info)."""
    name = "fixed"

    def __init__(self, table):
        self.table = table

    def classify(self, state):
        cls, p, enough = self.table[state["process_name"]]
        rest = (1 - p) / 4
        probs = {c: (p if c == cls else rest) for c in evaluate.CLASSES}
        return Classification(cls, probs, enough, "fixed-1")


def rec(i, label, name):
    return {"id": f"t{i}", "label": label, "judgment": False, "state": {"process_name": name, "command_line": name}}


def test_metrics():
    records = [
        rec(1, "latency-critical", "nginx"),
        rec(2, "latency-critical", "envoy"),
        rec(3, "background", "autovac"),
        rec(4, "batch-compute", "make"),
        rec(5, "unknown", "app"),
        rec(6, "unknown", "main"),
    ]
    backend = Fixed({
        "nginx": ("latency-critical", 0.95, 0.9),
        "envoy": ("latency-critical", 0.6, 0.9),  # too unsure for critical -> unknown
        "autovac": ("latency-critical", 0.95, 0.9),  # harmful promotion
        "make": ("batch-compute", 0.9, 0.9),
        "app": ("interactive", 0.9, 0.9),  # confident guess on an unknowable record
        "main": ("batch-compute", 0.9, 0.1),  # correctly says not enough information
    })
    m = evaluate.metrics(evaluate.run(backend, records, Thresholds()))
    assert m["critical_precision"] == 0.5
    assert m["harmful_promotions"] == ["t3"]
    assert m["critical_recall"] == 0.5
    assert m["accuracy"] == pytest.approx(3 / 6)  # nginx, make, main
    assert m["coverage"] == pytest.approx(4 / 6)
    assert m["unknown_recognised"] == 0.5
    assert m["confusion"]["background"]["latency-critical"] == 1
    assert m["calibration"]["ece"] is not None


def test_rejects_bad_labels(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text(json.dumps(rec(1, "web", "nginx")) + "\n")
    with pytest.raises(ValueError, match="unknown label 'web'"):
        evaluate.load(p)


def test_eval_set_is_built_from_build_py(tmp_path):
    # processes.jsonl is generated; editing it by hand would drift from build.py.
    before = EVAL.read_text()
    subprocess.run([sys.executable, str(ROOT / "eval" / "build.py")], check=True, capture_output=True)
    assert EVAL.read_text() == before, "eval/processes.jsonl is stale: run python3 eval/build.py"


def test_eval_set_leaks_no_secrets():
    text = EVAL.read_text()
    for secret in ("hunter2", "s3cret", "abc123"):
        assert secret not in text


def test_cli_eval_mock(capsys, tmp_path):
    out_json = tmp_path / "r.json"
    assert main(["eval", str(EVAL), "--errors", "--json", str(out_json)]) == 0
    out = capsys.readouterr().out
    assert "critical precision" in out and "wrong decisions:" in out
    data = json.loads(out_json.read_text())
    assert len(data["results"]) == len(evaluate.load(EVAL))
    assert main(["eval", str(EVAL), "--judgment", "only"]) == 0
    assert "judgment calls only" in capsys.readouterr().out
