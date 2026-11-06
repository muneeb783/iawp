import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bench_run", ROOT / "bench" / "run.py")
bench = importlib.util.module_from_spec(_spec)
sys.modules["bench_run"] = bench  # dataclasses look their module up here
_spec.loader.exec_module(bench)

WRK2 = """\
Running 30s test @ http://127.0.0.1/
  2 threads and 64 connections
  Thread calibration: mean lat.: 1.123ms, rate sampling interval: 10ms
  Thread calibration: mean lat.: 1.098ms, rate sampling interval: 10ms
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.05ms  512.33us   9.87ms   70.12%
    Req/Sec    10.55k     1.20k   14.44k    68.00%
  Latency Distribution (HdrHistogram - Recorded Latency)
 50.000%  980.00us
 75.000%    1.30ms
 90.000%    1.62ms
 99.000%    2.41ms
 99.900%    5.10ms
 99.990%    8.90ms
 99.999%    9.80ms
100.000%    9.87ms

  Detailed Percentile spectrum:
       Value   Percentile   TotalCount 1/(1-Percentile)

       0.120     0.000000            1         1.00
       0.980     0.500000       300000         2.00
#[Mean    =        1.050, StdDeviation   =        0.512]
#[Max     =        9.872, Total count    =       599990]
----------------------------------------------------------
  599990 requests in 30.00s, 487.13MB read
  Socket errors: connect 0, read 2, write 0, timeout 1
Requests/sec:  19999.31
Transfer/sec:     16.24MB
"""

STRESS = """\
stress-ng: info:  [2045] setting to a 42 secs run per stressor
stress-ng: metrc: [2045] stressor       bogo ops real time  usr time  sys time   bogo ops/s     bogo ops/s
stress-ng: metrc: [2045]                           (secs)    (secs)    (secs)   (real time) (usr+sys time)
stress-ng: metrc: [2045] cpu              169218     42.01    168.32      0.12      4028.04        1004.64
stress-ng: info:  [2045] successful run completed in 42.03 secs
"""


def test_parse_wrk2():
    r = bench.parse_wrk2(WRK2)
    assert r == {"p50": 0.98, "p99": 2.41, "p999": 5.1, "p9999": 8.9, "rps": 19999.31, "errors": 3}


def test_parse_wrk2_without_histogram_fails_loudly():
    with pytest.raises(bench.BenchError, match="--latency"):
        bench.parse_wrk2("Running 30s test\nRequests/sec: 10\n")


def test_parse_noise():
    assert bench.parse_stress(STRESS) == 4028.04
    assert bench.parse_builds("builds 14 in 42 s\n") == 20.0
    assert bench.parse_builds("") is None


def test_dry_run_order():
    lab = bench.DryLab(echo=False)
    b = bench.Bench(lab, bench.S1(rate=20000, ncpu=8), Path("/nonexistent"), "/opt/iawp", runs=2, cooldown=0)
    b.log = lambda m: lab.actions.append(f"# {m}")
    b.run_all()
    arms = [a.split()[1].split("=")[1] for a in lab.actions if a.startswith("# arm=")]
    assert arms == ["alone", "noise", "hand", "iawp"] * 2  # interleaved run by run

    def section(arm):
        start = lab.actions.index(f"# arm={arm} run=1/2")
        end = next(i for i in range(start + 1, len(lab.actions)) if lab.actions[i].startswith("# "))
        return lab.actions[start + 1:end]

    alone = section("alone")
    assert not any("stress-ng" in a or "scx_layered" in a for a in alone)
    hand = section("hand")
    sched = next(i for i, a in enumerate(hand) if "scx_layered" in a)
    stress = next(i for i, a in enumerate(hand) if "stress-ng" in a)
    load = next(i for i, a in enumerate(hand) if "wrk2" in a)
    assert sched < stress < load and "hand.config.json" in hand[sched]
    iawp = section("iawp")
    apply = next(i for i, a in enumerate(iawp) if a.startswith("run /opt/iawp apply --trust-critical --template "))
    assert next(i for i, a in enumerate(iawp) if "stress-ng" in a) < apply < next(i for i, a in enumerate(iawp) if "wrk2" in a)
    assert "run /opt/iawp stop" in iawp
    assert any("config --dry-run" in a for a in lab.actions[: lab.actions.index("# arm=alone run=1/2")])  # warm-up


def test_slow_setup_is_refused():
    class SlowApply(bench.DryLab):
        def run(self, cmd, log=None):
            if cmd[1:2] == ["apply"]:
                self.clock += 12
            return super().run(cmd, log)

    lab = SlowApply(echo=False)
    b = bench.Bench(lab, bench.S1(rate=1000, pre=10, ncpu=8), Path("/nonexistent"), "/opt/iawp", runs=1,
                    arms=("iawp",), cooldown=0, log=lambda m: None)
    with pytest.raises(bench.BenchError, match="raise --pre"):
        b.run_all()
    assert lab.actions[-1] == "run /opt/iawp stop" and lab.state == "disabled"  # cleaned up anyway


def test_summary_from_raw_files(tmp_path):
    for arm, p99s in {"noise": ["24.0ms", "40.0ms", "21.7ms"], "hand": ["5.2ms", "5.3ms", "5.1ms"]}.items():
        for n, p99 in enumerate(p99s, 1):
            (tmp_path / f"{arm}-{n}.load.txt").write_text(WRK2.replace(" 99.000%    2.41ms", f" 99.000%   {p99}"))
            (tmp_path / f"{arm}-{n}.stress.txt").write_text(STRESS)
            (tmp_path / f"{arm}-{n}.build.txt").write_text(f"builds {10 + n} in 42 s\n")
    table = bench.write_summary(tmp_path)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert list(summary) == ["noise", "hand"]  # arm order, not alphabetical
    assert summary["noise"]["p99"] == {"median": 24.0, "min": 21.7, "max": 40.0, "n": 3}
    assert summary["hand"]["errors"] == 9
    assert "24.00 [21.70..40.00]" in table and "request errors: noise 9, hand 9" in table


@pytest.mark.parametrize("template", sorted((ROOT / "bench" / "templates").glob("*.json")) + [bench.DEFAULT_TEMPLATE],
                         ids=lambda p: p.stem)
def test_hand_config_takes_the_template_policies(template):
    membership = ROOT / "bench" / "configs" / "s1-web-hand.json"
    policies = json.loads(template.read_text())
    hand = json.loads(bench.hand_config(membership, template))
    assert [layer["name"] for layer in hand] == ["critical", "batch", "default"]
    assert hand[0]["matches"] == [[{"PcommPrefix": "nginx"}]]
    for layer in hand:  # only membership differs between the hand and iawp arms
        assert layer["kind"] == policies[layer["name"]]


def test_cli_dry_run_passes_options_through(capsys, tmp_path):
    t = ROOT / "bench" / "templates" / "batch-slice-1ms.json"
    code = bench.main(["s1", "--rate", "20000", "--runs", "1", "--arms", "noise,iawp", "--template", str(t),
                       "--iawp", "/opt/iawp", "--out", str(tmp_path / "out"), "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "arm=noise run=1/1" in out and "arm=iawp run=1/1" in out and "arm=hand" not in out
    assert f"apply --trust-critical --template {t}" in out and "-R20000" in out


def test_chart_renders(tmp_path):
    pytest.importorskip("matplotlib")
    spec = importlib.util.spec_from_file_location("bench_chart", ROOT / "bench" / "chart.py")
    chart = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chart)
    stat = {"median": 2.0, "min": 1.9, "max": 2.2, "n": 2}
    (tmp_path / "summary.json").write_text(json.dumps({
        "alone": {"runs": 2, "errors": 0, "p50": stat, "p99": stat, "p999": stat},
        "iawp": {"runs": 2, "errors": 0, "p50": stat, "p99": stat, "p999": stat, "stress_ops": stat},
    }))
    assert chart.main([str(tmp_path)]) == 0
    assert (tmp_path / "chart.png").read_bytes()[:4] == b"\x89PNG"


def test_cli_noise_and_hand_config_options(capsys, tmp_path):
    client = ROOT / "bench" / "configs" / "s1-web-hand-client.json"
    code = bench.main(["s1", "--rate", "20000", "--runs", "1", "--arms", "noise,hand", "--noise", "stress",
                       "--hand-config", str(client), "--label", "x", "--iawp", "/opt/iawp", "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0 and "stress-ng" in out and "bash -c" not in out  # build loop left out
    with pytest.raises(SystemExit):
        bench.main(["s1", "--rate", "1", "--noise", "fans", "--dry-run"])
    assert "unknown noise sources: fans" in capsys.readouterr().err


def test_client_hand_config_protects_the_load_generator():
    hand = json.loads(bench.hand_config(ROOT / "bench" / "configs" / "s1-web-hand-client.json", bench.DEFAULT_TEMPLATE))
    assert {"PcommPrefix": "wrk"} in [m[0] for m in hand[0]["matches"]]
