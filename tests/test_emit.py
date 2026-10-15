import json
import random

from iawp.classify import build_state
from iawp.classify.mock import MockClassifier
from iawp.collector import collect
from iawp.emit import Placed, build_config, plan_rules, render
from iawp.policy import Decision, Thresholds, decide

from conftest import SESSION, make_proc


def placed(proc_root):
    mock = MockClassifier()
    return [Placed(r, decide(mock.classify(build_state(r)))) for r in collect(proc_root)]


def as_set(rules):
    return {(r.layer, r.kind, r.value) for r in rules}


def test_rules_for_server(server_proc):
    rules, unmatched = plan_rules(placed(server_proc))
    assert as_set(rules) == {
        ("critical", "CgroupPrefix", "system.slice/nginx.service/"),
        ("critical", "CgroupPrefix", "system.slice/postgresql@16-main.service/"),
        ("batch", "PcommPrefix", "make"),
        ("batch", "PcommPrefix", "cc1"),
        ("batch", "CgroupPrefix", "system.slice/cron.service/"),
    }
    nginx = next(r for r in rules if r.value.startswith("system.slice/nginx"))
    assert nginx.pids == (100, 101)
    # python3 serve.py / train.py were classified, but scx_layered can't tell them apart by name.
    reasons = {u.placed.record.pid: u.reason for u in unmatched}
    assert set(reasons) == {400, 401}
    assert "shared by unrelated workloads" in reasons[400]


def test_conflicting_name_is_not_emitted(server_proc):
    # A monitoring sidecar whose name starts with "postgres" would be pulled into
    # critical by PcommPrefix "postgres", so no name rule may be emitted.
    make_proc(server_proc, 800, "postgres", ["postgres"], uid=1000, cgroup=SESSION)
    make_proc(server_proc, 801, "postgres_export", ["postgres_exporter"], uid=1000, cgroup=SESSION)
    ps = placed(server_proc)
    ps = [p if p.record.pid != 801 else Placed(p.record, Decision("background", "batch", "test")) for p in ps]
    rules, unmatched = plan_rules(ps)
    assert ("critical", "PcommPrefix", "postgres") not in as_set(rules)
    assert any(u.placed.record.pid == 800 and "pid 801" in u.reason for u in unmatched)


def test_unknown_and_kernel_threads_get_no_rules(server_proc):
    rules, _ = plan_rules(placed(server_proc))
    captured = {pid for r in rules for pid in r.pids}
    assert not captured & {2, 3, 700}  # kernel threads, unknown zxqd


def test_config_shape_and_determinism(server_proc):
    ps = placed(server_proc)
    rules, _ = plan_rules(ps)
    text = render(build_config(rules))
    layers = json.loads(text)
    assert [l["name"] for l in layers] == ["critical", "batch", "default"]
    assert layers[-1]["matches"] == [[]]  # catch-all must be last
    assert layers[0]["kind"] == {"Open": {"preempt": True, "weight": 1000}}

    random.Random(0).shuffle(ps)
    assert render(build_config(plan_rules(ps)[0])) == text


def test_strict_threshold_empties_critical(server_proc):
    mock = MockClassifier()
    strict = Thresholds(critical=0.99)
    ps = [Placed(r, decide(mock.classify(build_state(r)), strict)) for r in collect(server_proc)]
    layers = json.loads(render(build_config(plan_rules(ps)[0])))
    assert "critical" not in [l["name"] for l in layers]
