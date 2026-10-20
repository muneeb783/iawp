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


def test_longer_name_rule_folds_into_shorter(server_proc):
    # Seen on the lab VM: stress-ng forks workers named stress-ng-cpu.
    make_proc(server_proc, 900, "stress-ng", ["stress-ng", "--cpu", "8"], uid=1000, cgroup=SESSION)
    make_proc(server_proc, 901, "stress-ng-cpu", ["stress-ng-cpu"], ppid=900, uid=1000, cgroup=SESSION,
              exe="/usr/bin/stress-ng")
    rules, _ = plan_rules(placed(server_proc))
    stress = [r for r in rules if r.value.startswith("stress-ng")]
    assert [(r.value, r.pids) for r in stress] == [("stress-ng", (900, 901))]


PG = "system.slice/postgresql@16-main.service"


def with_decisions(ps, **by_pid):
    """Override decisions: with_decisions(ps, p201=("background", "batch"))."""
    out = []
    for p in ps:
        if (key := f"p{p.record.pid}") in by_pid:
            cls, layer = by_pid[key]
            p = Placed(p.record, Decision(cls, layer, "test"))
        out.append(p)
    return out


def test_helpers_follow_their_service(server_proc):
    # The eval's harmful case p182: autovacuum shares the database's name and cgroup.
    make_proc(server_proc, 201, "postgres", ["postgres: 16/main: autovacuum launcher"], ppid=200, uid=111, cgroup=PG)
    ps = with_decisions(placed(server_proc), p201=("background", "batch"))
    rules, unmatched = plan_rules(ps)
    pg = next(r for r in rules if r.value == PG + "/")
    assert pg.layer == "critical" and pg.pids == (200, 201)
    assert "main process postgres (pid 200) is latency-critical" in pg.note
    assert "201 postgres (background)" in pg.note
    assert not any(u.placed.record.pid == 201 for u in unmatched)


def test_helper_cannot_promote_its_service(server_proc):
    cron = "system.slice/cron.service"
    make_proc(server_proc, 601, "nginx", ["nginx: worker process"], ppid=600, cgroup=cron)  # odd job under cron
    rules, _ = plan_rules(placed(server_proc))
    svc = next(r for r in rules if r.value == cron + "/")
    assert svc.layer == "batch" and 601 in svc.pids


def test_unknown_main_uses_agreeing_members(server_proc):
    job = "system.slice/nightly-build.service"
    make_proc(server_proc, 900, "sh", ["/bin/sh", "-c", "/opt/build.sh"], cgroup=job)
    make_proc(server_proc, 901, "make", ["make", "-j8"], ppid=900, cgroup=job)
    make_proc(server_proc, 902, "cc1", ["cc1", "x.c"], ppid=901, cgroup=job)
    rules, _ = plan_rules(placed(server_proc))
    svc = next(r for r in rules if r.value == job + "/")
    assert svc.layer == "batch" and svc.pids == (900, 901, 902)
    assert "main process sh (pid 900) is interactive; every other decided member is batch" in svc.note


def test_unknown_main_and_disagreeing_members_stay_default(server_proc):
    job = "system.slice/mixed.service"
    make_proc(server_proc, 900, "sh", ["/bin/sh", "-c", "run"], cgroup=job)
    make_proc(server_proc, 901, "make", ["make"], ppid=900, cgroup=job)
    make_proc(server_proc, 902, "redis-server", ["redis-server"], ppid=900, cgroup=job)
    rules, unmatched = plan_rules(placed(server_proc))
    assert not any(r.value == job + "/" for r in rules)
    reasons = {u.placed.record.pid: u.reason for u in unmatched}
    assert "members disagree (batch, critical)" in reasons[902]
    # make's name rule would now capture pid 901, which stays in default with its service.
    assert ("batch", "PcommPrefix", "make") not in as_set(rules)


def test_name_rule_checks_effective_layer(server_proc):
    # A session `postgres` (critical) would also capture the service's helper; that helper's
    # effective layer is critical too (it follows its service), so the name rule is safe.
    make_proc(server_proc, 201, "postgres", ["postgres: 16/main: autovacuum launcher"], ppid=200, uid=111, cgroup=PG)
    make_proc(server_proc, 800, "postgres", ["postgres", "-D", "/tmp/dev"], uid=1000, cgroup=SESSION)
    ps = with_decisions(placed(server_proc), p201=("background", "batch"))
    rules, unmatched = plan_rules(ps)
    assert ("critical", "PcommPrefix", "postgres") in as_set(rules)


def test_workers_cannot_make_a_service_critical(server_proc):
    job = "system.slice/wrapped.service"
    make_proc(server_proc, 900, "sh", ["/bin/sh", "-c", "exec-servers"], cgroup=job)
    make_proc(server_proc, 901, "redis-server", ["redis-server"], ppid=900, cgroup=job)
    rules, unmatched = plan_rules(placed(server_proc))
    assert not any(r.value == job + "/" for r in rules)
    assert "only a main process can make a service critical" in next(
        u.reason for u in unmatched if u.placed.record.pid == 901)
