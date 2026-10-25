import struct

import pytest
from conftest import SESSION, make_proc
from test_apply import FakeHost

from iawp import apply as ap
from iawp import cli
from iawp import watch as w
from iawp.classify import ClassifierError
from iawp.collector import collect
from iawp.emit import Rule


def kernel_event(what, tgid, pid=None):
    """One netlink message as the process connector sends it."""
    event = struct.pack("=IIQii", what, 3, 123456789, pid or tgid, tgid) + b"\0" * 16  # comm[16] for COMM events
    cn = struct.pack("=IIIIHH", w.CN_IDX_PROC, w.CN_VAL_PROC, 7, 0, len(event), 0)
    size = 16 + len(cn) + len(event)
    return struct.pack("=IHHII", size, w.NLMSG_DONE, 0, 7, 0) + cn + event + b"\0" * (-size % 4)


def test_parse_events():
    fork = 0x00000001
    data = kernel_event(w.PROC_EVENT_EXEC, 4242) + kernel_event(fork, 9) + kernel_event(w.PROC_EVENT_COMM, 77, pid=78)
    assert w.parse_events(data) == [4242, 77]  # forks ignored; a renamed thread reports its process
    assert w.parse_events(data[:20]) == []  # truncated read
    assert w.parse_events(struct.pack("=IHHII", 0, 0, 0, 0, 0)) == []  # malformed length must not loop


def test_subscribe_message():
    msg = w.subscribe_message(99)
    size, kind, _, _, pid = struct.unpack_from("=IHHII", msg)
    idx, val, _, _, length, _ = struct.unpack_from("=IIIIHH", msg, 16)
    assert (size, kind, pid) == (len(msg), w.NLMSG_DONE, 99)
    assert (idx, val, length) == (1, 1, 4) and struct.unpack_from("=I", msg, 36) == (w.PROC_CN_MCAST_LISTEN,)


def test_poller_reports_new_pids(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    make_proc(root, 10, "a")
    poller = w.ProcPoller(root, sleep=lambda s: None)
    assert poller.wait(1) == []
    make_proc(root, 11, "b")
    make_proc(root, 12, "c")
    assert poller.wait(1) == [11, 12]
    assert poller.wait(1) == []


class Scripted:
    """A scan whose result the test sets: processes in a fake /proc, rules by hand."""

    def __init__(self, root):
        self.root, self.rules, self.held, self.calls, self.fail = root, [], [], 0, False

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise ClassifierError("model server down")
        return w.Snapshot(list(self.rules), list(self.held), [p for p in collect(self.root) if not p.kernel_thread])


@pytest.fixture
def rig(tmp_path):
    host = FakeHost(tmp_path / "host")
    make_proc(host.proc_root, 1, "systemd", ["/sbin/init"], ppid=0, cgroup="init.scope")
    make_proc(host.proc_root, 500, "make", ["make", "-j8"], cgroup=SESSION)
    scan = Scripted(host.proc_root)
    scan.rules = [Rule("batch", "PcommPrefix", "make", (500,))]
    logs = []
    watcher = w.Watcher(host, scan, w.Timing(settle=2, cooldown=120, sticky=3600, rescan=300), log=logs.append)
    return host, scan, watcher, logs


def test_first_step_applies_and_repeats_do_not_restart(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    assert host.restarts() == 1 and '"make"' in host.current.read_text()
    watcher.step(300)  # periodic rescan, nothing new
    assert scan.calls == 2 and host.restarts() == 1


def test_known_programs_do_not_rescan(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    make_proc(host.proc_root, 501, "make", ["make", "-C", "lib"], cgroup=SESSION)  # same kind: scx_layered handles it
    watcher.notice(10, 501)
    watcher.notice(10, 999)  # exited before we could read it
    assert watcher.dirty_since is None and watcher.due() == 300


def test_new_program_waits_to_settle_then_cooldown(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    make_proc(host.proc_root, 600, "cc1", ["cc1", "main.c"], cgroup=SESSION)
    scan.rules.append(Rule("batch", "PcommPrefix", "cc1", (600,)))
    watcher.notice(10, 600)
    assert watcher.due() == 12
    watcher.step(11)
    assert scan.calls == 1  # still settling
    watcher.step(12)
    assert scan.calls == 2 and host.restarts() == 1  # changed, but the last restart was at 0
    assert "applying in 108 s" in logs[-1] and watcher.due() == 120
    watcher.step(120)
    assert host.restarts() == 2 and '"cc1"' in host.current.read_text()
    assert logs[-1].endswith("(+batch PcommPrefix cc1)")


def test_rules_outlive_their_processes_for_a_while(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    (host.proc_root / "500" / "status").unlink()
    (host.proc_root / "500").rename(host.proc_root / "gone")  # make exits
    scan.rules = []
    watcher.step(300)
    assert host.restarts() == 1  # still in the config, so no restart
    watcher.step(3600)
    assert host.restarts() == 1
    watcher.step(3900)  # an hour after it was last seen
    assert host.restarts() == 2 and '"make"' not in host.current.read_text()
    assert logs[-1].endswith("(-batch PcommPrefix make)")


def test_sticky_rule_dropped_when_a_live_process_no_longer_fits(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    scan.rules = []  # make is still running, but the plan dropped its rule (e.g. now a name conflict)
    watcher.step(300)
    assert host.restarts() == 2 and '"make"' not in host.current.read_text()


def test_held_critical_is_logged_once_and_shown_in_status(rig):
    host, scan, watcher, logs = rig
    scan.held = ['{"PcommPrefix": "nginx"}']
    watcher.step(0)
    watcher.step(300)
    assert sum("held back" in m for m in logs) == 1
    assert 'pending:     1 critical placements need approval' in ap.status(host)
    scan.held = []  # approved with `iawp apply`
    watcher.step(600)
    assert "pending" not in ap.status(host)


def test_failures_are_logged_and_watching_continues(rig):
    host, scan, watcher, logs = rig
    scan.fail = True
    watcher.step(0)
    assert "classifier failed" in logs[-1] and host.restarts() == 0
    scan.fail = False
    make_proc(host.proc_root, 700, "BADd", ["BADd"], cgroup=SESSION)
    scan.rules = [Rule("batch", "PcommPrefix", "make", (500,)), Rule("batch", "PcommPrefix", "BAD", (700,))]
    watcher.step(300)
    assert "apply failed: scx_layered rejected" in logs[-1]
    scan.rules = scan.rules[:1]
    watcher.step(600)
    assert host.restarts() == 1


def test_restarts_scx_layered_if_it_went_away(rig):
    host, scan, watcher, logs = rig
    watcher.step(0)
    host.active = False
    host.set_sched("disabled", "")  # crashed past systemd's restart limit
    watcher.step(300)
    assert host.restarts() == 2 and ap.sched_state(host).layered


def test_cli_watch_once(monkeypatch, capsys, tmp_path, server_proc):
    host = FakeHost(tmp_path / "host")
    monkeypatch.setattr(cli, "_host", lambda args: host)
    code = cli.main(["watch", "--once", "--backend", "mock", "--proc-root", str(server_proc)])
    out = capsys.readouterr().out
    assert code == 0 and "applied" in out and "held back" in out
    applied = host.current.read_text()
    assert '"PcommPrefix": "make"' in applied and '"critical"' not in applied
    assert "pending:" in ap.status(host)
