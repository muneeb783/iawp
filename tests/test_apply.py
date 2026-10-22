import os
import subprocess

import pytest

from iawp import apply as ap
from iawp import cli
from iawp.emit import Rule

SCX = "/usr/local/bin/scx_layered"


class FakeHost(ap.Host):
    """A pretend machine: systemctl flips a fake sched_ext sysfs.

    A config containing BAD fails validation; one containing NOSTART passes
    validation but scx_layered dies on start.
    """

    def __init__(self, tmp):
        tmp.mkdir()
        super().__init__(state_dir=tmp / "state", sched_ext=tmp / "sys", unit_dir=tmp / "units",
                         proc_root=tmp / "proc", settle_seconds=1.0)
        self.sched_ext.mkdir()
        self.unit_dir.mkdir()
        self.proc_root.mkdir()
        self.set_sched("disabled", "")
        self.active = False
        self.loaded = False  # systemd has not started the unit yet
        self.root = True
        self.calls = []
        self.clock = 1_760_000_000.0

    def set_sched(self, state, ops):
        (self.sched_ext / "state").write_text(state + "\n")
        (self.sched_ext / "root").mkdir(exist_ok=True)
        ops_file = self.sched_ext / "root" / "ops"
        if ops:
            ops_file.write_text(ops + "\n")
        elif ops_file.exists():
            ops_file.unlink()

    def run(self, *cmd):
        self.calls.append(cmd)
        ok = subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == SCX and cmd[1] == "--print-and-exit":
            text = open(cmd[2][2:]).read()
            return subprocess.CompletedProcess(cmd, 1, "", "parse error") if "BAD" in text else ok
        if cmd[:2] == ("systemctl", "reset-failed") and not self.loaded:
            return subprocess.CompletedProcess(cmd, 1, "", f"Unit {cmd[2]} not loaded.")  # as real systemd does
        if cmd[:2] == ("systemctl", "restart"):
            self.loaded = True
            if "NOSTART" in self.current.read_text():
                self.active = False
                self.set_sched("disabled", "")
                return subprocess.CompletedProcess(cmd, 1, "", "Job failed")
            else:
                self.active = True
                self.set_sched("enabled", "layered_1.1.3_x86_64")
            return ok
        if cmd[:2] == ("systemctl", "stop"):
            self.active = False
            self.set_sched("disabled", "")
            return ok
        if cmd[:2] == ("systemctl", "is-active"):
            return subprocess.CompletedProcess(cmd, 0 if self.active else 3, "", "")
        if cmd[0] == "journalctl":
            return subprocess.CompletedProcess(cmd, 0, "scx_layered: boom", "")
        return ok

    def which(self, name):
        return {"scx_layered": SCX, "systemctl": "/usr/bin/systemctl"}.get(name)

    def is_root(self):
        return self.root

    def sleep(self, seconds):
        pass

    def now(self):
        self.clock += 1
        return self.clock

    def restarts(self):
        return sum(1 for c in self.calls if c[:2] == ("systemctl", "restart"))


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path / "host")


def test_preflight_refusals(host, tmp_path):
    host.root = False
    with pytest.raises(ap.ApplyError, match="needs root"):
        ap.preflight(host)
    host.root = True
    host.set_sched("enabled", "lavd_1.1.3")  # someone else's scheduler, not our unit
    with pytest.raises(ap.ApplyError, match="another sched_ext scheduler is loaded \\(lavd"):
        ap.preflight(host)
    (host.sched_ext / "state").unlink()
    with pytest.raises(ap.ApplyError, match="no sched_ext"):
        ap.preflight(host)


def test_first_apply_writes_unit_and_starts(host):
    out = ap.apply(host, "config one\n")
    assert out.startswith("applied ")
    assert ap.sched_state(host).layered and host.active
    assert host.current.is_symlink() and host.current.read_text() == "config one\n"
    unit = host.unit_path.read_text()
    assert f"ExecStart={SCX} f:{host.current}" in unit and "[Install]" not in unit  # not started at boot
    assert ("systemctl", "daemon-reload") in host.calls


def test_unchanged_config_does_not_restart(host):
    ap.apply(host, "config one\n")
    before = host.restarts()
    assert ap.apply(host, "config one\n").startswith("no changes")
    assert host.restarts() == before


def test_invalid_config_never_reaches_the_kernel(host):
    ap.apply(host, "config one\n")
    with pytest.raises(ap.ApplyError, match="rejected the generated config:\nparse error"):
        ap.apply(host, "BAD config\n")
    assert host.current.read_text() == "config one\n"
    assert host.restarts() == 1 and len(ap.history(host)) == 1


def test_failed_start_rolls_back(host):
    ap.apply(host, "config one\n")
    with pytest.raises(ap.ApplyError, match="rolled back to .*\n.*boom"):
        ap.apply(host, "NOSTART config two\n")
    assert host.current.read_text() == "config one\n"
    assert ap.sched_state(host).layered
    assert len(ap.history(host)) == 1  # the config that never ran is not kept


def test_failed_first_start_stops(host):
    with pytest.raises(ap.ApplyError, match="stopped it, so the kernel uses its default scheduler"):
        ap.apply(host, "NOSTART config\n")
    assert not host.active
    assert ap.history(host) == [] and not host.current.is_symlink()
    assert "(none applied yet)" in ap.status(host)


def test_rollback_walks_history(host):
    with pytest.raises(ap.ApplyError, match="no earlier config"):
        ap.rollback(host)
    ap.apply(host, "config one\n")
    ap.apply(host, "config two\n")
    ap.apply(host, "config three\n")
    ap.rollback(host)
    assert host.current.read_text() == "config two\n"
    ap.rollback(host)
    assert host.current.read_text() == "config one\n"
    with pytest.raises(ap.ApplyError, match="no earlier config"):
        ap.rollback(host)


def test_history_order_and_pruning(host):
    host.now = lambda: 1_760_000_000.0  # every save in the same second
    for i in range(ap.KEEP_CONFIGS + 5):
        ap.apply(host, f"config {i}\n")
    names = [p.name for p in ap.history(host)]
    assert len(names) == ap.KEEP_CONFIGS
    assert [p.read_text() for p in ap.history(host)][-1] == f"config {ap.KEEP_CONFIGS + 4}\n"
    assert names == sorted(names)


def test_rollback_through_symlinked_state_dir(tmp_path):
    real = FakeHost(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real.state_dir.parent)
    real.state_dir = link / "state"  # e.g. /var/lib -> /data/lib
    ap.apply(real, "config one\n")
    ap.apply(real, "config two\n")
    ap.rollback(real)
    assert real.current.read_text() == "config one\n"


def test_stop_and_status(host):
    ap.apply(host, "config one\n")
    assert "enabled (layered_1.1.3_x86_64)" in ap.status(host)
    assert "default scheduler" in ap.stop(host)
    assert "sched_ext:   disabled" in ap.status(host)


def test_approvals_survive_renames(host, tmp_path):
    prog = tmp_path / "bin" / "schbench"
    prog.parent.mkdir()
    prog.write_bytes(b"\x7fELF fake program")
    for pid in (10, 11):
        (host.proc_root / str(pid)).mkdir()
        os.symlink(prog, host.proc_root / str(pid) / "exe")
    original = Rule("critical", "PcommPrefix", "schbench", (10,))
    renamed = Rule("critical", "PcommPrefix", "schbench-v2", (11,))

    approvals = ap.Approvals()
    hashes = ap.exe_hashes(host, original.pids)
    assert len(hashes) == 1
    approvals.approve(original, hashes, "schbench", host.now())
    approvals.save(host)

    loaded = ap.Approvals.load(host)
    assert loaded.covers(renamed, ap.exe_hashes(host, renamed.pids))  # same file, new name
    other = Rule("critical", "PcommPrefix", "other", (99,))
    assert not loaded.covers(other, ap.exe_hashes(host, other.pids))  # unreadable exe -> no hash match


def run_apply(monkeypatch, capsys, host, server_proc, *extra, tty=False, answer="n"):
    monkeypatch.setattr(cli, "_host", lambda args: host)
    monkeypatch.setattr("sys.stdin.isatty", lambda: tty)
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    code = cli.main(["apply", "--backend", "mock", "--proc-root", str(server_proc), *extra])
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_holds_back_critical_without_approval(monkeypatch, capsys, host, server_proc):
    code, out, err = run_apply(monkeypatch, capsys, host, server_proc)
    assert code == 0 and "held back" in err
    applied = host.current.read_text()
    assert '"critical"' not in applied and '"PcommPrefix": "make"' in applied  # batch still applied


def test_cli_approval_is_remembered(monkeypatch, capsys, host, server_proc):
    code, out, _ = run_apply(monkeypatch, capsys, host, server_proc, tty=True, answer="y")
    assert code == 0 and "wants" in out and '"critical"' in host.current.read_text()
    # Next run, no terminal: the stored approval is enough.
    code, out, err = run_apply(monkeypatch, capsys, host, server_proc)
    assert "held back" not in err and out.startswith("no changes")


def test_cli_trust_critical(monkeypatch, capsys, host, server_proc):
    code, _, err = run_apply(monkeypatch, capsys, host, server_proc, "--trust-critical")
    assert code == 0 and "--trust-critical" in err and '"critical"' in host.current.read_text()
    assert not (host.state_dir / "approvals.json").exists()  # trusting is not approving


def test_cli_refuses_before_classifying(monkeypatch, capsys, host, server_proc):
    host.root = False
    code, _, err = run_apply(monkeypatch, capsys, host, server_proc)
    assert code == 1 and "needs root" in err
