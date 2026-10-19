import os
from pathlib import Path

import pytest

SESSION = "user.slice/user-1000.slice/session-3.scope"


@pytest.fixture(autouse=True)
def private_cache(tmp_path, monkeypatch):
    """Keep every test's answer cache out of the real ~/.cache."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    return tmp_path / "xdg-cache" / "iawp" / "classify.db"


def make_proc(root: Path, pid: int, comm: str, cmdline=(), ppid=1, uid=0, cgroup="", exe=None):
    """Write the /proc/<pid> files the collector reads."""
    d = root / str(pid)
    d.mkdir()
    (d / "status").write_text(f"Name:\t{comm}\nState:\tS (sleeping)\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (d / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in cmdline))
    (d / "cgroup").write_text(f"0::/{cgroup}\n")
    if exe:
        os.symlink(exe, d / "exe")
    return d


@pytest.fixture
def server_proc(tmp_path: Path) -> Path:
    """A small server: services in their own cgroups, a build and scripts in a login session."""
    root = tmp_path / "proc"
    root.mkdir()
    (root / "self").mkdir()  # non-numeric entries must be ignored
    make_proc(root, 1, "systemd", ["/sbin/init"], ppid=0, cgroup="init.scope", exe="/usr/lib/systemd/systemd")
    make_proc(root, 2, "kthreadd", ppid=0)
    make_proc(root, 3, "kworker/0:1", ppid=2)
    make_proc(root, 100, "nginx", ["nginx: master process /usr/sbin/nginx"], cgroup="system.slice/nginx.service", exe="/usr/sbin/nginx")
    make_proc(root, 101, "nginx", ["nginx: worker process"], ppid=100, uid=33, cgroup="system.slice/nginx.service", exe="/usr/sbin/nginx")
    make_proc(root, 200, "postgres", ["/usr/lib/postgresql/16/bin/postgres", "-D", "/var/lib/postgresql/16/main"],
              uid=111, cgroup="system.slice/postgresql@16-main.service")
    make_proc(root, 300, "bash", ["-bash"], uid=1000, cgroup=SESSION)
    make_proc(root, 400, "python3", ["python3", "serve.py", "--port", "8080"], ppid=300, uid=1000, cgroup=SESSION)
    make_proc(root, 401, "python3", ["python3", "train.py", "--epochs", "10"], ppid=300, uid=1000, cgroup=SESSION)
    make_proc(root, 500, "make", ["make", "-j8"], ppid=300, uid=1000, cgroup=SESSION)
    make_proc(root, 501, "cc1", ["/usr/libexec/gcc/x86_64-linux-gnu/14/cc1", "-quiet", "main.c"], ppid=500, uid=1000, cgroup=SESSION)
    make_proc(root, 600, "cron", ["/usr/sbin/cron", "-f"], cgroup="system.slice/cron.service")
    make_proc(root, 700, "zxqd", ["/opt/zxq/bin/zxqd", "--db-password=hunter2", "--token", "abc"], cgroup="system.slice/zxq.service")
    return root
