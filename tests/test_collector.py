from iawp.collector import collect


def test_collects_fields(server_proc):
    by_pid = {r.pid: r for r in collect(server_proc)}
    nginx = by_pid[101]
    assert nginx.comm == "nginx"
    assert nginx.ppid == 100
    assert nginx.parent_comm == "nginx"
    assert nginx.uid == 33
    assert nginx.exe == "/usr/sbin/nginx"
    assert nginx.cgroup == "system.slice/nginx.service"
    assert nginx.cmdline == ("nginx: worker process",)
    assert not nginx.kernel_thread


def test_kernel_threads_and_missing_exe(server_proc):
    by_pid = {r.pid: r for r in collect(server_proc)}
    assert by_pid[2].kernel_thread and by_pid[3].kernel_thread
    assert not by_pid[1].kernel_thread
    assert by_pid[400].exe is None  # unreadable without root behaves like missing


def test_skips_non_numeric_and_vanished(server_proc):
    (server_proc / "999").mkdir()  # process exited: directory left without files
    pids = [r.pid for r in collect(server_proc)]
    assert 999 not in pids
    assert pids == sorted(pids)
