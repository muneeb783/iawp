import json

from iawp.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan(server_proc, capsys):
    code, out, _ = run(capsys, "scan", "--backend", "mock", "--proc-root", str(server_proc))
    assert code == 0
    assert "kworker" not in out  # kernel threads hidden by default
    nginx_line = next(l for l in out.splitlines() if l.startswith("101 "))
    assert "latency-critical" in nginx_line and "critical" in nginx_line
    assert "hunter2" not in out


def test_explain_shows_redacted_state(server_proc, capsys):
    code, out, _ = run(capsys, "explain", "700", "--backend", "mock", "--proc-root", str(server_proc))
    assert code == 0
    assert "hunter2" not in out and "abc" not in out
    assert "--db-password=<redacted>" in out
    assert "Decision: unknown -> layer default" in out


def test_explain_missing_pid(server_proc, capsys):
    code, _, err = run(capsys, "explain", "4242", "--backend", "mock", "--proc-root", str(server_proc))
    assert code == 1 and "no process" in err


def test_config_dry_run(server_proc, capsys, tmp_path):
    code, out, err = run(capsys, "config", "--dry-run", "--backend", "mock", "--proc-root", str(server_proc))
    assert code == 0
    assert json.loads(out)[-1]["name"] == "default"
    assert "pid 400 python3" in err  # unmatched processes are reported

    current = tmp_path / "current.json"
    current.write_text(out)
    code, out, _ = run(capsys, "config", "--dry-run", "--against", str(current), "--backend", "mock", "--proc-root", str(server_proc))
    assert out.startswith("no changes")


def test_config_requires_dry_run(server_proc, capsys):
    code, _, err = run(capsys, "config", "--backend", "mock", "--proc-root", str(server_proc))
    assert code == 2 and "--dry-run" in err
