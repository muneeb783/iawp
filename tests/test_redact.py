import pytest

from iawp.redact import MAX_ARG_LEN, MAX_ARGS, REDACTED, redact_args


@pytest.mark.parametrize("argv, expected", [
    (["app", "--password=hunter2"], ["app", f"--password={REDACTED}"]),
    (["app", "--db-password=hunter2"], ["app", f"--db-password={REDACTED}"]),
    (["app", "--token", "abc123"], ["app", "--token", REDACTED]),
    (["app", "-api-key", "abc"], ["app", "-api-key", REDACTED]),
    (["env", "PGPASSWORD=s3cret", "psql"], ["env", f"PGPASSWORD={REDACTED}", "psql"]),
    (["psql", "postgres://alice:s3cret@db:5432/app"], ["psql", f"postgres://alice:{REDACTED}@db:5432/app"]),
    (["curl", "https://x.io/a?token=abc&page=2"], ["curl", f"https://x.io/a?token={REDACTED}&page=2"]),
    (["curl", "-H", "Authorization: Bearer abc.def"], ["curl", "-H", f"Authorization: Bearer {REDACTED}"]),
    (["app", "--key", "AKIAIOSFODNN7EXAMPLE1234"], ["app", "--key", REDACTED]),
    (["app", "--id", "ghp_x7K2mQ9vR4tW8yZ1aB3cD5eF6gH0jL"], ["app", "--id", REDACTED]),  # prefixed token
    (["git", "checkout", "3f9c2a7be1d04c6a9f2b8e5d7c1a0b4e6f8d2c9a"], ["git", "checkout", REDACTED]),
])
def test_redacts_secrets(argv, expected):
    assert redact_args(argv) == expected


@pytest.mark.parametrize("argv", [
    ["/usr/lib/postgresql/16/bin/postgres", "-D", "/var/lib/postgresql/16/main"],
    ["python3", "serve.py", "--port", "8080"],
    ["/usr/lib/python3/dist-packages/supervisor/supervisord.py"],
    ["nginx: worker process"],
    ["/home/dev/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc"],
    ["cadvisor", "--housekeeping_interval=10s", "--max_housekeeping_interval=15s"],
])
def test_keeps_ordinary_args(argv):
    assert redact_args(argv) == argv


def test_limits_length():
    assert redact_args(["x" * 500])[0] == "x" * MAX_ARG_LEN + "…"
    out = redact_args([f"a{i}" for i in range(100)])
    assert len(out) == MAX_ARGS + 1 and out[-1] == f"<+{100 - MAX_ARGS} args>"
