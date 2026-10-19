import os
import time

from iawp.classify.base import Classification
from iawp.classify.cache import Cache, CachedClassifier, normalise
from iawp.cli import main

from test_systemone import answer, server  # noqa: F401  (fixture)


class Counting:
    name = "fake"

    def __init__(self):
        self.calls = []

    def classify(self, state):
        self.calls.append(state)
        return Classification("batch-compute", {"batch-compute": 1.0}, 0.9, "fake-1.0")


def cached(tmp_path, identity="fake model=a", questions=None, ttl_days=30):
    inner = Counting()
    return inner, CachedClassifier(inner, Cache(tmp_path / "c.db", ttl_days), identity, questions or {"q": 1})


STATE = {"process_name": "make", "command_line": "make -j8", "cgroup": "user.slice/user-1000.slice/session-3.scope"}


def test_second_ask_is_a_hit(tmp_path):
    inner, c = cached(tmp_path)
    first, second = c.classify(STATE), c.classify(STATE)
    assert len(inner.calls) == 1 and (c.hits, c.misses) == (1, 1)
    assert first.cached_at is None and second.cached_at is not None
    assert second.model == "fake-1.0" and second.probabilities == first.probabilities


def test_survives_restart_and_ignores_session_numbers(tmp_path):
    cached(tmp_path)[1].classify(STATE)
    inner, c = cached(tmp_path)  # new process, same file
    c.classify({**STATE, "cgroup": "user.slice/user-1001.slice/session-87.scope"})
    assert inner.calls == []


def test_meaningful_differences_miss(tmp_path):
    inner, c = cached(tmp_path)
    c.classify({**STATE, "command_line": "python3 serve.py"})
    c.classify({**STATE, "command_line": "python3 train.py"})
    assert len(inner.calls) == 2


def test_new_questions_or_model_invalidate(tmp_path):
    cached(tmp_path)[1].classify(STATE)
    for kwargs in ({"questions": {"q": 2}}, {"identity": "fake model=b"}):
        inner, c = cached(tmp_path, **kwargs)
        c.classify(STATE)
        assert len(inner.calls) == 1, kwargs


def test_expired_entries_are_asked_again(tmp_path):
    cached(tmp_path)[1].classify(STATE)
    inner, c = cached(tmp_path, ttl_days=0)
    time.sleep(0.01)
    c.classify(STATE)
    assert len(inner.calls) == 1


def test_model_only_sees_normalised_state(tmp_path):
    inner, c = cached(tmp_path)
    c.classify({"cgroup": "system.slice/docker-" + "ab" * 32 + ".scope"})
    assert inner.calls == [{"cgroup": "system.slice/docker-<id>.scope"}]
    assert normalise({"x": "session-3.scope"}) == {"x": "session-N.scope"}


def test_file_is_private(tmp_path):
    cached(tmp_path)
    assert os.stat(tmp_path / "c.db").st_mode & 0o777 == 0o600


def test_cli_rescan_uses_cache(server, server_proc, private_cache, capsys):  # noqa: F811
    argv = ["scan", "--backend", "local", "--url", server.url, "--proc-root", str(server_proc)]
    assert main(argv) == 0
    asked = len(server.seen)
    assert f"0 hits, {asked} asked the model" in capsys.readouterr().out
    assert main(argv) == 0
    assert len(server.seen) == asked  # nothing sent the second time
    assert f"{asked} hits, 0 asked" in capsys.readouterr().out

    assert main(["cache", "stats"]) == 0
    assert f"{asked} answers" in capsys.readouterr().out
    assert private_cache.exists()
    assert main(["cache", "clear"]) == 0 and f"removed {asked}" in capsys.readouterr().out

    assert main([*argv, "--no-cache"]) == 0
    assert len(server.seen) == 2 * asked
