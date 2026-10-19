import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from iawp.classify.systemone import ClassifierError, SystemOneClassifier, hosted, local, parse_response
from iawp.cli import main
from iawp.taxonomy import CLASSES


def answer(probs, enough=0.9, model="test-model-1.0"):
    return {"model": model, "answers": {
        "workload": {"choice": max(probs, key=probs.get), "confidence": max(probs.values()), "probabilities": probs},
        "enough_info": {"noul": enough},
    }}


@pytest.fixture
def server():
    """A fake SystemOne server. Set `.reply(body) -> (status, payload)`; requests land in `.seen`."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, dict(self.headers), body))
            status, payload = httpd.reply(body)
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    httpd.reply = lambda body: (200, answer({"latency-critical": 0.95, "batch-compute": 0.05}))
    httpd.seen = seen
    httpd.url = f"http://127.0.0.1:{httpd.server_port}"
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


STATE = {"process_name": "nginx", "executable": "/usr/sbin/nginx", "command_line": "nginx: worker process"}


def test_request_shape(server):
    local(server.url, model="m-1").classify(STATE)
    path, headers, body = server.seen[0]
    assert path == "/v1/systemone"
    assert "Authorization" not in headers  # local never sends a key
    assert body["model"] == "m-1"
    assert body["state"] == "process_name: nginx\nexecutable: /usr/sbin/nginx\ncommand_line: nginx: worker process"
    q = body["questions"]
    assert q["workload"]["type"] == "choice"
    assert list(q["workload"]["criteria"]) == list(CLASSES)  # same options, same order, every time
    assert q["enough_info"]["type"] == "noul"


def test_parses_and_normalises():
    c = parse_response(answer({"latency-critical": 0.6, "interactive": 0.2, "not-a-class": 0.5}, 0.8, "jev-1.13.0"))
    assert c.cls == "latency-critical" and c.model == "jev-1.13.0" and c.enough_info == 0.8
    assert list(c.probabilities) == list(CLASSES)
    assert c.probabilities["latency-critical"] == pytest.approx(0.75)
    assert sum(c.probabilities.values()) == pytest.approx(1.0)


@pytest.mark.parametrize("payload", [{}, {"answers": {"workload": {}}}, answer({"x": 1.0})])
def test_rejects_unusable_answers(payload):
    with pytest.raises(ClassifierError):
        parse_response(payload)


def test_http_and_connection_errors(server):
    server.reply = lambda body: (500, b"model not loaded")
    with pytest.raises(ClassifierError, match="HTTP 500: model not loaded"):
        local(server.url).classify(STATE)
    server.reply = lambda body: (200, b"<html>")
    with pytest.raises(ClassifierError, match="not answer with JSON"):
        local(server.url).classify(STATE)
    with pytest.raises(ClassifierError, match="cannot reach"):
        SystemOneClassifier("local", "http://127.0.0.1:9", timeout=2).classify(STATE)


def test_hosted_needs_key_and_sends_it(server, monkeypatch):
    monkeypatch.delenv("IAWP_API_KEY", raising=False)
    with pytest.raises(ClassifierError, match="IAWP_API_KEY"):
        hosted(server.url)
    monkeypatch.setenv("IAWP_API_KEY", "k-123")
    hosted(server.url).classify(STATE)
    _, headers, body = server.seen[0]
    assert headers["Authorization"] == "Bearer k-123"
    assert body["model"] == "jev-latest"


def test_cli_with_local_backend(server, server_proc, capsys):
    def reply(body):
        name = body["state"].splitlines()[0]
        if name.endswith("make") or name.endswith("cc1"):
            return 200, answer({"batch-compute": 0.9, "interactive": 0.1})
        return 200, answer({"latency-critical": 0.95, "background": 0.05}, enough=0.3 if "zxqd" in name else 0.9)
    server.reply = reply

    assert main(["config", "--dry-run", "--backend", "local", "--url", server.url, "--proc-root", str(server_proc)]) == 0
    layers = json.loads(capsys.readouterr().out)
    assert {"PcommPrefix": "make"} in [m[0] for m in layers[1]["matches"]]
    assert not any("zxq" in json.dumps(l) for l in layers)  # not enough information -> default
    # nginx master and worker differ (cmdline), so 2 requests; no request repeats an identical state.
    states = [b["state"] for _, _, b in server.seen]
    assert len(states) == len(set(states))
    assert all("hunter2" not in s for s in states)  # redaction happens before anything is sent


def test_cli_reports_unreachable_server(server_proc, capsys):
    code = main(["scan", "--backend", "local", "--url", "http://127.0.0.1:9", "--proc-root", str(server_proc)])
    err = capsys.readouterr().err
    assert code == 1 and "cannot reach" in err and "--backend mock" in err
