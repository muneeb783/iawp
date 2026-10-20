"""Client for SystemOne-protocol decision models (Jev, JevOS, Laya, Clef...).

One request per process: the redacted state plus a `choice` question over
the taxonomy classes. A `noul` "is there enough information?" question was
dropped after evaluation: JevOS v5 scored known and unknowable processes
almost alike (0.37 vs 0.32), so it gated nothing, while class confidence is
well calibrated. Answers to it are still read if a server returns one.
The same code serves a model on this machine (`local`) or a hosted API
(`hosted`); only the base URL and the API key differ.

Standard library only, so iawp stays installable on a bare server.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from iawp.classify.base import Classification
from iawp.taxonomy import CLASSES

LOCAL_URL = "http://127.0.0.1:8017"  # JevOS default port
HOSTED_URL = "https://api.typesafe.ai"
# The protocol requires a model in every request; servers that host one model
# accept this alias. Pin an exact version (--model) for reproducible results.
DEFAULT_MODEL = "jev-latest"
API_KEY_ENV = "IAWP_API_KEY"  # never a flag: flags are readable by every user in /proc/<pid>/cmdline

WORKLOAD = "workload"
ENOUGH_INFO = "enough_info"

QUESTIONS = {
    WORKLOAD: {
        "type": "choice",
        "instructions": "What kind of workload is this Linux process? Judge by what the program is for, not by how busy it is right now.",
        "criteria": dict(CLASSES),  # fixed order: reordering options shifts the probabilities
    },
}


class ClassifierError(RuntimeError):
    """The model could not be reached or gave an unusable answer."""


class ServerUnreachable(ClassifierError):
    """Nothing answered at the server address."""


class SystemOneClassifier:
    def __init__(self, name: str, url: str, model: str | None = None, api_key: str | None = None,
                 timeout: float = 30.0):
        self.name = name
        self.endpoint = url.rstrip("/") + "/v1/systemone"
        self.model = model or DEFAULT_MODEL
        self.api_key = api_key
        self.timeout = timeout
        # What the cache keys on: a different server or model is a different classifier.
        self.identity = f"{name} {self.endpoint} model={self.model}"

    def classify(self, state: dict[str, str]) -> Classification:
        body = {"model": self.model, "state": format_state(state), "questions": QUESTIONS}
        return parse_response(self._post(body))

    def _post(self, body: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.endpoint, json.dumps(body).encode(), headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read(300).decode(errors="replace").strip()
            raise ClassifierError(f"{self.endpoint} answered HTTP {e.code}: {detail or e.reason}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            reason = getattr(e, "reason", e)
            raise ServerUnreachable(f"cannot reach a SystemOne server at {self.endpoint} ({reason})") from None
        except json.JSONDecodeError:
            raise ClassifierError(f"{self.endpoint} did not answer with JSON") from None


def format_state(state: dict[str, str]) -> str:
    """The text the model reads: the same lines `iawp explain` prints."""
    return "\n".join(f"{k}: {v}" for k, v in state.items())


def parse_response(resp: dict) -> Classification:
    answers = resp.get("answers")
    try:
        choice = answers[WORKLOAD]
        raw = choice["probabilities"]
        enough = float(answers[ENOUGH_INFO]["noul"]) if ENOUGH_INFO in answers else 1.0
    except (KeyError, TypeError, ValueError):
        raise ClassifierError(f"unexpected answer shape: {json.dumps(resp)[:300]}") from None

    # Keep only our classes, in our order, and renormalise: servers differ in
    # rounding and some return labels we did not offer.
    probs = {c: max(0.0, float(raw.get(c, 0.0))) for c in CLASSES}
    total = sum(probs.values())
    if total <= 0:
        raise ClassifierError(f"no probability for any known class: {json.dumps(raw)[:300]}")
    probs = {c: p / total for c, p in probs.items()}
    return Classification(max(probs, key=probs.get), probs, enough, str(resp.get("model", "unknown")))


def local(url: str | None = None, model: str | None = None) -> SystemOneClassifier:
    return SystemOneClassifier("local", url or LOCAL_URL, model)


def hosted(url: str | None = None, model: str | None = None) -> SystemOneClassifier:
    key = os.environ.get(API_KEY_ENV)
    if not key:
        raise ClassifierError(f"the hosted backend needs an API key in the {API_KEY_ENV} environment variable")
    return SystemOneClassifier("hosted", url or HOSTED_URL, model, key)
