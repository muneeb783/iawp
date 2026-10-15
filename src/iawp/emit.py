"""Generate an scx_layered config from placement decisions.

The hard part is not the JSON, it is choosing a match rule that selects
exactly the processes we mean. scx_layered matches on kernel-visible facts
(comm prefix, cgroup path, uid, ...), not on command lines, so `python
serve.py` and `python train.py` look identical to it by name. Rules:

1. Prefer the process's cgroup when it is dedicated to one service or
   container (system.slice/nginx.service, docker-<id>.scope, kubepods...).
2. Otherwise use its name (PcommPrefix), unless the name is a generic
   interpreter or wrapper that many unrelated workloads share.
3. Only emit a rule if every currently running process it would capture was
   placed in the same layer. Otherwise leave it out and report why.

Anything without a safe rule stays in the default layer, which is always last.
Output is sorted so that diffs between runs show only real changes.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from importlib import resources

from iawp.collector import ProcessRecord
from iawp.policy import Decision
from iawp.taxonomy import LAYER_ORDER

DEFAULT_LAYER = "default"

# Names shared by unrelated workloads; a PcommPrefix rule on these would
# capture far more than the one process that was classified.
AMBIGUOUS_COMMS = {
    "python", "python3", "node", "java", "ruby", "perl", "php", "dotnet", "bun", "deno",
    "sh", "bash", "dash", "zsh", "env", "sudo", "su", "timeout", "nice", "taskset",
    "tini", "dumb-init", "runc", "conmon", "xargs", "parallel",
}

_DEDICATED_CGROUP = [
    re.compile(r"^system\.slice/[^/]+\.service$"),
    re.compile(r"^system\.slice/(docker|cri-containerd|crio|libpod)-[0-9a-f]+\.scope$"),
    re.compile(r"^kubepods[./].*pod[0-9a-f_-]{8,}"),  # refined in Phase 4 (Kubernetes)
]


@dataclass(frozen=True)
class Placed:
    record: ProcessRecord
    decision: Decision


@dataclass(frozen=True)
class Rule:
    layer: str
    kind: str  # scx_layered match type, e.g. "PcommPrefix"
    value: str
    pids: tuple[int, ...]  # processes this rule captures right now


@dataclass(frozen=True)
class Unmatched:
    placed: Placed
    reason: str


def plan_rules(placed: list[Placed]) -> tuple[list[Rule], list[Unmatched]]:
    """Pick one safe match rule per non-default process."""
    procs = [p for p in placed if not p.record.kernel_thread]
    rules: dict[tuple[str, str, str], set[int]] = {}
    unmatched = []
    for p in procs:
        layer = p.decision.layer
        if layer == DEFAULT_LAYER:
            continue
        rule, reason = _cgroup_rule(p, procs)
        if rule is None:
            rule, reason = _comm_rule(p, procs)
        if rule is None:
            unmatched.append(Unmatched(p, reason))
            continue
        kind, value, pids = rule
        rules.setdefault((layer, kind, value), set()).update(pids)
    planned = [Rule(l, k, v, tuple(sorted(pids))) for (l, k, v), pids in sorted(rules.items())]
    return planned, unmatched


def _cgroup_rule(p: Placed, procs: list[Placed]):
    path = p.record.cgroup
    if not any(rx.match(path) for rx in _DEDICATED_CGROUP):
        return None, f"cgroup {path or '(none)'} is not dedicated to one service"
    members = [q for q in procs if q.record.cgroup == path or q.record.cgroup.startswith(path + "/")]
    if conflict := _conflict(p, members):
        return None, f"cgroup {path} also holds {conflict}"
    return ("CgroupPrefix", path + "/", [q.record.pid for q in members]), ""


def _comm_rule(p: Placed, procs: list[Placed]):
    comm = p.record.comm
    if not comm or comm in AMBIGUOUS_COMMS or comm.startswith("python"):
        return None, f"name {comm!r} is shared by unrelated workloads"
    # PcommPrefix is a prefix match: "nginx" would also capture "nginx-exporter".
    members = [q for q in procs if q.record.comm.startswith(comm)]
    if conflict := _conflict(p, members):
        return None, f"name {comm!r} also matches {conflict}"
    return ("PcommPrefix", comm, [q.record.pid for q in members]), ""


def _conflict(p: Placed, members: list[Placed]) -> str:
    """Describe a process the rule would capture that belongs in another layer."""
    for q in members:
        if q.decision.layer != p.decision.layer:
            return f"pid {q.record.pid} ({q.record.comm}, {q.decision.cls} -> {q.decision.layer})"
    return ""


def load_template() -> dict[str, dict]:
    text = resources.files("iawp").joinpath("templates/layers.json").read_text()
    return {k: v for k, v in json.loads(text).items() if not k.startswith("_")}


def build_config(rules: list[Rule], template: dict[str, dict] | None = None) -> list[dict]:
    template = template or load_template()
    layers = []
    for name in LAYER_ORDER:
        if name == DEFAULT_LAYER:
            matches: list[list[dict]] = [[]]  # catch-all; scx_layered requires it last
        else:
            matches = [[{r.kind: r.value}] for r in rules if r.layer == name]
            if not matches:
                continue
        layers.append({
            "name": name,
            "comment": "generated by iawp; layer policy from templates/layers.json",
            "matches": sorted(matches, key=json.dumps),
            "kind": template[name],
        })
    return layers


def render(layers: list[dict]) -> str:
    """JSON with one match per line, so reviewing a diff is easy."""
    out = ["["]
    for i, layer in enumerate(layers):
        out.append("  {")
        out.append(f'    "name": {json.dumps(layer["name"])},')
        out.append(f'    "comment": {json.dumps(layer["comment"])},')
        out.append('    "matches": [')
        ms = layer["matches"]
        out += [f"      {json.dumps(m)}{',' if j < len(ms) - 1 else ''}" for j, m in enumerate(ms)]
        out.append("    ],")
        out.append(f'    "kind": {json.dumps(layer["kind"])}')
        out.append("  }" + ("," if i < len(layers) - 1 else ""))
    out.append("]")
    return "\n".join(out) + "\n"


def diff(old: str, new: str, old_name: str = "current", new_name: str = "generated") -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True), old_name, new_name,
    ))
