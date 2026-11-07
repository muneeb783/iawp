"""Generate an scx_layered config from placement decisions.

The hard part is not the JSON, it is choosing a match rule that selects
exactly the processes we mean. scx_layered matches on kernel-visible facts
(comm prefix, cgroup path, uid, ...), not on command lines, so `python
serve.py` and `python train.py` look identical to it by name. Rules:

1. A cgroup dedicated to one service or container (system.slice/nginx.service,
   an instance of a template unit such as
   system.slice/system-postgresql.slice/postgresql@18-main.service,
   docker-<id>.scope, kubepods...) is placed as a whole: one CgroupPrefix
   rule, layer chosen by the service's main process. scx_layered cannot split
   a service anyway (postgres autovacuum shares the database's name and
   cgroup), and splitting it is not what an operator would write by hand.
2. Other processes are matched by name (PcommPrefix), unless the name is a
   generic interpreter or wrapper that many unrelated workloads share.
3. Only emit a name rule if every currently running process it would capture
   ends up in the same layer. Otherwise leave it out and report why.

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
from iawp.taxonomy import LAYER_ORDER, UNKNOWN

DEFAULT_LAYER = "default"

# Names shared by unrelated workloads; a PcommPrefix rule on these would
# capture far more than the one process that was classified.
AMBIGUOUS_COMMS = {
    "python", "python3", "node", "java", "ruby", "perl", "php", "dotnet", "bun", "deno",
    "sh", "bash", "dash", "zsh", "env", "sudo", "su", "timeout", "nice", "taskset",
    "tini", "dumb-init", "runc", "conmon", "xargs", "parallel",
}

_DEDICATED_CGROUP = [
    re.compile(r"^system\.slice/(system-[^/]+\.slice/)?[^/]+\.service$"),  # template instances sit in system-<name>.slice
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
    note: str = ""  # why, when it is not simply "classified so" (service placement)


@dataclass(frozen=True)
class Unmatched:
    placed: Placed
    reason: str


def plan_rules(placed: list[Placed]) -> tuple[list[Rule], list[Unmatched]]:
    """Pick one safe match rule per non-default process."""
    procs = [p for p in placed if not p.record.kernel_thread]
    services: dict[str, list[Placed]] = {}
    for p in procs:
        if _dedicated(p.record.cgroup):
            services.setdefault(p.record.cgroup, []).append(p)

    # The layer each process will actually land in, which name rules are checked against.
    effective = {p.record.pid: p.decision.layer for p in procs}
    service_rules: list[Rule] = []
    unmatched: list[Unmatched] = []
    for path, members in sorted(services.items()):
        layer, note, misses = _service_layer(path, members)
        for q in members:
            effective[q.record.pid] = layer
        unmatched += misses
        if layer != DEFAULT_LAYER:
            service_rules.append(Rule(layer, "CgroupPrefix", path + "/",
                                      tuple(sorted(q.record.pid for q in members)), note))

    rules: dict[tuple[str, str, str], set[int]] = {}
    for p in procs:
        if p.record.cgroup in services or p.decision.layer == DEFAULT_LAYER:
            continue
        rule, reason = _comm_rule(p, procs, effective)
        if rule is None:
            unmatched.append(Unmatched(p, reason))
            continue
        kind, value, pids = rule
        rules.setdefault((p.decision.layer, kind, value), set()).update(pids)
    _drop_covered_prefixes(rules)
    planned = service_rules + [Rule(l, k, v, tuple(sorted(pids))) for (l, k, v), pids in rules.items()]
    return sorted(planned, key=lambda r: (r.layer, r.kind, r.value)), unmatched


def _dedicated(cgroup: str) -> bool:
    return any(rx.match(cgroup) for rx in _DEDICATED_CGROUP)


def _service_layer(path: str, members: list[Placed]) -> tuple[str, str, list[Unmatched]]:
    """One layer for a whole service, decided by its main process.

    Main process: the member whose parent is outside the cgroup (systemd's
    MainPID); the lowest pid if there are several. If the main process lands
    in default (unknown, or a wrapper like `sh -c`), the other members decide
    when they all agree, but never for `critical`: only a main process can
    promote a service, so a misclassified helper cannot.
    """
    pids = {q.record.pid for q in members}
    roots = sorted((q for q in members if q.record.ppid not in pids), key=lambda q: q.record.pid)
    main = roots[0] if roots else min(members, key=lambda q: q.record.pid)
    main_is = f"main process {main.record.comm} (pid {main.record.pid}) is {main.decision.cls}"
    if main.decision.layer != DEFAULT_LAYER:
        layer, why = main.decision.layer, main_is
    else:
        decided = {q.decision.layer for q in members if q is not main and q.decision.cls != UNKNOWN}
        if len(decided) == 1 and not decided & {DEFAULT_LAYER, "critical"}:
            layer = next(iter(decided))
            why = f"{main_is}; every other decided member is {layer}"
        else:
            layer = DEFAULT_LAYER
            if decided == {"critical"}:
                why = f"{main_is}; only a main process can make a service critical"
            elif len(decided) > 1:
                why = f"{main_is} and members disagree ({', '.join(sorted(decided))})"
            else:
                why = main_is
    followers = [q for q in members if q.decision.layer != layer and q.decision.cls != UNKNOWN]
    note = f"service {path}: {why}"
    if followers:
        note += "; follow it: " + ", ".join(f"{q.record.pid} {q.record.comm} ({q.decision.cls})" for q in followers)
    misses = [Unmatched(q, f"stays with its service in default: {why}")
              for q in members if layer == DEFAULT_LAYER and q.decision.layer != DEFAULT_LAYER]
    return layer, note, misses


def _drop_covered_prefixes(rules: dict[tuple[str, str, str], set[int]]) -> None:
    """Fold "stress-ng-cpu" into "stress-ng": the shorter prefix already captures it.

    Only within one layer. Across layers it cannot happen, because the shorter
    rule would have failed the conflict check.
    """
    for key in sorted(rules, key=lambda k: -len(k[2])):
        layer, kind, value = key
        if kind != "PcommPrefix":
            continue
        shorter = [k for k in rules if k[:2] == key[:2] and k != key and value.startswith(k[2])]
        if shorter:
            rules[min(shorter, key=lambda k: len(k[2]))].update(rules.pop(key))


def _comm_rule(p: Placed, procs: list[Placed], effective: dict[int, str]):
    comm = p.record.comm
    if not comm or comm in AMBIGUOUS_COMMS or comm.startswith("python"):
        return None, f"name {comm!r} is shared by unrelated workloads"
    # PcommPrefix is a prefix match: "nginx" would also capture "nginx-exporter".
    # A process matching rules in two layers goes to the first layer, so every
    # captured process must already be headed for this rule's layer.
    members = [q for q in procs if q.record.comm.startswith(comm)]
    for q in members:
        if effective[q.record.pid] != p.decision.layer:
            where = "its service's layer" if effective[q.record.pid] != q.decision.layer else q.decision.cls
            return None, (f"name {comm!r} also matches pid {q.record.pid} "
                          f"({q.record.comm}, {where} -> {effective[q.record.pid]})")
    return ("PcommPrefix", comm, [q.record.pid for q in members]), ""


class TemplateError(ValueError):
    """A layer policy template that cannot be read or lacks a layer."""


def load_template(path: str | None = None) -> dict[str, dict]:
    """Layer policies by layer name; the built-in, lab-tested one unless `path` is given."""
    try:
        if path:
            with open(path) as f:
                text = f.read()
        else:
            text = resources.files("iawp").joinpath("templates/layers.json").read_text()
        template = {k: v for k, v in json.loads(text).items() if not k.startswith("_")}
    except (OSError, ValueError) as e:
        raise TemplateError(f"cannot read template {path}: {e}") from None
    if missing := [name for name in LAYER_ORDER if name not in template]:
        raise TemplateError(f"template {path} has no policy for layers: {', '.join(missing)}")
    return template


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
