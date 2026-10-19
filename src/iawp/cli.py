"""iawp command line: scan, explain, config."""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from iawp import __version__
from iawp.classify.systemone import HOSTED_URL
from iawp.classify import BACKENDS, Classification, ClassifierError, ServerUnreachable, build_state, get_backend
from iawp.collector import ProcessRecord, collect
from iawp.emit import Placed, Rule, Unmatched, build_config, diff, plan_rules, render
from iawp.policy import Decision, Thresholds, decide
from iawp.taxonomy import LAYER_ORDER, UNKNOWN


@dataclass(frozen=True)
class Row:
    record: ProcessRecord
    state: dict[str, str] | None  # None for kernel threads, which are never classified
    result: Classification | None
    decision: Decision


def classify_all(args: argparse.Namespace) -> list[Row]:
    backend = get_backend(args.backend, args.url, args.model, None if args.no_cache else _cache_path(args))
    args.classifier = backend  # scan reports cache hits
    if args.backend == "hosted":
        print(f"iawp: sending redacted details of uncached processes to {HOSTED_URL}", file=sys.stderr)
    thresholds = Thresholds(critical=args.critical_threshold, other=args.threshold)
    answers: dict[tuple, Classification] = {}  # identical workers (stress-ng-cpu x8) cost one request
    rows = []
    for r in collect(Path(args.proc_root)):
        if r.kernel_thread:
            rows.append(Row(r, None, None, Decision(UNKNOWN, "default", "kernel thread")))
            continue
        state = build_state(r)
        key = tuple(state.items())
        if key not in answers:
            answers[key] = backend.classify(state)
        result = answers[key]
        rows.append(Row(r, state, result, decide(result, thresholds)))
    return rows


def plan(rows: list[Row]) -> tuple[list[Rule], list[Unmatched]]:
    return plan_rules([Placed(row.record, row.decision) for row in rows])


def cmd_scan(args: argparse.Namespace) -> int:
    rows = classify_all(args)
    rules, unmatched = plan(rows)
    covered = {pid for rule in rules for pid in rule.pids}
    shown = [row for row in rows if args.all or not row.record.kernel_thread]
    shown.sort(key=lambda row: (LAYER_ORDER.index(row.decision.layer), row.decision.cls, row.record.comm, row.record.pid))

    header = ("PID", "USER", "NAME", "CLASS", "P", "LAYER", "RULE", "COMMAND")
    table = []
    for row in shown:
        r, d = row.record, row.decision
        p = f"{row.result.confidence:.2f}" if row.result else "-"
        rule = "yes" if r.pid in covered else ("no" if d.layer != "default" else "")
        cmd = row.state["command_line"] if row.state else f"[{r.comm}]"
        table.append((str(r.pid), r.user, r.comm, d.cls, p, d.layer, rule, cmd))
    _print_table(header, table)

    counts = {layer: sum(1 for row in shown if row.decision.layer == layer) for layer in LAYER_ORDER}
    print(f"\n{len(shown)} processes: " + ", ".join(f"{n} {layer}" for layer, n in counts.items())
          + f"  (backend: {args.backend})")
    if hasattr(args.classifier, "hits"):
        c = args.classifier
        print(f"cache: {c.hits} hits, {c.misses} asked the model  ({c.cache.path})")
    if unmatched:
        print(f"{len(unmatched)} classified but left in default (no safe match rule); see `iawp explain <pid>`")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    rows = classify_all(args)
    row = next((row for row in rows if row.record.pid == args.pid), None)
    if row is None:
        print(f"no process with pid {args.pid}", file=sys.stderr)
        return 1
    r = row.record
    print(f"pid {r.pid}  {r.comm}  (parent {r.ppid} {r.parent_comm or '?'}, uid {r.uid})\n")
    if row.state is None:
        print("kernel thread: never classified, always in the default layer")
        return 0

    print(f"Sent to the {args.backend} classifier (after redaction):")
    for k, v in row.state.items():
        print(f"  {k:<15} {v}")

    res = row.result
    when = f", cached {time.strftime('%Y-%m-%d %H:%M', time.localtime(res.cached_at))}" if res.cached_at else ""
    print(f"\nAnswer from {res.model}{when}:")
    print(f"  enough information to tell: {res.enough_info:.2f}")
    for cls, p in sorted(res.probabilities.items(), key=lambda kv: -kv[1]):
        print(f"  {cls:<17} {p:.2f}  {'#' * round(p * 30)}")

    d = row.decision
    print(f"\nDecision: {d.cls} -> layer {d.layer}  ({d.reason})")
    rules, unmatched = plan(rows)
    if rule := next((x for x in rules if r.pid in x.pids), None):
        print(f"Config rule: {{\"{rule.kind}\": \"{rule.value}\"}} in layer {rule.layer} (captures {len(rule.pids)} processes)")
    elif miss := next((u for u in unmatched if u.placed.record.pid == r.pid), None):
        print(f"No config rule, stays in default: {miss.reason}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    if not args.dry_run:
        print("iawp config only supports --dry-run for now; applying configs arrives with `iawp apply`.", file=sys.stderr)
        return 2
    rows = classify_all(args)
    rules, unmatched = plan(rows)
    text = render(build_config(rules))
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output}", file=sys.stderr)
    if args.against:
        old = Path(args.against).read_text()
        out = diff(old, text, args.against, "generated")
        print(out or f"no changes against {args.against}")
    elif not args.output:
        print(text, end="")
    if unmatched:
        print(f"note: {len(unmatched)} classified processes have no safe match rule and stay in default:", file=sys.stderr)
        for u in unmatched:
            print(f"  pid {u.placed.record.pid} {u.placed.record.comm}: {u.reason}", file=sys.stderr)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from iawp import evaluate

    path = Path(args.file)
    records = evaluate.load(path)
    if args.judgment == "exclude":
        records = [r for r in records if not r.get("judgment")]
    elif args.judgment == "only":
        records = [r for r in records if r.get("judgment")]
    # Measure the model itself: a cache would hide both its latency and changes in its answers.
    backend = get_backend(args.backend, args.url, args.model)
    if args.backend == "hosted":
        print(f"iawp: sending {len(records)} eval records to {HOSTED_URL}", file=sys.stderr)
    thresholds = Thresholds(critical=args.critical_threshold, other=args.threshold)
    progress = None
    if sys.stderr.isatty() and args.backend != "mock":
        progress = lambda i, n: print(f"\r  {i}/{n}", end="" if i < n else "\n", file=sys.stderr, flush=True)  # noqa: E731
    scored = evaluate.run(backend, records, thresholds, progress)
    judgment = {"include": "judgment calls included", "exclude": "clear labels only", "only": "judgment calls only"}
    print(evaluate.report(scored, args.backend, path, judgment[args.judgment]))
    if args.errors:
        print("\nwrong decisions:\n" + (evaluate.errors(scored) or "  none"))
    if args.json:
        evaluate.dump(scored, Path(args.json), args.backend)
        print(f"\nwrote per-record results to {args.json}", file=sys.stderr)
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    from iawp.classify.cache import Cache

    path = _cache_path(args)
    if not path.exists():
        print(f"no cache at {path}")
        return 0
    cache = Cache(path)
    if args.action == "clear":
        print(f"removed {cache.clear()} answers from {path}")
        return 0
    rows = cache.stats()
    print(f"{path}: {sum(n for *_, n in rows)} answers")
    for classifier, model, n in rows:
        print(f"  {n:>5}  {model:<20} via {classifier}")
    return 0


def _cache_path(args: argparse.Namespace) -> Path:
    from iawp.classify.cache import default_path

    return Path(args.cache) if args.cache else default_path()


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(header)]
    widths[3] = min(widths[3], 16)
    fixed = sum(widths[:-1]) + 2 * (len(header) - 1)
    widths[-1] = max(20, shutil.get_terminal_size((120, 20)).columns - fixed)
    for r in [header, *rows]:
        cells = [c if len(c) <= w else c[: w - 1] + "…" for c, w in zip(r, widths)]
        print("  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip())


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", choices=BACKENDS, default="mock", help="classifier backend (default: mock)")
    common.add_argument("--url", help="SystemOne server for the local/hosted backends")
    common.add_argument("--model", help="model to request; pin an exact version for reproducible results")
    common.add_argument("--cache", metavar="FILE", help="answer cache (default: /var/cache/iawp as root, else ~/.cache/iawp)")
    common.add_argument("--no-cache", action="store_true", help="always ask the model")
    common.add_argument("--threshold", type=float, default=Thresholds.other,
                        help="min probability for batch/other layers (default: %(default)s)")
    common.add_argument("--critical-threshold", type=float, default=Thresholds.critical,
                        help="min probability for the critical layer (default: %(default)s)")
    common.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(prog="iawp", description="Intent-aware workload placement for scx_layered.")
    parser.add_argument("--version", action="version", version=f"iawp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", parents=[common], help="classify running processes")
    p.add_argument("--all", action="store_true", help="include kernel threads")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("explain", parents=[common], help="show what was sent to the classifier and why")
    p.add_argument("pid", type=int)
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("config", parents=[common], help="generate an scx_layered config")
    p.add_argument("--dry-run", action="store_true", help="print the config without applying it")
    p.add_argument("--against", metavar="FILE", help="show a diff against an existing config")
    p.add_argument("-o", "--output", metavar="FILE", help="also write the config to FILE")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("eval", parents=[common], help="score a backend on a labelled process set")
    p.add_argument("file", nargs="?", default="eval/processes.jsonl", help="labelled records (default: %(default)s)")
    p.add_argument("--judgment", choices=["include", "exclude", "only"], default="include",
                   help="records whose label is a judgment call (default: include)")
    p.add_argument("--errors", action="store_true", help="list every wrong decision")
    p.add_argument("--json", metavar="FILE", help="save per-record results and metrics")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("cache", parents=[common], help="show or clear remembered model answers")
    p.add_argument("action", choices=["stats", "clear"], nargs="?", default="stats")
    p.set_defaults(func=cmd_cache)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("scan", "explain", "config") and not Path(args.proc_root).is_dir():
        print(f"iawp: {args.proc_root} not found; iawp reads Linux's /proc and must run on Linux", file=sys.stderr)
        return 1
    try:
        return args.func(args)
    except ClassifierError as e:
        print(f"iawp: {e}", file=sys.stderr)
        if isinstance(e, ServerUnreachable) and args.backend == "local":
            print("iawp: start a local model server (see docs), or use --backend mock", file=sys.stderr)
        return 1
