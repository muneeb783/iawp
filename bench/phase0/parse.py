#!/usr/bin/env python3
"""Summarize Phase 0 schbench results.

Usage: python3 parse.py <results_dir>

Reads <arm>-<n>.txt files written by run.sh, extracts the final percentile
summary that schbench prints at exit, plus stress-ng's throughput from
<arm>-<n>.noise.log when present, writes results.csv, and prints the median
and min..max per arm.
"""

import csv
import re
import statistics
import sys
from pathlib import Path

SECTIONS = {
    "Wakeup Latencies percentiles": "wake",
    "Request Latencies percentiles": "req",
}
PCTS = {"50.0": "p50", "90.0": "p90", "99.0": "p99", "99.9": "p999"}
FIELDS = [f"{s}_{p}" for s in SECTIONS.values() for p in PCTS.values()] + ["avg_rps", "batch_ops"]
ARM_ORDER = ["alone", "noise"]  # then hand-* arms alphabetically

PCT_RE = re.compile(r"^\s*\*?\s*(\d+\.\d)th:\s+(\d+)")
FILE_RE = re.compile(r"^(?P<arm>.+)-(?P<run>\d+)\.txt$")
# stress-ng --metrics-brief row: stressor, bogo ops, real/usr/sys secs, bogo ops/s (real time), ...
STRESS_RE = re.compile(r"\]\s+cpu\s+\d+\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+([\d.]+)")


def parse_stress(text: str) -> float | None:
    """Batch throughput: stress-ng cpu bogo ops per second of wall time."""
    m = STRESS_RE.search(text)
    return float(m.group(1)) if m else None


def parse_schbench(text: str) -> dict:
    """Return the last value seen for each metric; schbench's final block wins."""
    out = {}
    section = None
    for line in text.splitlines():
        for header, key in SECTIONS.items():
            if line.startswith(header):
                section = key
                break
        else:
            if line.startswith("RPS percentiles"):
                section = None
            elif m := PCT_RE.match(line):
                if section and m.group(1) in PCTS:
                    out[f"{section}_{PCTS[m.group(1)]}"] = int(m.group(2))
            elif line.startswith("average rps:"):
                out["avg_rps"] = float(line.split(":", 1)[1])
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    d = Path(sys.argv[1])
    rows = []
    for f in sorted(d.glob("*.txt")):
        m = FILE_RE.match(f.name)
        if not m:
            continue
        vals = parse_schbench(f.read_text(errors="replace"))
        if "req_p99" not in vals:
            print(f"warning: no summary in {f.name}", file=sys.stderr)
            continue
        noise = f.with_suffix(".noise.log")
        if noise.exists() and (ops := parse_stress(noise.read_text(errors="replace"))) is not None:
            vals["batch_ops"] = ops
        rows.append({"arm": m["arm"], "run": int(m["run"]), **vals})

    if not rows:
        print(f"no results found in {d}", file=sys.stderr)
        return 1

    with open(d / "results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["arm", "run", *FIELDS])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["arm"], r["run"])))

    arms = sorted({r["arm"] for r in rows},
                  key=lambda a: (ARM_ORDER.index(a) if a in ARM_ORDER else len(ARM_ORDER), a))
    # Wakeup percentiles stay in results.csv but are not shown: with -R (fixed
    # rate) schbench collects only a handful of wakeup samples per run.
    shown = ["req_p50", "req_p99", "req_p999", "avg_rps", "batch_ops"]
    print(f"{'arm':<16} {'n':>2}  " + "  ".join(f"{k:>20}" for k in shown))
    for arm in arms:
        rs = [r for r in rows if r["arm"] == arm]
        cells = []
        for k in shown:
            xs = [r[k] for r in rs if k in r]
            if not xs:
                cells.append(f"{'-':>20}")
                continue
            med = statistics.median(xs)
            cells.append(f"{med:>8.0f} [{min(xs):>.0f}..{max(xs):>.0f}]".rjust(20))
        print(f"{arm:<16} {len(rs):>2}  " + "  ".join(cells))
    print("\nlatencies in usec; batch_ops = stress-ng bogo ops/s; median [min..max] across runs")
    print(f"wrote {d / 'results.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
