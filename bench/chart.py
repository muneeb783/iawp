#!/usr/bin/env python3
"""Chart a benchmark results directory: one panel per measure, arms on the y axis.

Usage (on the Mac, after copying results back; needs matplotlib):
  python3 bench/chart.py lab-out/s1/20261025-023734-s1      # writes chart.png there
  python3 bench/chart.py <dir> -o s1.png

Each panel has its own scale (p99.9 is ~20x p50, so a shared axis would flatten
the rest). Bars are medians across runs; the thin whisker spans min..max.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
BAR = "#2a78d6"  # one series per panel: the arm names on the axis carry identity

PANELS = [  # key, title, unit
    ("p50", "p50 latency", "ms"),
    ("p99", "p99 latency", "ms"),
    ("p999", "p99.9 latency", "ms"),
    ("stress_ops", "noise throughput (stress-ng)", "bogo ops/s"),
]


def draw(summary: dict, title: str, out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    arms = list(summary)
    panels = [p for p in PANELS if any(p[0] in summary[a] for a in arms)]
    fig, axes = plt.subplots(1, len(panels), figsize=(3.4 * len(panels), 0.55 * len(arms) + 1.6),
                             sharey=True, facecolor=SURFACE)
    axes = [axes] if len(panels) == 1 else list(axes)
    ys = list(range(len(arms)))[::-1]  # first arm on top
    for ax, (key, name, unit) in zip(axes, panels):
        ax.set_facecolor(SURFACE)
        top = max(summary[a][key]["max"] for a in arms if key in summary[a])
        for y, arm in zip(ys, arms):
            s = summary[arm].get(key)
            if s is None:
                ax.text(0, y, "  n/a", va="center", ha="left", color=INK_2, fontsize=9)
                continue
            ax.barh(y, s["median"], height=0.42, color=BAR, zorder=2)
            ax.plot([s["min"], s["max"]], [y, y], color=INK, linewidth=1, zorder=3)
            ax.text(s["max"] + top * 0.03, y, _fmt(s["median"]), va="center", ha="left", color=INK, fontsize=9)
        ax.set_xlim(0, top * 1.3)
        ax.set_title(f"{name}\n({unit}, lower is better)" if unit == "ms" else f"{name}\n({unit}, higher is better)",
                     color=INK, fontsize=10, loc="left")
        ax.grid(axis="x", color=GRID, linewidth=0.8, zorder=0)
        ax.tick_params(colors=INK_2, labelsize=9, length=0)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
    axes[0].set_yticks(ys, arms)
    axes[0].tick_params(axis="y", labelsize=10, labelcolor=INK)
    runs = max(v["runs"] for v in summary.values())
    fig.suptitle(title, color=INK, fontsize=12, x=0.01, ha="left")
    fig.text(0.01, 0.01, f"median of {runs} runs; whisker = min..max", color=INK_2, fontsize=8)
    fig.tight_layout(rect=(0, 0.04, 1, 0.97))
    fig.savefig(out, dpi=160, facecolor=SURFACE)
    plt.close(fig)


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if v >= 100 else f"{v:.2f}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bench/chart.py", description=__doc__.split("\n\n")[0])
    p.add_argument("dir", type=Path, help="results directory containing summary.json")
    p.add_argument("-o", "--output", type=Path, help="PNG to write (default: <dir>/chart.png)")
    p.add_argument("--title", help="chart title (default: from meta.json)")
    args = p.parse_args(argv)
    try:
        summary = json.loads((args.dir / "summary.json").read_text())
    except FileNotFoundError:
        print(f"chart: no summary.json in {args.dir}; run `bench/run.py summarize {args.dir}` first", file=sys.stderr)
        return 1
    title = args.title
    if title is None:
        meta_path = args.dir / "meta.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        rate = next((w[2:] for w in meta.get("load", "").split() if w.startswith("-R")), "?")
        title = f"{meta.get('scenario', 'bench').upper()}: nginx at {rate} req/s, {meta.get('cpus', '?')} CPUs"
    out = args.output or args.dir / "chart.png"
    draw(summary, title, out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
