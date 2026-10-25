#!/usr/bin/env python3
"""iawp benchmark harness: does a generated config protect a service as well as a hand-written one?

Arms, interleaved run by run so slow drift on the host hits every arm equally:
  alone   the service only, kernel default scheduler: the best case
  noise   service plus noise, kernel default scheduler: the problem
  hand    service plus noise under scx_layered with a hand-written config
  iawp    service plus noise under scx_layered with the config `iawp apply --trust-critical` generates

Scenario S1 (web): nginx serves a static page; wrk2 sends requests at a fixed
rate and reports latency percentiles measured from each request's scheduled
send time, so a slow server cannot hide its tail by slowing the generator.
Noise: stress-ng on every CPU plus a loop of `make -j<ncpu>` building Lua.

`hand` and `iawp` always share one layer policy template (slices, weights,
preemption): the hand config contributes only which processes go where.

Every arm gets the same window: noise starts, the arm has `--pre` seconds to
set itself up (iawp classifies and applies here), then wrk2 measures for
`--duration` seconds. Run bench/setup.sh once first.

Usage (on the lab VM, as root):
  sudo bench/run.py s1 calibrate                 # max rate nginx sustains alone
  sudo bench/run.py s1 --rate 20000              # 4 arms x 5 runs
  bench/run.py s1 --rate 20000 --dry-run         # print what would run; runs nothing
  bench/run.py summarize bench/results/<dir>     # redo the summary from raw files
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCX_STATE = Path("/sys/kernel/sched_ext/state")
BUILD_DIR = Path("/var/tmp/iawp-bench/lua")  # bench/setup.sh unpacks Lua here
DEFAULT_TEMPLATE = HERE.parent / "src" / "iawp" / "templates" / "layers.json"
ARMS = ("alone", "noise", "hand", "iawp")
NOISY = ("noise", "hand", "iawp")


class BenchError(RuntimeError):
    pass


# ------------------------------------------------------------------ parsing

_WRK_PCT = re.compile(r"^\s*(\d+\.\d+)%\s+([\d.]+)(us|ms|s|m)\s*$")
_UNIT_MS = {"us": 0.001, "ms": 1.0, "s": 1000.0, "m": 60_000.0}
_WRK_KEYS = {"50.000": "p50", "99.000": "p99", "99.900": "p999", "99.990": "p9999"}
# stress-ng --metrics-brief row: stressor, bogo ops, real/usr/sys secs, bogo ops/s (real time), ...
_STRESS = re.compile(r"\]\s+cpu\s+\d+\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+([\d.]+)")
_BUILDS = re.compile(r"^builds (\d+) in (\d+) s$", re.M)


def parse_wrk2(text: str) -> dict[str, float]:
    """Latency percentiles (ms) from wrk2's corrected histogram, achieved rate, and errors."""
    out: dict[str, float] = {}
    in_block = False
    for line in text.splitlines():
        if "Latency Distribution (HdrHistogram - Recorded Latency)" in line:
            in_block = True
        elif in_block and (m := _WRK_PCT.match(line)):
            if m[1] in _WRK_KEYS:
                out[_WRK_KEYS[m[1]]] = float(m[2]) * _UNIT_MS[m[3]]
        elif in_block and line.strip():
            in_block = False  # the detailed spectrum that follows has a different format
        if line.startswith("Requests/sec:"):
            out["rps"] = float(line.split(":", 1)[1])
        if m := re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", line):
            out["errors"] = out.get("errors", 0) + sum(int(x) for x in m.groups())
        if m := re.search(r"Non-2xx or 3xx responses: (\d+)", line):
            out["errors"] = out.get("errors", 0) + int(m[1])
    if "p99" not in out:
        raise BenchError("no latency distribution in wrk2 output (was --latency passed?)")
    out.setdefault("errors", 0)
    return out


def parse_stress(text: str) -> float | None:
    """Noise throughput: stress-ng cpu bogo ops per second of wall time."""
    m = _STRESS.search(text)
    return float(m[1]) if m else None


def parse_builds(text: str) -> float | None:
    """Noise throughput: completed Lua builds per minute."""
    m = _BUILDS.search(text)
    return int(m[1]) * 60 / int(m[2]) if m else None


# ------------------------------------------------------------------ the machine

class Lab:
    """Everything the harness does to the machine, so a dry run can stand in."""

    def run(self, cmd: list[str], log: Path | None = None) -> subprocess.CompletedProcess:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if log:
            log.write_text(res.stdout + res.stderr)
        return res

    def spawn(self, cmd: list[str], log: Path, cwd: Path | None = None) -> subprocess.Popen:
        with open(log, "w") as f:  # the child keeps its own copy of the descriptor
            return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=cwd, start_new_session=True)

    def stop(self, proc: subprocess.Popen, sig: int = signal.SIGTERM, timeout: float = 15) -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()

    def sched_state(self) -> str:
        return SCX_STATE.read_text().strip()

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, seconds))

    def now(self) -> float:
        return time.monotonic()

    def copy(self, src: Path, dst: Path) -> None:
        shutil.copyfile(src, dst)


class DryLab(Lab):
    """Prints each action instead of doing it; tracks just enough state to walk the arms."""

    def __init__(self, echo: bool = True):
        self.actions: list[str] = []
        self.echo = echo
        self.state = "disabled"
        self.clock = 0.0

    def _say(self, text: str) -> None:
        self.actions.append(text)
        if self.echo:
            print(f"  {text}")

    def run(self, cmd, log=None):
        self._say("run " + " ".join(cmd))
        if cmd[1:2] == ["apply"]:
            self.state = "enabled"
        elif cmd[1:2] == ["stop"]:
            self.state = "disabled"
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def spawn(self, cmd, log, cwd=None):
        self._say("start " + " ".join(cmd))
        if Path(cmd[0]).name == "scx_layered":
            self.state = "enabled"
        return _FakeProc(cmd)

    def stop(self, proc, sig=signal.SIGTERM, timeout=15):
        self._say(f"stop {Path(proc.args[0]).name}")
        if Path(proc.args[0]).name == "scx_layered":
            self.state = "disabled"

    def sched_state(self):
        return self.state

    def sleep(self, seconds):
        self.clock += max(0.0, seconds)

    def now(self):
        return self.clock

    def copy(self, src, dst):
        pass


@dataclass
class _FakeProc:
    args: list[str]
    pid: int = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


# ------------------------------------------------------------------ scenario S1

@dataclass
class S1:
    rate: int
    duration: int = 30  # measured seconds per run
    pre: int = 10  # seconds from noise start to measuring: ramp-up, and the arm's own setup
    ncpu: int = field(default_factory=lambda: os.cpu_count() or 8)
    hand_config: Path = HERE / "configs" / "s1-web-hand.json"
    url: str = "http://127.0.0.1/"
    name: str = "s1"

    def load_cmd(self, rate: int | None = None, duration: int | None = None) -> list[str]:
        return ["wrk2", "-t2", "-c64", f"-d{duration or self.duration}s", f"-R{rate or self.rate}", "--latency", self.url]

    def noise_cmds(self) -> list[tuple[str, list[str], Path | None]]:
        window = self.pre + self.duration + 2
        build_loop = (
            f"end=$((SECONDS+{window})); n=0; "
            f"while ((SECONDS<end)); do make -s -C src clean >/dev/null 2>&1; "
            f"make -s -j{self.ncpu} -C src linux >/dev/null 2>&1 && ((SECONDS<=end)) && n=$((n+1)); done; "
            f'echo "builds $n in {window} s"'
        )
        return [
            ("stress", ["stress-ng", "--cpu", str(self.ncpu), "--metrics-brief", "--timeout", f"{window}s"], None),
            ("build", ["bash", "-c", build_loop], BUILD_DIR),
        ]


# ------------------------------------------------------------------ running

@dataclass
class Bench:
    lab: Lab
    scenario: S1
    out: Path
    iawp: str
    runs: int = 5
    template: Path = DEFAULT_TEMPLATE
    arms: tuple[str, ...] = ARMS
    cooldown: float = 5.0
    log: callable = print

    def preflight(self) -> None:
        if isinstance(self.lab, DryLab):
            return
        if os.geteuid() != 0:
            raise BenchError("run as root (sudo): scx_layered and iawp apply need it")
        need = ["wrk2", "stress-ng", "scx_layered", "make", "gcc"]
        if missing := [n for n in need if not shutil.which(n)]:
            raise BenchError(f"not found: {', '.join(missing)}; run bench/setup.sh first")
        if any(a in self.arms for a in NOISY) and not (BUILD_DIR / "src").is_dir():
            raise BenchError(f"{BUILD_DIR} missing; run bench/setup.sh first")
        if "iawp" in self.arms and not Path(self.iawp).exists():
            raise BenchError(f"iawp not found at {self.iawp}; pass --iawp")
        if self.lab.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode != 0:
            raise BenchError("nginx is not running: systemctl start nginx")
        if self.lab.run(["systemctl", "is-active", "--quiet", "iawp-scx.service"]).returncode == 0:
            raise BenchError("iawp-scx.service is running (iawp watch or apply); `iawp stop` first")

    def warm_up(self) -> None:
        """Classify the noise once before measuring, so the iawp arm's apply hits the cache."""
        if "iawp" not in self.arms:
            return
        self.log("warm-up: classifying the noise processes once (fills iawp's cache)")
        procs = self._start_noise("warmup")
        self.lab.sleep(3)
        res = self.lab.run([self.iawp, "config", "--dry-run", "--template", str(self.template)],
                           self.out / "warmup.config.json")
        for p in procs:
            self.lab.stop(p)
        if res.returncode != 0:
            raise BenchError(f"iawp could not classify (is the model server running?):\n{res.stderr.strip()[-500:]}")

    def run_all(self) -> None:
        self.preflight()
        self.write_meta()
        self.warm_up()
        for n in range(1, self.runs + 1):
            for arm in self.arms:
                self.run_one(arm, n)
        self.log("dry run: nothing was started or written" if isinstance(self.lab, DryLab) else f"done: {self.out}")

    def run_one(self, arm: str, n: int) -> None:
        base = f"{arm}-{n}"
        if self.lab.sched_state() != "disabled":
            raise BenchError("a sched_ext scheduler is loaded before the run; stop it first")
        self.log(f"arm={arm} run={n}/{self.runs}")
        sched = None
        noise: list = []
        try:
            if arm == "hand":
                sched = self.lab.spawn(["scx_layered", "--stats", "1", f"f:{self.out / 'hand.config.json'}"],
                                       self.out / f"{base}.sched.log")
                self._wait_state("enabled")
            if arm in NOISY:
                start = self.lab.now()
                noise = self._start_noise(base)
                if arm == "iawp":
                    res = self.lab.run([self.iawp, "apply", "--trust-critical", "--template", str(self.template)],
                                       self.out / f"{base}.apply.txt")
                    if res.returncode != 0:
                        raise BenchError(f"iawp apply failed; see {base}.apply.txt")
                    self._wait_state("enabled")
                    self.lab.copy(Path("/var/lib/iawp/current.json"), self.out / f"{base}.config.json")
                spent = self.lab.now() - start
                if spent > self.scenario.pre - 1:
                    raise BenchError(f"{arm} setup took {spent:.1f} s of the {self.scenario.pre} s window; raise --pre")
                self.lab.sleep(self.scenario.pre - spent)
            else:
                self.lab.sleep(2)
            res = self.lab.run(self.scenario.load_cmd(), self.out / f"{base}.load.txt")
            if res.returncode != 0:
                raise BenchError(f"wrk2 failed; see {base}.load.txt")
            for p in noise:
                p.wait()  # they end on their own at the end of the window
            noise = []
        finally:
            for p in noise:
                self.lab.stop(p)
            if sched is not None:
                self.lab.stop(sched, signal.SIGINT)
                self._wait_state("disabled")
            if arm == "iawp":
                self.lab.run([self.iawp, "stop"])
                self._wait_state("disabled")
        self.lab.sleep(self.cooldown)

    def _start_noise(self, base: str) -> list:
        return [self.lab.spawn(cmd, self.out / f"{base}.{kind}.txt", cwd) for kind, cmd, cwd in self.scenario.noise_cmds()]

    def _wait_state(self, want: str, timeout: float = 15) -> None:
        deadline = self.lab.now() + timeout
        while self.lab.sched_state() != want:
            if self.lab.now() > deadline:
                raise BenchError(f"sched_ext did not become {want} within {timeout:.0f} s")
            self.lab.sleep(0.2)

    def write_meta(self) -> None:
        if isinstance(self.lab, DryLab):
            return
        self.out.mkdir(parents=True, exist_ok=True)
        s = self.scenario
        meta = {
            "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "scenario": s.name,
            "host": os.uname().nodename,
            "kernel": os.uname().release,
            "cpus": s.ncpu,
            "cpu_model": _cpu_model(),
            "scx_layered": _first_line(["scx_layered", "--version"]),
            "iawp": _first_line([self.iawp, "--version"]),
            "nginx": _first_line(["nginx", "-v"]),
            "load": " ".join(s.load_cmd()),
            "noise": [" ".join(cmd) for _, cmd, _ in s.noise_cmds()],
            "pre_seconds": s.pre,
            "arms": list(self.arms),
            "runs": self.runs,
            "iawp_flags": "apply --trust-critical (critical placements not operator-approved)",
            "template": str(self.template),
        }
        (self.out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        shutil.copyfile(self.template, self.out / "template.json")
        (self.out / "hand.config.json").write_text(hand_config(s.hand_config, self.template))


def hand_config(membership: Path, template: Path) -> str:
    """The hand-written config's matches with the template's layer policies."""
    policies = json.loads(template.read_text())
    layers = json.loads(membership.read_text())
    for layer in layers:
        layer["kind"] = policies[layer["name"]]
    return json.dumps(layers, indent=1) + "\n"


def calibrate(lab: Lab, s1: S1) -> int:
    """Highest rate nginx sustains alone; benchmark at ~40% of it, as in Phase 0."""
    out = Path(f"/tmp/iawp-calibrate-{os.getpid()}.txt")
    res = lab.run(s1.load_cmd(rate=1_000_000, duration=20), out)
    try:
        stats = parse_wrk2(res.stdout + res.stderr)
    except BenchError as e:
        tail = "\n".join((res.stdout + res.stderr).strip().splitlines()[-25:])
        raise BenchError(f"{e}; wrk2 exited {res.returncode}, last lines:\n{tail}") from None
    best = int(stats["rps"])
    print(f"nginx alone: {best} requests/s at saturation (p99 {stats['p99']:.2f} ms)")
    print(f"suggested: --rate {round(best * 0.4, -3):.0f}")
    return best


# ------------------------------------------------------------------ summary

METRICS = [  # key, label, format
    ("p50", "p50 ms", "{:.2f}"),
    ("p99", "p99 ms", "{:.2f}"),
    ("p999", "p99.9 ms", "{:.2f}"),
    ("rps", "req/s", "{:.0f}"),
    ("stress_ops", "stress ops/s", "{:.0f}"),
    ("builds_min", "builds/min", "{:.1f}"),
]


def collect(out: Path) -> list[dict]:
    rows = []
    for f in sorted(out.glob("*-*.load.txt")):
        arm, run = f.name[: -len(".load.txt")].rsplit("-", 1)
        row: dict = {"arm": arm, "run": int(run), **parse_wrk2(f.read_text(errors="replace"))}
        if (p := out / f"{arm}-{run}.stress.txt").exists() and (v := parse_stress(p.read_text(errors="replace"))):
            row["stress_ops"] = v
        if (p := out / f"{arm}-{run}.build.txt").exists() and (v := parse_builds(p.read_text(errors="replace"))) is not None:
            row["builds_min"] = v
        rows.append(row)
    return rows


def summarize(rows: list[dict]) -> dict[str, dict]:
    """Per arm and metric: median, min, max, n."""
    order = {a: i for i, a in enumerate(ARMS)}
    out: dict[str, dict] = {}
    for arm in sorted({r["arm"] for r in rows}, key=lambda a: (order.get(a, len(order)), a)):
        rs = [r for r in rows if r["arm"] == arm]
        out[arm] = {"runs": len(rs), "errors": sum(r.get("errors", 0) for r in rs)}
        for key, _, _ in METRICS:
            xs = [r[key] for r in rs if key in r]
            if xs:
                out[arm][key] = {"median": statistics.median(xs), "min": min(xs), "max": max(xs), "n": len(xs)}
    return out


def render_table(summary: dict[str, dict]) -> str:
    cols = [m for m in METRICS if any(m[0] in v for v in summary.values())]
    header = ["arm", "n"] + [label for _, label, _ in cols]
    lines = []
    for arm, v in summary.items():
        cells = [arm, str(v["runs"])]
        for key, _, fmt in cols:
            if key in v:
                s = v[key]
                cells.append(f"{fmt.format(s['median'])} [{fmt.format(s['min'])}..{fmt.format(s['max'])}]")
            else:
                cells.append("-")
        lines.append(cells)
    widths = [max(len(r[i]) for r in [header, *lines]) for i in range(len(header))]
    fmt_row = lambda r: "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()  # noqa: E731
    text = "\n".join(fmt_row(r) for r in [header, *lines])
    errors = {a: v["errors"] for a, v in summary.items() if v["errors"]}
    note = "median [min..max] across runs; latency from wrk2's corrected histogram"
    if errors:
        note += "\nrequest errors: " + ", ".join(f"{a} {n}" for a, n in errors.items())
    return text + "\n\n" + note


def write_summary(out: Path) -> str:
    summary = summarize(collect(out))
    if not summary:
        raise BenchError(f"no results in {out}")
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    table = render_table(summary)
    (out / "summary.txt").write_text(table + "\n")
    return table


# ------------------------------------------------------------------ helpers and CLI

def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _first_line(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        return "not found"
    return ((res.stdout or res.stderr).strip().splitlines() or ["?"])[0]


def default_iawp() -> str:
    user = os.environ.get("SUDO_USER")
    venv = Path(f"~{user}" if user else "~").expanduser() / "iawp" / ".venv" / "bin" / "iawp"
    return str(venv) if venv.exists() else (shutil.which("iawp") or str(venv))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bench/run.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("s1", help="web: nginx + wrk2 under stress-ng and a compile loop")
    s1.add_argument("action", nargs="?", choices=["run", "calibrate"], default="run")
    s1.add_argument("--rate", type=int, help="wrk2 requests per second (see `calibrate`)")
    s1.add_argument("--runs", type=int, default=5)
    s1.add_argument("--duration", type=int, default=30, help="measured seconds per run (default: %(default)s)")
    s1.add_argument("--pre", type=int, default=10, help="seconds of noise before measuring (default: %(default)s)")
    s1.add_argument("--arms", default=",".join(ARMS), help="comma-separated subset of %(default)s")
    s1.add_argument("--iawp", default=default_iawp(), help="iawp executable (default: %(default)s)")
    s1.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE,
                    help="layer policies for both hand and iawp (default: iawp's built-in)")
    s1.add_argument("--out", help="results directory (default: bench/results/<time>-s1)")
    s1.add_argument("--dry-run", action="store_true", help="print the actions without running anything")
    sm = sub.add_parser("summarize", help="rebuild summary.txt and summary.json from a results directory")
    sm.add_argument("dir")
    args = p.parse_args(argv)

    try:
        if args.cmd == "summarize":
            print(write_summary(Path(args.dir)))
            return 0
        lab = DryLab() if args.dry_run else Lab()
        if args.action == "calibrate":
            calibrate(lab, S1(rate=0))
            return 0
        if not args.rate:
            p.error("--rate is required; run `bench/run.py s1 calibrate` to choose one")
        arms = tuple(a for a in args.arms.split(",") if a)
        if bad := [a for a in arms if a not in ARMS]:
            p.error(f"unknown arms: {', '.join(bad)}")
        label = "" if args.template == DEFAULT_TEMPLATE else f"-{args.template.stem}"
        out = Path(args.out) if args.out else HERE / "results" / f"{time.strftime('%Y%m%d-%H%M%S')}-s1{label}"
        bench = Bench(lab, S1(args.rate, args.duration, args.pre), out, args.iawp,
                      runs=args.runs, arms=arms, template=args.template.resolve())
        try:
            bench.run_all()
        finally:
            if user := os.environ.get("SUDO_USER"):
                subprocess.run(["chown", "-R", user, str(out)], capture_output=True)
        if not args.dry_run:
            print(write_summary(out))
        return 0
    except BenchError as e:
        print(f"bench: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("bench: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
