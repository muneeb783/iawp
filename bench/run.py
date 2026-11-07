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

Scenario S2 (database): PostgreSQL serves pgbench's read-write transactions at
a fixed rate; latency is taken from pgbench's per-transaction log and includes
the schedule lag, so it too counts from the scheduled start. Noise: a backup
loop (compressed pg_dump of another database) and a bulk-load loop (COPY of
2M rows into a table of the benchmark database). The COPY and the dump's reads
run in postgres backends, in the same cgroup and under the same name as the
backends serving pgbench, so no placement can separate them from the service.

`hand` and `iawp` always share one layer policy template (slices, weights,
preemption): the hand config contributes only which processes go where.

Every arm gets the same window: noise starts, the arm has `--pre` seconds to
set itself up (iawp classifies and applies here), then wrk2 measures for
`--duration` seconds. Run bench/setup.sh once first.

Usage (on the lab VM, as root):
  sudo bench/run.py s1 calibrate                 # max rate nginx sustains alone
  sudo bench/run.py s1 --rate 20000              # 4 arms x 5 runs
  sudo bench/run.py s2 calibrate                 # max transactions/s postgres sustains alone
  sudo bench/run.py s2 --rate 2000
  bench/run.py s1 --rate 20000 --dry-run         # print what would run; runs nothing
  bench/run.py summarize bench/results/<dir>     # redo the summary from raw files
"""

from __future__ import annotations

import argparse
import json
import math
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
BULK_CSV = Path("/var/tmp/iawp-bench/bulk.csv")  # bench/setup.sh writes the rows S2's bulk load copies
PG_ENV = ["PGHOST=127.0.0.1", "PGUSER=bench", "PGPASSWORD=bench"]  # lab-only role made by bench/setup.sh
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
_COUNT = re.compile(r"^(\w+) (\d+) in (\d+) s$", re.M)  # "builds 14 in 42 s", from the noise loops


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


def parse_count(text: str) -> float | None:
    """Noise throughput of a loop: completed rounds (builds, dumps, copies) per minute, summed over its streams."""
    ms = _COUNT.findall(text)
    return sum(int(n) for _, n, _ in ms) * 60 / int(ms[0][2]) if ms else None


parse_builds = parse_count


def parse_pgbench(summary: str, logs: list[str]) -> dict[str, float]:
    """Latency percentiles (ms) from pgbench's per-transaction logs, rate and failures from its summary.

    A log line is `client txn time_us script epoch epoch_us [schedule_lag_us]`;
    with --rate the latency counted is time + lag, from the scheduled start.
    """
    lat = []
    for text in logs:
        for line in text.splitlines():
            f = line.split()
            if len(f) >= 6 and f[2].isdigit():  # "failed" or "skipped" otherwise
                lat.append((int(f[2]) + (int(f[6]) if len(f) > 6 else 0)) / 1000)
    if not lat:
        raise BenchError("no transactions in the pgbench logs (was --log passed?)")
    lat.sort()
    out = {key: _rank(lat, q) for key, q in (("p50", 0.5), ("p99", 0.99), ("p999", 0.999), ("p9999", 0.9999))}
    if m := re.search(r"^tps = ([\d.]+)", summary, re.M):
        out["rps"] = float(m[1])
    m = re.search(r"^number of failed transactions: (\d+)", summary, re.M)
    out["errors"] = int(m[1]) if m else 0
    return out


def _rank(xs: list[float], q: float) -> float:
    """Nearest-rank percentile of sorted xs."""
    return xs[min(len(xs) - 1, max(0, math.ceil(q * len(xs)) - 1))]


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


# ------------------------------------------------------------------ scenarios
#
# A scenario supplies the load command and its parser, the noise loops, and
# its own preflight checks; Bench runs the arms the same way for every scenario.

def _loop(body: str, word: str, window: int) -> str:
    """Bash: repeat `body` for `window` seconds, then print "<word> N in <window> s" (rounds completed in time).

    A failing round waits a second, so a broken setup cannot turn the noise into a fork loop.
    """
    return (f"end=$((SECONDS+{window})); n=0; "
            f"while ((SECONDS<end)); do if {body}; then ((SECONDS<=end)) && n=$((n+1)); else sleep 1; fi; done; "
            f'echo "{word} $n in {window} s"')


def _streams(loop: str, k: int) -> str:
    """Bash: run `loop` k times in parallel, with $i = 1..k in each."""
    return f"for i in $(seq {k}); do ( {loop} ) & done; wait"


@dataclass
class S1:
    rate: int
    duration: int = 30  # measured seconds per run
    pre: int = 20  # seconds from noise start to measuring: ramp-up, and the arm's own setup (iawp apply)
    ncpu: int = field(default_factory=lambda: os.cpu_count() or 8)
    hand_config: Path = HERE / "configs" / "s1-web-hand.json"
    url: str = "http://127.0.0.1/"
    name: str = "s1"
    noise: tuple[str, ...] = ("stress", "build")  # which noise sources run

    NOISE = ("stress", "build")
    NOTE = "latency from wrk2's corrected histogram"
    VERSION = ["nginx", "-v"]

    def load_cmd(self, log: Path | None = None, rate: int | None = None, duration: int | None = None) -> list[str]:
        return ["wrk2", "-t2", "-c64", f"-d{duration or self.duration}s", f"-R{rate or self.rate}", "--latency", self.url]

    def noise_cmds(self) -> list[tuple[str, list[str], Path | None]]:
        window = self.pre + self.duration + 2
        build = f"make -s -C src clean >/dev/null 2>&1; make -s -j{self.ncpu} -C src linux >/dev/null 2>&1"
        sources = [
            ("stress", ["stress-ng", "--cpu", str(self.ncpu), "--metrics-brief", "--timeout", f"{window}s"], None),
            ("build", ["bash", "-c", _loop(build, "builds", window)], BUILD_DIR),
        ]
        return [s for s in sources if s[0] in self.noise]

    def preflight(self, lab: Lab) -> None:
        _need_tools("wrk2", "stress-ng", "make", "gcc")
        if "build" in self.noise and not (BUILD_DIR / "src").is_dir():
            raise BenchError(f"{BUILD_DIR} missing; run bench/setup.sh first")
        if lab.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode != 0:
            raise BenchError("nginx is not running: systemctl start nginx")

    @staticmethod
    def parse_load(out: Path, base: str) -> dict[str, float]:
        return parse_wrk2((out / f"{base}.load.txt").read_text(errors="replace"))

    def calibrate(self, lab: Lab) -> int:
        """Highest rate nginx sustains alone. 40% of it overloaded the box under noise; S1 used ~9%."""
        out = Path(f"/tmp/iawp-calibrate-{os.getpid()}.txt")
        res = lab.run(self.load_cmd(rate=1_000_000, duration=20), out)
        try:
            stats = parse_wrk2(res.stdout + res.stderr)
        except BenchError as e:
            raise BenchError(f"{e}; wrk2 exited {res.returncode}, last lines:\n{_tail(res)}") from None
        best = int(stats["rps"])
        print(f"nginx alone: {best} requests/s at saturation (p99 {stats['p99']:.2f} ms)")
        print(f"suggested: --rate {round(best * 0.1, -3):.0f}, then check `alone` stays far from saturation")
        return best


@dataclass
class S2:
    rate: int  # transactions per second
    duration: int = 30
    pre: int = 20
    ncpu: int = field(default_factory=lambda: os.cpu_count() or 8)
    hand_config: Path = HERE / "configs" / "s2-db-hand.json"
    clients: int = 16
    streams: int = 0  # parallel backups and parallel bulk loads; 0: half the CPUs each, enough to saturate the box
    name: str = "s2"
    noise: tuple[str, ...] = ("backup", "copy")

    NOISE = ("backup", "copy")
    NOTE = "latency from pgbench's per-transaction log, schedule lag included"
    VERSION = ["psql", "--version"]

    def load_cmd(self, log: Path | None = None, rate: int | None = None, duration: int | None = None) -> list[str]:
        cmd = ["env", *PG_ENV, "pgbench", "-n", "-M", "prepared", f"-c{self.clients}", "-j2",
               f"-T{duration or self.duration}"]
        if rate != 0:
            cmd.append(f"-R{rate or self.rate}")
        if log is not None:
            cmd += ["--log", f"--log-prefix={log}.pgbench"]
        return cmd + ["bench"]

    def noise_cmds(self) -> list[tuple[str, list[str], Path | None]]:
        window = self.pre + self.duration + 2
        env = "export " + " ".join(PG_ENV) + "; "
        k = self.k
        dump = "pg_dump --no-sync -Fc -Z6 -f /dev/null archive"
        copy = f"psql -qX -v ON_ERROR_STOP=1 -c \"TRUNCATE bulk_$i\" -c \"\\copy bulk_$i from '{BULK_CSV}' csv\" bench"
        sources = [
            ("backup", ["bash", "-c", env + _streams(_loop(dump, "dumps", window), k)], None),
            ("copy", ["bash", "-c", env + _streams(_loop(copy, "copies", window), k)], None),
        ]
        return [s for s in sources if s[0] in self.noise]

    @property
    def k(self) -> int:
        return self.streams or max(1, self.ncpu // 2)

    def preflight(self, lab: Lab) -> None:
        _need_tools("pgbench", "pg_dump", "psql", "pg_isready")
        if lab.run(["pg_isready", "-q", "-h", "127.0.0.1"]).returncode != 0:
            raise BenchError("postgres is not accepting connections: systemctl start postgresql")
        if "copy" in self.noise:
            last = lab.run(["env", *PG_ENV, "psql", "-XtAc", f"select to_regclass('bulk_{self.k}')", "bench"])
            if not BULK_CSV.is_file() or last.stdout.strip() != f"bulk_{self.k}":
                raise BenchError(f"{BULK_CSV} or table bulk_{self.k} missing; run bench/setup.sh first")

    @staticmethod
    def parse_load(out: Path, base: str) -> dict[str, float]:
        logs = [f.read_text(errors="replace") for f in sorted(out.glob(f"{base}.pgbench.*"))]
        return parse_pgbench((out / f"{base}.load.txt").read_text(errors="replace"), logs)

    def calibrate(self, lab: Lab) -> int:
        """Highest transaction rate postgres sustains alone (no --rate)."""
        res = lab.run(self.load_cmd(rate=0, duration=20))
        m = re.search(r"^tps = ([\d.]+)", res.stdout, re.M)
        if res.returncode != 0 or not m:
            raise BenchError(f"pgbench exited {res.returncode}, last lines:\n{_tail(res)}")
        best = int(float(m[1]))
        print(f"postgres alone: {best} transactions/s at saturation ({self.clients} clients)")
        print(f"suggested: --rate {max(100, round(best * 0.2, -2)):.0f}, then check `alone` stays far from saturation")
        return best


SCENARIOS = {"s1": S1, "s2": S2}


def _need_tools(*names: str) -> None:
    if missing := [n for n in ("scx_layered", *names) if not shutil.which(n)]:
        raise BenchError(f"not found: {', '.join(missing)}; run bench/setup.sh first")


def _tail(res: subprocess.CompletedProcess, n: int = 25) -> str:
    return "\n".join((res.stdout + res.stderr).strip().splitlines()[-n:])


# ------------------------------------------------------------------ running

@dataclass
class Bench:
    lab: Lab
    scenario: S1 | S2
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
        self.scenario.preflight(self.lab)
        if "iawp" in self.arms and not Path(self.iawp).exists():
            raise BenchError(f"iawp not found at {self.iawp}; pass --iawp")
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
            res = self.lab.run(self.scenario.load_cmd(log=self.out / base), self.out / f"{base}.load.txt")
            if res.returncode != 0:
                raise BenchError(f"the load generator failed; see {base}.load.txt")
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
            "service": _first_line(s.VERSION),
            "load": " ".join(s.load_cmd()),
            "noise": [" ".join(cmd) for _, cmd, _ in s.noise_cmds()],
            "pre_seconds": s.pre,
            "hand_config": str(s.hand_config),
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


# ------------------------------------------------------------------ summary

METRICS = [  # key, label, format
    ("p50", "p50 ms", "{:.2f}"),
    ("p99", "p99 ms", "{:.2f}"),
    ("p999", "p99.9 ms", "{:.2f}"),
    ("rps", "req/s", "{:.0f}"),
    ("stress_ops", "stress ops/s", "{:.0f}"),
    ("builds_min", "builds/min", "{:.1f}"),
    ("dumps_min", "dumps/min", "{:.1f}"),
    ("copies_min", "copies/min", "{:.1f}"),
]
NOISE_METRICS = {  # noise source -> (metric, parser of its output file)
    "stress": ("stress_ops", parse_stress),
    "build": ("builds_min", parse_count),
    "backup": ("dumps_min", parse_count),
    "copy": ("copies_min", parse_count),
}


def scenario_of(out: Path) -> type[S1] | type[S2]:
    meta = out / "meta.json"
    name = json.loads(meta.read_text()).get("scenario", "s1") if meta.exists() else "s1"
    return SCENARIOS[name]


def collect(out: Path) -> list[dict]:
    scenario = scenario_of(out)
    rows = []
    for f in sorted(out.glob("*-*.load.txt")):
        base = f.name[: -len(".load.txt")]
        arm, run = base.rsplit("-", 1)
        row: dict = {"arm": arm, "run": int(run), **scenario.parse_load(out, base)}
        for kind, (key, parse) in NOISE_METRICS.items():
            if (p := out / f"{base}.{kind}.txt").exists() and (v := parse(p.read_text(errors="replace"))) is not None:
                row[key] = v
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


def render_table(summary: dict[str, dict], source: str = S1.NOTE) -> str:
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
    note = f"median [min..max] across runs; {source}"
    if errors:
        note += "\nrequest errors: " + ", ".join(f"{a} {n}" for a, n in errors.items())
    return text + "\n\n" + note


def write_summary(out: Path) -> str:
    summary = summarize(collect(out))
    if not summary:
        raise BenchError(f"no results in {out}")
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    table = render_table(summary, scenario_of(out).NOTE)
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
    for name, help_, unit in (("s1", "web: nginx + wrk2 under stress-ng and a compile loop", "wrk2 requests"),
                              ("s2", "database: postgres + pgbench under a backup and a bulk load", "pgbench transactions")):
        cls = SCENARIOS[name]
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("action", nargs="?", choices=["run", "calibrate"], default="run")
        sp.add_argument("--rate", type=int, help=f"{unit} per second (see `calibrate`)")
        sp.add_argument("--runs", type=int, default=5)
        sp.add_argument("--duration", type=int, default=30, help="measured seconds per run (default: %(default)s)")
        sp.add_argument("--pre", type=int, default=20, help="seconds of noise before measuring (default: %(default)s)")
        sp.add_argument("--noise", default=",".join(cls.NOISE), help="noise sources (default: %(default)s)")
        sp.add_argument("--hand-config", type=Path, default=cls.hand_config,
                        help="hand-written membership; layer policies still come from --template")
        sp.add_argument("--label", help="suffix for the results directory name")
        sp.add_argument("--arms", default=",".join(ARMS), help="comma-separated subset of %(default)s")
        sp.add_argument("--iawp", default=default_iawp(), help="iawp executable (default: %(default)s)")
        sp.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE,
                        help="layer policies for both hand and iawp (default: iawp's built-in)")
        sp.add_argument("--out", help=f"results directory (default: bench/results/<time>-{name})")
        sp.add_argument("--dry-run", action="store_true", help="print the actions without running anything")
        if name == "s2":
            sp.add_argument("--streams", type=int, default=0,
                            help="parallel backups and parallel bulk loads (default: half the CPUs each)")
    sm = sub.add_parser("summarize", help="rebuild summary.txt and summary.json from a results directory")
    sm.add_argument("dir")
    args = p.parse_args(argv)

    try:
        if args.cmd == "summarize":
            print(write_summary(Path(args.dir)))
            return 0
        cls = SCENARIOS[args.cmd]
        lab = DryLab() if args.dry_run else Lab()
        if args.action == "calibrate":
            cls(rate=0).calibrate(lab)
            return 0
        if not args.rate:
            p.error(f"--rate is required; run `bench/run.py {args.cmd} calibrate` to choose one")
        arms = tuple(a for a in args.arms.split(",") if a)
        if bad := [a for a in arms if a not in ARMS]:
            p.error(f"unknown arms: {', '.join(bad)}")
        noise = tuple(n for n in args.noise.split(",") if n)
        if bad := [n for n in noise if n not in cls.NOISE]:
            p.error(f"unknown noise sources: {', '.join(bad)}")
        label = f"-{args.label}" if args.label else ("" if args.template == DEFAULT_TEMPLATE else f"-{args.template.stem}")
        out = Path(args.out) if args.out else HERE / "results" / f"{time.strftime('%Y%m%d-%H%M%S')}-{args.cmd}{label}"
        extra = {"streams": args.streams} if args.cmd == "s2" else {}
        scenario = cls(args.rate, args.duration, args.pre, hand_config=args.hand_config.resolve(), noise=noise, **extra)
        bench = Bench(lab, scenario, out, args.iawp,
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
