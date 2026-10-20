"""Load generated configs into scx_layered, safely and reversibly.

scx_layered (checked in 1.1.3) reads its config once at startup and cannot
reload it, so applying a change means restarting it; the kernel runs its
default scheduler for that moment. Hence: apply only real changes, validate
before loading, verify after, and roll back automatically when the new config
does not come up.

State (root only), in /var/lib/iawp:
  configs/<time>.json   every applied config, newest last (the rollback history)
  current.json          symlink to the config the service runs
  approvals.json        critical placements an operator approved

scx_layered runs as the systemd unit iawp-scx.service, so crashes restart it
and its log lands in the journal. The unit is not enabled at boot: a stale
config should not load itself after a reboot.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from iawp.emit import Rule

UNIT = "iawp-scx.service"
KEEP_CONFIGS = 20


class ApplyError(RuntimeError):
    """Apply refused or failed; the message says why and what was done about it."""


@dataclass
class Host:
    """Everything apply touches on the machine, so tests can point it elsewhere."""

    state_dir: Path = Path("/var/lib/iawp")
    sched_ext: Path = Path("/sys/kernel/sched_ext")
    unit_dir: Path = Path("/etc/systemd/system")
    proc_root: Path = Path("/proc")
    settle_seconds: float = 10.0

    def run(self, *cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True)

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def now(self) -> float:
        return time.time()

    # -- derived paths
    @property
    def configs(self) -> Path:
        return self.state_dir / "configs"

    @property
    def current(self) -> Path:
        return self.state_dir / "current.json"

    @property
    def unit_path(self) -> Path:
        return self.unit_dir / UNIT


@dataclass
class SchedState:
    state: str  # enabled, disabled, enabling, disabling
    ops: str  # name of the loaded BPF scheduler, "" when none

    @property
    def layered(self) -> bool:
        return self.state == "enabled" and self.ops.startswith("layered")


def sched_state(host: Host) -> SchedState:
    state = (host.sched_ext / "state").read_text().strip()
    ops_file = host.sched_ext / "root" / "ops"
    ops = ops_file.read_text().strip() if ops_file.exists() else ""
    return SchedState(state, ops)


def preflight(host: Host) -> str:
    """Refuse early, with a reason, instead of failing halfway. Returns the scx_layered path."""
    if not host.is_root():
        raise ApplyError("apply needs root: it starts a scheduler and writes /var/lib/iawp")
    if not (host.sched_ext / "state").exists():
        raise ApplyError(f"this kernel has no sched_ext ({host.sched_ext} missing); it needs Linux 6.12 or newer")
    scx = host.which("scx_layered")
    if not scx:
        raise ApplyError("scx_layered not found in PATH; install it from https://github.com/sched-ext/scx")
    if not host.which("systemctl"):
        raise ApplyError("apply runs scx_layered as a systemd service, and systemctl was not found")
    st = sched_state(host)
    if st.state == "enabled" and not _unit_active(host):
        raise ApplyError(f"another sched_ext scheduler is loaded ({st.ops or 'unknown'}); stop it first")
    return scx


# ------------------------------------------------------------------ approvals

@dataclass
class Approvals:
    """Critical placements an operator said yes to.

    Keyed two ways: by the rule, and by a fingerprint of each program file.
    A renamed copy of an approved program has a new name rule but the same
    fingerprint, so it does not need asking again.
    """

    rules: dict[str, dict] = field(default_factory=dict)  # "PcommPrefix schbench" -> info
    exe_sha256: dict[str, dict] = field(default_factory=dict)  # hash -> info

    @classmethod
    def load(cls, host: Host) -> "Approvals":
        path = host.state_dir / "approvals.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        return cls(data.get("rules", {}), data.get("exe_sha256", {}))

    def save(self, host: Host) -> None:
        host.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        _atomic_write(host.state_dir / "approvals.json",
                      json.dumps({"rules": self.rules, "exe_sha256": self.exe_sha256}, indent=1, sort_keys=True) + "\n")

    def covers(self, rule: Rule, hashes: list[str]) -> bool:
        if _rule_key(rule) in self.rules:
            return True
        return bool(hashes) and all(h in self.exe_sha256 for h in hashes)

    def approve(self, rule: Rule, hashes: list[str], names: str, when: float) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(when))
        self.rules[_rule_key(rule)] = {"names": names, "approved": stamp}
        for h in hashes:
            self.exe_sha256[h] = {"names": names, "approved": stamp}


def _rule_key(rule: Rule) -> str:
    return f"{rule.kind} {rule.value}"


def exe_hashes(host: Host, pids: tuple[int, ...]) -> list[str]:
    """SHA-256 of each distinct program file behind these pids; [] if any is unreadable."""
    seen: dict[str, str] = {}
    for pid in pids:
        exe = host.proc_root / str(pid) / "exe"
        try:
            target = os.readlink(exe)
            if target not in seen:
                h = hashlib.sha256()
                with open(exe, "rb") as f:  # through /proc, so a replaced file still hashes what runs
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                seen[target] = h.hexdigest()
        except OSError:
            return []
    return sorted(set(seen.values()))


# ------------------------------------------------------------------ configs

def current_config(host: Host) -> str | None:
    return host.current.read_text() if host.current.exists() else None


def history(host: Host) -> list[Path]:
    # Resolved, so they compare equal to the symlink target even if a parent dir is a symlink.
    return sorted(p.resolve() for p in host.configs.glob("*.json")) if host.configs.exists() else []


def validate(host: Host, scx: str, text: str) -> None:
    host.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = host.state_dir / "candidate.json"
    tmp.write_text(text)
    res = host.run(scx, "--print-and-exit", f"f:{tmp}")
    if res.returncode != 0:
        raise ApplyError(f"scx_layered rejected the generated config:\n{(res.stderr or res.stdout).strip()[-800:]}")
    tmp.unlink()


def save(host: Host, text: str) -> Path:
    host.configs.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Names sort in apply order: rollback walks this order.
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(host.now()))
    # Number after the highest name in use, never into a gap left by pruning:
    # a reused low number would sort as oldest and be pruned while running.
    taken = [int(p.stem.rsplit("-", 1)[1]) for p in host.configs.glob(f"{stamp}-*.json")]
    path = host.configs / f"{stamp}-{max(taken, default=-1) + 1:02d}.json"
    path.write_text(text)
    for old in history(host)[:-KEEP_CONFIGS]:
        if old.resolve() != _target(host):
            old.unlink()
    return path


def point_current(host: Host, path: Path) -> None:
    """Swap the symlink atomically: the service never sees a missing or half-written file."""
    tmp = host.state_dir / "current.json.tmp"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(Path("configs") / path.name)  # relative, so moving state_dir keeps it valid
    os.replace(tmp, host.current)


def _target(host: Host) -> Path | None:
    return host.current.resolve() if host.current.is_symlink() else None


# ------------------------------------------------------------------ service

def ensure_unit(host: Host, scx: str) -> None:
    text = (
        "[Unit]\n"
        "Description=scx_layered with iawp-generated layers\n"
        "Documentation=https://github.com/muneeb783/iawp\n"
        "StartLimitIntervalSec=60\n"
        "StartLimitBurst=3\n"
        "\n"
        "[Service]\n"
        f"ExecStart={scx} f:{host.current}\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
    )
    if host.unit_path.exists() and host.unit_path.read_text() == text:
        return
    host.unit_path.write_text(text)
    _systemctl(host, "daemon-reload")


def _systemctl(host: Host, *args: str) -> None:
    res = host.run("systemctl", *args)
    if res.returncode != 0:
        raise ApplyError(f"systemctl {' '.join(args)} failed: {(res.stderr or res.stdout).strip()}")


def _unit_active(host: Host) -> bool:
    return host.run("systemctl", "is-active", "--quiet", UNIT).returncode == 0


def _wait_layered(host: Host) -> bool:
    waited = 0.0
    while waited < host.settle_seconds:
        if _unit_active(host) and sched_state(host).layered:
            return True
        host.sleep(0.25)
        waited += 0.25
    return False


def restart_with(host: Host, path: Path, previous: Path | None) -> None:
    """Point the service at `path` and restart; on failure go back to `previous`."""
    point_current(host, path)
    _systemctl(host, "reset-failed", UNIT)
    _systemctl(host, "restart", UNIT)
    if _wait_layered(host):
        return
    log = host.run("journalctl", "-u", UNIT, "-n", "20", "--no-pager").stdout.strip()
    if previous is None:
        host.run("systemctl", "stop", UNIT)
        raise ApplyError(f"scx_layered did not come up with {path.name}; stopped it, so the kernel uses its "
                         f"default scheduler.\n{log}")
    point_current(host, previous)
    _systemctl(host, "reset-failed", UNIT)
    _systemctl(host, "restart", UNIT)
    ok = _wait_layered(host)
    raise ApplyError(f"scx_layered did not come up with {path.name}; rolled back to {previous.name}"
                     f"{'' if ok else ' (which also failed to start)'}.\n{log}")


# ------------------------------------------------------------------ commands

def apply(host: Host, text: str) -> str:
    """Validate, save and load `text`. Returns a one-line outcome."""
    scx = preflight(host)
    if text == current_config(host) and sched_state(host).layered and _unit_active(host):
        return "no changes; scx_layered keeps running the current config"
    validate(host, scx, text)
    previous = _target(host)
    path = save(host, text)
    ensure_unit(host, scx)
    restart_with(host, path, previous)
    return f"applied {path.name}; scx_layered is running it"


def rollback(host: Host) -> str:
    scx = preflight(host)
    configs = history(host)
    target = _target(host)
    if target not in configs or configs.index(target) == 0:
        raise ApplyError("no earlier config to roll back to")
    previous = configs[configs.index(target) - 1]
    ensure_unit(host, scx)
    restart_with(host, previous, target)
    return f"rolled back from {target.name} to {previous.name}"


def stop(host: Host) -> str:
    if not host.is_root():
        raise ApplyError("stop needs root")
    host.run("systemctl", "stop", UNIT)
    for _ in range(int(host.settle_seconds / 0.25)):
        if not sched_state(host).layered:
            return "stopped scx_layered; the kernel is back on its default scheduler"
        host.sleep(0.25)
    raise ApplyError("scx_layered is still loaded after stopping the service")


def status(host: Host) -> str:
    st = sched_state(host) if (host.sched_ext / "state").exists() else SchedState("unavailable", "")
    target = _target(host)
    lines = [
        f"sched_ext:   {st.state}{f' ({st.ops})' if st.ops else ''}",
        f"service:     {UNIT} {'active' if _unit_active(host) else 'inactive'}",
        f"config:      {target.name if target else '(none applied yet)'}",
        f"history:     {len(history(host))} configs in {host.configs}",
    ]
    return "\n".join(lines)


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)
