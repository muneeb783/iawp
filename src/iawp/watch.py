"""Keep the applied config current as programs start and stop: `iawp watch`.

The kernel's process connector reports every exec (a process starting a new
program) and every rename over a netlink socket. Most of them change nothing:
scx_layered already places a new process that matches an existing rule, so a
tenth nginx worker or another cc1 needs no new config. Only a new kind of
program (a name and cgroup not seen at the last scan) leads to a rescan.

A rescan classifies through the cache and builds a config exactly as `apply`
does. Since applying restarts scx_layered (about 1 s on the kernel's default
scheduler), changes are rate-limited by a cooldown, and a rule stays for a
while after its last process exits so short-lived jobs do not cause restarts
twice. Critical placements are never approved here: there is nobody to ask,
so they wait in pending.json until an operator runs `iawp apply`.

Without the process connector (not Linux, not root, or a kernel without it),
new pids are found by polling /proc instead.
"""

from __future__ import annotations

import errno
import json
import os
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from iawp import apply as applier
from iawp.classify import ClassifierError
from iawp.collector import ProcessRecord, read_process
from iawp.emit import Rule, build_config, render

# linux/connector.h and linux/cn_proc.h
NETLINK_CONNECTOR = 11
CN_IDX_PROC = CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
NLMSG_DONE = 3
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_COMM = 0x00000200

_NLMSGHDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
_CN_MSG = struct.Struct("=IIIIHH")  # idx, val, seq, ack, len, flags
_PROC_EVENT = struct.Struct("=IIQii")  # what, cpu, timestamp_ns, then process_pid, process_tgid for exec and comm


@dataclass(frozen=True)
class Timing:
    settle: float = 2.0  # after the first event, wait this long so a burst of execs costs one rescan
    cooldown: float = 120.0  # at least this long between two restarts of scx_layered
    sticky: float = 3600.0  # keep a rule this long after its last process exits
    rescan: float = 300.0  # rescan this often anyway: catches missed events and expires sticky rules


@dataclass(frozen=True)
class Snapshot:
    """One scan: rules ready to apply, and what was running."""

    rules: list[Rule]  # after the critical gate
    held: list[str]  # critical rules waiting for an operator's approval
    procs: list[ProcessRecord]  # user-space processes seen


# ------------------------------------------------------------------ process connector

def subscribe_message(pid: int) -> bytes:
    payload = struct.pack("=I", PROC_CN_MCAST_LISTEN)
    cn = _CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0)
    size = _NLMSGHDR.size + len(cn) + len(payload)
    return _NLMSGHDR.pack(size, NLMSG_DONE, 0, 0, pid) + cn + payload


def parse_events(data: bytes) -> list[int]:
    """Pids (thread group ids) that exec'd or were renamed, from one netlink read."""
    pids = []
    offset = 0
    while offset + _NLMSGHDR.size <= len(data):
        size = _NLMSGHDR.unpack_from(data, offset)[0]
        if size < _NLMSGHDR.size or offset + size > len(data):
            break  # malformed or truncated; drop the rest rather than misread or loop forever
        body = offset + _NLMSGHDR.size + _CN_MSG.size
        if body + _PROC_EVENT.size <= offset + size:
            what, _cpu, _ts, _pid, tgid = _PROC_EVENT.unpack_from(data, body)
            if what in (PROC_EVENT_EXEC, PROC_EVENT_COMM):
                pids.append(tgid)
        offset += (size + 3) & ~3  # NLMSG_ALIGN
    return pids


class ProcConnector:
    """Exec and rename events straight from the kernel. Needs root and Linux."""

    name = "process connector"

    def __init__(self) -> None:
        family = getattr(socket, "AF_NETLINK", None)
        if family is None:
            raise OSError("no netlink sockets on this platform")
        self.sock = socket.socket(family, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            self.sock.bind((0, CN_IDX_PROC))
            self.sock.send(subscribe_message(self.sock.getsockname()[0]))
        except OSError:
            self.sock.close()
            raise

    def wait(self, timeout: float) -> list[int] | None:
        """Pids with events, [] on timeout, None if the kernel dropped events."""
        ready, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        pids: list[int] = []
        while ready:
            try:
                data = self.sock.recv(1 << 16, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
            except OSError as e:
                if e.errno == errno.ENOBUFS:  # we fell behind and the kernel dropped some
                    return None
                raise
            pids += parse_events(data)
        return pids


class ProcPoller:
    """Fallback: notice new pids by listing /proc every few seconds."""

    name = "polling /proc"

    def __init__(self, proc_root: Path, interval: float = 5.0, sleep: Callable[[float], None] = time.sleep):
        self.proc_root, self.interval, self.sleep = proc_root, interval, sleep
        self.seen = self._pids()

    def _pids(self) -> set[int]:
        return {int(e.name) for e in os.scandir(self.proc_root) if e.name.isdigit()}

    def wait(self, timeout: float) -> list[int] | None:
        self.sleep(max(0.0, min(timeout, self.interval)))
        now = self._pids()
        new, self.seen = sorted(now - self.seen), now
        return new


def event_source(proc_root: Path, poll: bool = False):
    if not poll:
        try:
            return ProcConnector()
        except OSError as e:
            print(f"iawp: process connector unavailable ({e}); polling /proc instead", file=sys.stderr)
    return ProcPoller(proc_root)


# ------------------------------------------------------------------ the loop

@dataclass
class Watcher:
    host: applier.Host
    scan: Callable[[], Snapshot]
    timing: Timing = field(default_factory=Timing)
    log: Callable[[str], None] = print
    template: dict[str, dict] | None = None  # layer policies; None: the built-in template

    dirty_since: float | None = None
    next_rescan: float = 0.0  # 0: scan on the first step
    last_apply: float = float("-inf")
    want: str | None = None  # config waiting for the cooldown
    known: set[tuple[str, str]] = field(default_factory=set)  # (name, cgroup) seen at the last scan
    remembered: dict[tuple[str, str], tuple[Rule, float]] = field(default_factory=dict)  # rule -> last seen
    held: list[str] = field(default_factory=list)
    waiting_logged: bool = False

    def notice(self, now: float, pid: int) -> None:
        """An exec or rename. Rescan only for a new kind of program."""
        try:
            r = read_process(self.host.proc_root, pid)
        except OSError:
            return  # already gone: too short-lived to matter to the scheduler
        if r.kernel_thread or _kind(r) in self.known:
            return
        self.mark(now)

    def mark(self, now: float) -> None:
        if self.dirty_since is None:
            self.dirty_since = now

    def due(self) -> float:
        """When step() next has something to do."""
        times = [self.next_rescan]
        if self.dirty_since is not None:
            times.append(self.dirty_since + self.timing.settle)
        if self.want is not None:
            times.append(self.last_apply + self.timing.cooldown)
        return min(times)

    def step(self, now: float) -> None:
        settled = self.dirty_since is not None and now >= self.dirty_since + self.timing.settle
        if settled or now >= self.next_rescan:
            self._rescan(now)
        if self.want is not None:
            self._apply(now)

    def _rescan(self, now: float) -> None:
        self.dirty_since = None
        self.next_rescan = now + self.timing.rescan
        try:
            snap = self.scan()
        except ClassifierError as e:
            self.log(f"classifier failed, keeping the current config: {e}")
            return
        self.known = {_kind(p) for p in snap.procs}
        if snap.held != self.held:
            for label in sorted(set(snap.held) - set(self.held)):
                self.log(f"held back {label}: critical placements need approval; run `iawp apply` in a terminal")
            self.held = snap.held
            applier.save_pending(self.host, snap.held, now)
        text = render(build_config(self._with_sticky(now, snap), self.template))
        self.want = None if self._in_effect(text) else text
        self.waiting_logged = False

    def _with_sticky(self, now: float, snap: Snapshot) -> list[Rule]:
        """Add back rules whose processes all exited less than `sticky` seconds ago.

        Only while no running process matches them: a rule that the plan
        dropped for a live process (reclassified, or now a conflict) must go.
        """
        rules = list(snap.rules)
        present = {(r.kind, r.value) for r in rules}
        for r in rules:
            self.remembered[(r.kind, r.value)] = (r, now)
        for key, (r, seen) in sorted(self.remembered.items()):
            if key in present:
                continue
            if now - seen > self.timing.sticky or _captures(r, snap.procs):
                del self.remembered[key]
                continue
            rules.append(Rule(r.layer, r.kind, r.value, (), f"kept for now: its processes exited {now - seen:.0f} s ago"))
        return rules

    def _in_effect(self, text: str) -> bool:
        return text == applier.current_config(self.host) and applier.sched_state(self.host).layered

    def _apply(self, now: float) -> None:
        ready = self.last_apply + self.timing.cooldown
        if now < ready:
            if not self.waiting_logged:
                self.log(f"config changed; applying in {ready - now:.0f} s (cooldown between restarts)")
                self.waiting_logged = True
            return
        text, self.want = self.want, None
        self.last_apply = now
        before = applier.current_config(self.host)
        try:
            self.log(f"{applier.apply(self.host, text)} ({rule_changes(before, text)})")
        except applier.ApplyError as e:
            self.log(f"apply failed: {e}")


def run(watcher: Watcher, events, now: Callable[[], float] = time.time) -> None:
    """Forever: wait for events or the next deadline, then step."""
    watcher.log(f"watching for new programs ({events.name}); Ctrl-C to stop")
    watcher.step(now())
    while True:
        pids = events.wait(watcher.due() - now())
        t = now()
        if pids is None:
            watcher.log("the kernel dropped process events; rescanning everything")
            watcher.mark(t - watcher.timing.settle)
        else:
            for pid in pids:
                watcher.notice(t, pid)
        watcher.step(t)


def rule_changes(old: str | None, new: str) -> str:
    """"+batch PcommPrefix crunch, -batch PcommPrefix make": what an apply changed, for the log."""
    def matches(text: str | None) -> set[tuple[str, str]]:
        try:
            layers = json.loads(text or "[]")
        except ValueError:
            return set()
        return {(layer["name"], f"{kind} {value}")
                for layer in layers for match in layer["matches"] for cond in match for kind, value in cond.items()}

    o, n = matches(old), matches(new)
    changes = [f"+{layer} {m}" for layer, m in sorted(n - o)] + [f"-{layer} {m}" for layer, m in sorted(o - n)]
    return ", ".join(changes) or "same rules"


def _kind(p: ProcessRecord) -> tuple[str, str]:
    # Raw cgroup, not blurred like the cache key: a new container is a new
    # cgroup that needs its own CgroupPrefix rule, so it must cause a rescan.
    return p.comm, p.cgroup


def _captures(rule: Rule, procs: list[ProcessRecord]) -> bool:
    if rule.kind == "PcommPrefix":
        return any(p.comm.startswith(rule.value) for p in procs)
    if rule.kind == "CgroupPrefix":
        return any((p.cgroup + "/").startswith(rule.value) for p in procs)
    return True  # a kind we cannot check: do not keep it around blindly
