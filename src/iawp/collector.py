"""Collect per-process facts from /proc. Needs no root.

Everything here is a plain file read. Without root, /proc/<pid>/exe is
unreadable for other users' processes, so `exe` may be None; cmdline,
status and cgroup are world-readable.
"""

from __future__ import annotations

import dataclasses
import os
import pwd
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

KTHREADD_PID = 2


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    comm: str  # kernel task name, max 15 chars; what scx_layered's PcommPrefix sees
    exe: str | None  # resolved executable path, None if unreadable
    cmdline: tuple[str, ...]  # raw argv; redact before showing it to any model
    cgroup: str  # cgroup v2 path without leading '/', e.g. "system.slice/nginx.service"
    uid: int  # effective uid, matching scx_layered's UIDEquals
    user: str
    kernel_thread: bool
    parent_comm: str | None = None


def collect(proc_root: Path = Path("/proc")) -> list[ProcessRecord]:
    """Snapshot every process under proc_root, skipping ones that exit mid-read."""
    records = []
    for entry in os.scandir(proc_root):
        if not entry.name.isdigit():
            continue
        try:
            records.append(read_process(proc_root, int(entry.name)))
        except (FileNotFoundError, ProcessLookupError):
            continue  # exited between scandir and read

    comm_of = {r.pid: r.comm for r in records}
    return sorted(
        (dataclasses.replace(r, parent_comm=comm_of.get(r.ppid)) for r in records),
        key=lambda r: r.pid,
    )


def read_process(proc_root: Path, pid: int) -> ProcessRecord:
    base = proc_root / str(pid)
    status = _parse_status((base / "status").read_text(errors="replace"))
    ppid = int(status.get("PPid", "0"))
    uids = status.get("Uid", "0").split()  # real, effective, saved, filesystem
    uid = int(uids[1] if len(uids) > 1 else uids[0])
    cmdline = _read_cmdline(base / "cmdline")
    return ProcessRecord(
        pid=pid,
        ppid=ppid,
        comm=status.get("Name", ""),
        exe=_read_exe(base / "exe"),
        cmdline=cmdline,
        cgroup=_read_cgroup(base / "cgroup"),
        uid=uid,
        user=_user_name(uid),
        kernel_thread=not cmdline and KTHREADD_PID in (pid, ppid),
    )


def _parse_status(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key] = value.strip()
    return out


def _read_cmdline(path: Path) -> tuple[str, ...]:
    raw = path.read_bytes()
    if not raw:
        return ()
    return tuple(a.decode(errors="replace") for a in raw.rstrip(b"\0").split(b"\0"))


def _read_exe(path: Path) -> str | None:
    try:
        return os.readlink(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _read_cgroup(path: Path) -> str:
    try:
        lines = path.read_text().splitlines()
    except PermissionError:
        return ""
    # cgroup v2 is the single "0::<path>" line; fall back to the first v1 line.
    for line in lines:
        if line.startswith("0::"):
            return line[3:].lstrip("/")
    return lines[0].split(":", 2)[-1].lstrip("/") if lines else ""


@lru_cache(maxsize=None)
def _user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)
