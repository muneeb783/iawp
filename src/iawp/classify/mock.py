"""Rule-based stand-in for a model. Used in tests, CI and offline demos.

Deliberately simple: known binary names, plus command-line keywords for
generic interpreters like python or java. Anything else reports low
"enough information", which policy turns into `unknown`.
"""

from __future__ import annotations

import posixpath

from iawp.classify.base import Classification
from iawp.taxonomy import CLASSES

NAMES: dict[str, set[str]] = {
    "latency-critical": {
        "nginx", "haproxy", "envoy", "caddy", "httpd", "apache2", "traefik",
        "postgres", "mysqld", "mariadbd", "redis-server", "memcached", "mongod",
        "etcd", "kube-apiserver", "coredns", "php-fpm", "uvicorn", "gunicorn", "schbench",
    },
    "batch-compute": {
        "make", "cc1", "cc1plus", "gcc", "g++", "clang", "ld", "rustc", "cargo",
        "javac", "ffmpeg", "x264", "stress-ng", "blender", "bazel", "ninja",
    },
    "io-data": {
        "rsync", "tar", "pg_dump", "pg_basebackup", "mysqldump", "dd", "rclone",
        "restic", "borg", "zstd", "gzip", "xz",
    },
    "background": {
        "cron", "crond", "node_exporter", "fluent-bit", "fluentd", "telegraf",
        "systemd-journal", "rsyslogd", "unattended-upgr", "packagekitd", "snapd",
        "containerd", "dockerd", "kubelet",
    },
    "interactive": {
        "bash", "zsh", "sh", "fish", "tmux", "tmux: server", "screen", "sshd",
        "vim", "nvim", "emacs", "less", "htop", "top",
    },
}

# Interpreters whose name says nothing about the workload; look at arguments.
GENERIC = {"python", "python3", "node", "java", "ruby", "perl", "php", "dotnet", "bun", "deno"}
HINTS: dict[str, tuple[str, ...]] = {
    "latency-critical": ("serve", "server", "uvicorn", "gunicorn", "runserver", "api"),
    "batch-compute": ("train", "build", "compile", "benchmark", "simulate"),
    "io-data": ("backup", "etl", "ingest", "export", "sync"),
}

HIT, ENOUGH, NOT_ENOUGH = 0.97, 0.95, 0.2


class MockClassifier:
    name = "mock"

    def classify(self, state: dict[str, str]) -> Classification:
        cls = self._match(state)
        if cls is None:
            even = 1 / len(CLASSES)
            return Classification(next(iter(CLASSES)), {c: even for c in CLASSES}, NOT_ENOUGH, "mock-1")
        rest = (1 - HIT) / (len(CLASSES) - 1)
        probs = {c: (HIT if c == cls else rest) for c in CLASSES}
        return Classification(cls, probs, ENOUGH, "mock-1")

    def _match(self, state: dict[str, str]) -> str | None:
        # The process's own name comes first. A script run through an interpreter
        # often has a telling name ("unattended-upgr") while its exe is just
        # /usr/bin/python3, and exe is only readable as root: checking exe first
        # made root scans worse than unprivileged ones.
        names = [state.get("process_name", ""), posixpath.basename(state.get("executable", ""))]
        for name in names:
            if _generic(name):
                continue
            for cls, known in NAMES.items():
                if name in known:
                    return cls
        if any(_generic(n) for n in names):
            args = state.get("command_line", "").lower()
            for cls, words in HINTS.items():
                if any(w in args for w in words):
                    return cls
        return None


def _generic(name: str) -> bool:
    return name in GENERIC or name.startswith("python")
