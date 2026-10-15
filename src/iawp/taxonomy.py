"""Process classes, the one-line descriptions a classifier sees, and their layers.

Option order is fixed: SystemOne-style models shift probabilities when options
are reordered, so every request must present them identically.
"""

from __future__ import annotations

UNKNOWN = "unknown"

# Order matters (see module docstring). `unknown` is not offered as an option;
# it is what a process gets when the classifier cannot or should not decide.
CLASSES: dict[str, str] = {
    "latency-critical": "Serves requests where a user or another service waits on each response: web and API servers, databases answering queries, proxies, RPC services.",
    "interactive": "Driven directly by a person at a terminal or desktop: shells, editors, ssh sessions, terminal UIs.",
    "batch-compute": "CPU-heavy work judged by total throughput, not response time: builds and compilers, model training, encoding, simulations, stress tests.",
    "io-data": "Moves or transforms data and mostly waits on disk or network: backups, rsync, bulk loads, ETL, compaction.",
    "background": "Low-priority housekeeping that runs continuously or on a timer: monitoring agents, log shippers, cron jobs, update checkers.",
}

# Layer names match the lab-tested template in templates/layers.json.
LAYER_OF: dict[str, str] = {
    "latency-critical": "critical",
    "batch-compute": "batch",
    "background": "batch",
    "interactive": "default",
    "io-data": "default",
    UNKNOWN: "default",
}

LAYER_ORDER = ["critical", "batch", "default"]
