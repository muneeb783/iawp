# Phase 0 lab notebook

Lab: GCP c3-standard-8 (8 vCPU = 4 cores x 2 SMT, Xeon Platinum 8481C), Ubuntu 26.04,
kernel 7.0.0-1014-gcp, scx_layered 1.1.3 built from sched-ext/scx.
Workload: `schbench -m 2 -t 4 -R <rps>`. Noise: `stress-ng --cpu 8`.

## 2026-10-13

**Calibration (idle, unbounded):** ~1546 rps max; each request is ~5 ms of CPU.

**schbench wakeup latency is useless with `-R`.** Fixed-rate mode records only tens of
wakeup samples per run (0 in one run), so p99 = p99.9 = max. Use request latency
p99/p99.9 plus achieved rps as the headline metrics.

**RPS=900 was too heavy** (~4.5 CPUs, 56% of the box). Moved to RPS=400 (~2 CPUs idle,
~3 CPUs under SMT contention): a small service next to a big batch job.

**Fixed partitions lose to the default scheduler.** With batch `Confined` to 6 or 4 CPUs,
the fence is protected both ways (`prot=100` in `--stats`): critical cannot preempt into
batch's CPUs, so it saturates its own slice (util 200% on 2 CPUs) and queues.
s1-hand: 203 rps achieved of 400, p99 240 ms.

**SMT inflates service CPU demand ~50%.** 400 rps took ~3.1 CPUs under layered with busy
siblings vs ~2 CPUs idle.

**Priority beats partitioning.** 1 run x 10 s each, RPS=400:

| arm | req p50 | req p99 | req p99.9 | rps | batch ops/s |
|---|---|---|---|---|---|
| alone | 4.6 ms | 5.1 ms | 5.3 ms | 430 | - |
| noise (EEVDF) | 10.1 ms | 47.9 ms | 106 ms | 400 | 8032 |
| b: batch Confined <=4 | 11.0 ms | 55.5 ms | 76.7 ms | 428 | 5055 |
| **d: critical Open+preempt, batch Open w=50** | **4.7 ms** | **15.1 ms** | **25.7 ms** | 404 | **8327** |
| e: critical Grouped 2-6 | 7.6 ms | 47.2 ms | 97.7 ms | 406 | 7649 |
| f: d + exclusive | 5.0 ms | 24.4 ms | 56.0 ms | 408 | 8070 |

`s1-hand-d` is the hand-tuned reference. Implication for iawp's generator: emit d's
shape and let the classifier decide only membership.

Open questions: remaining p99 gap vs alone (likely SMT sibling interference);
noise-arm variance between runs is large (p99 13 ms vs 48 ms), so use 5+ runs.

**Correction after 5 x 30 s runs (results/20261013-195733).** The single 10 s run above
overstated d's p99 win; that noise run was an outlier.

| arm | req p50 | req p99 | req p99.9 | rps | batch ops/s |
|---|---|---|---|---|---|
| alone | 4.7 ms | 5.1 [5.1..5.2] | 5.6 [5.2..5.7] | 410 | - |
| noise | 8.8 ms | 14.1 [13.9..26.5] | 42.7 [39.7..66.7] | 400 | 7680 |
| d | 4.7 ms | 14.7 [11.3..15.9] | 26.8 [21.5..28.3] | 412 | 7799 |

Clear wins at p50 and p99.9 (non-overlapping ranges); p99 is flat. Hypothesis: the 0.8 ms
critical slice chops 5 ms requests so critical threads queue behind each other.
Testing g (default 20 ms slice) and h (5 ms).

**Slice was the culprit (results/20261013-200908, 3 x 30 s).**

| arm | req p50 | req p99 | req p99.9 | rps | batch ops/s |
|---|---|---|---|---|---|
| alone | 4.9 ms | 5.2 [5.2..5.2] | 5.4 [5.3..5.5] | 410 | - |
| noise | 8.8 ms | 22.1 [21.8..27.9] | 47.0 [43.5..65.2] | 400 | 7821 |
| d (0.8 ms slice) | 4.8 ms | 13.2 [11.8..16.5] | 26.0 [24.5..28.9] | 413 | 7776 |
| **g (20 ms default slice)** | **4.7 ms** | **5.2 [5.2..5.2]** | **5.4 [5.4..10.5]** | 412 | **7836** |
| h (5 ms slice) | 5.1 ms | 5.2 [5.2..5.3] | 6.0 [5.3..10.6] | 413 | 7758 |

With g, p99 under full CPU noise matches the alone baseline; batch throughput unchanged.
`s1-hand-g` is the hand-tuned reference. Lesson for the generator: layer knobs (slice,
kind, preempt) are workload-sensitive, so keep them in a lab-tested template and let the
classifier decide only membership.

**Gate 1: PASS (results/20261013-202048, 5 x 30 s, interleaved).**

| arm | req p50 | req p99 | req p99.9 | rps | batch ops/s |
|---|---|---|---|---|---|
| alone | 5.0 ms | 5.2 [5.18..5.24] | 5.7 [5.5..5.8] | 411 | - |
| noise | 9.3 ms | 23.8 [21.7..39.9] | 61.4 [45.0..78.0] | 400 | 7662 |
| hand-g | 4.9 ms | 5.2 [5.18..5.29] | 10.0 [5.4..10.1] | 411 | 7792 |

p99 4.6x better than EEVDF under noise and equal to alone; p99.9 6x better; batch
throughput unchanged. Residual: p99.9 ~10 ms in 4 of 5 runs (about one extra request of
queueing) vs 5.7 ms alone.

Not yet covered (plan asks for these; add in Phase 2's harness): compile-job noise,
runqlat / perf sched views of run-queue delay, S2 database scenario.
