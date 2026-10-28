# v0.1 baseline — UiS pitter VMs, 2026-10-04

Code: v0.1 (0448a43) + a latency patch (measurement only).

Metrics:
- blocks/s: per replica (sweep's own THROUGHPUT column is the sum over n).
- commands/s: from the `committed N (M commands)` line in `<suite>/logs/`.
- latency: propose → commit of each block, measured at the replica that
  proposed it, on its own clock (no cross-host clock involved).
- `-workers` is diem's batch (commands per proposal), not client concurrency.
- `-rate` is a token bucket **per replica**; offered load ≈ n × rate.

All runs: 20 s, 3 reps, n=4 on pitter1–4, 0 failed, 0 degraded.

## load (n=4, unthrottled)

| batch | payload | blocks/s | kcmd/s | p50 ms | p99 ms |
|---|---|---|---|---|---|
| 1   | 128  | 110.5 | 0.11  | 20.3  | 23.1  |
| 1   | 1024 | 103.6 | 0.10  | 21.8  | 24.0  |
| 1   | 4096 | 100.2 | 0.10  | 22.5  | 24.6  |
| 16  | 128  | 102.0 | 1.63  | 22.1  | 24.3  |
| 16  | 1024 | 88.3  | 1.41  | 25.5  | 27.6  |
| 16  | 4096 | 57.7  | 0.92  | 39.3  | 43.3  |
| 256 | 128  | 68.5  | 17.55 | 33.3  | 37.1  |
| 256 | 1024 | 24.4  | 6.25  | 93.7  | 99.0  |
| 256 | 4096 | 7.6   | 1.96  | 301.0 | 320.5 |

## rate (n=4, payload 1024, batch 256)

| rate/replica | offered ≈ | blocks/s | kcmd/s | p50 ms | p99 ms |
|---|---|---|---|---|---|
| 500       | 2k  | 80.5 | 1.86 | 27.4 | 37.4 |
| 2000      | 8k  | 24.9 | 6.20 | 93.3 | 99.2 |
| 8000      | 32k | 24.7 | 6.28 | 93.1 | 99.4 |
| unlimited | —   | 25.2 | 6.45 | 90.3 | 98.5 |

Saturation at n=4, 1 KiB: ≈ 6.3k cmd/s (≈ 6.4 MB/s of payload). There are no
points between 2k and 8k offered, so the knee itself is not located. Past
saturation latency rises because blocks fill (bigger blocks commit slower),
not because of queueing — v0.1 has no command queue.

Repeatability: rep-to-rep spread mostly < 1 %; the same config in load and rate
gave 24.4 vs 25.2 blocks/s.

## Bottleneck probe (`probe/`)

n=4, 4 KiB × 256 (1 MiB blocks): 7.8 blocks/s, 2.0k cmd/s, p50 303 ms.

| | used | capacity |
|---|---|---|
| CPU per VM | ≈ 0.45 core of diem, no thread > 16 % | 8 cores (Xeon E5-2609, no SHA-NI), 91 % idle |
| network per VM | ≈ 6.5 MB/s each way (≈ 55 Mbit/s) | 1 Gbit, 5.6 % |
| RTT pitter↔pitter | 0.39 ms | |

Round time ≈ 128 ms against ≈ 25 ms to put 1 MiB on the wire to 3 peers.
Even at batch 1 a round takes ≈ 10 ms against a 0.4 ms RTT. Neither CPU nor
network is saturated: the replicas are **waiting**, not working. Cause not yet
found (an execution trace was the next step).

Laptop, same code, 4 replicas in one process (`-local 4`): 43k / 34k / 18k
cmd/s at 128 / 1024 / 4096 B, batch 256 — 2.4–9× the VMs. Its CPU profile:
ECDSA verify ≈ 24 %, SHA-256 of payloads ≈ 23 % (each payload hashed twice per
replica: block id + execution state), memmove ≈ 18 %, syscalls ≈ 14 %.

## What this supports comparing later

- Blocks/s, cmd/s and propose→commit latency at n=4 across payload × batch,
  with variance — good for the wire-layer and named-type experiments, provided
  each experiment branch carries the same instrumentation patch.
- Not supported: scaling with n (scale suite not run), long-run stability, a
  located saturation knee, client-perceived latency (there is no client).
- Caveat: at large blocks the VMs are wait-bound, so CPU savings (e.g. fewer
  copies in the wire layer) may not show up as throughput there; compare
  latency at small blocks and laptop `-local` profiles as well.
