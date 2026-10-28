# v0.2 variants vs v0.1 — UiS pitter VMs, 2026-10-06/07

Same matrix, metrics and caveats as `../v0.1/SUMMARY.md` (n=4 on pitter1–4,
20 s, 3 reps). All runs back to back in one session, 23:25–01:11, one suite
at a time. 0 failed suites.

| label | branch | code |
|---|---|---|
| v0.1-control | main @ 19c6d5d | v0.1 + latency metrics; same-day control |
| v0.2-direct | refactor/proto-direct | diem on `*diempb` directly, no wire.go (now main) |
| v0.2-interfaces | refactor/proto-interfaces | direct + getter-only interfaces |
| v0.2-views | refactor/proto-views | diem proto-free, zero-copy views in diemnet |
| v0.2-net | refactor/net-in-diem | direct + diemnet folded into diem |

Benchmarked at the pre-rebase commits; the later rebase onto main changed
no Go source.

Reproduce one label (from its worktree):
`HOSTS='pitter[1-10]' OUT=<main>/out/uis/<label> scripts/uis.sh {smoke,load,rate}`

## load: blocks/s per replica (p50 ms)

| batch × payload | v0.1-control | v0.2-direct | v0.2-interfaces | v0.2-views | v0.2-net |
|---|---|---|---|---|---|
| 1 × 128 | 104.8 (21.5) | 106.6 (21.4) | 104.4 (21.6) | 104.5 (21.5) | 104.7 (21.5) |
| 1 × 1024 | 103.2 (21.8) | 103.4 (21.8) | 102.8 (21.9) | 103.1 (21.9) | 104.4 (21.7) |
| 1 × 4096 | 99.8 (22.5) | 100.0 (22.5) | 99.8 (22.6) | 101.6 (22.5) | 101.1 (22.4) |
| 16 × 128 | 102.2 (22.1) | 101.9 (22.1) | 101.6 (22.2) | 106.3 (22.0) | 101.9 (22.1) |
| 16 × 1024 | 90.0 (25.4) | 88.0 (25.6) | 97.8 (23.8) | 87.9 (25.6) | 87.9 (25.6) |
| 16 × 4096 | 60.3 (38.3) | 57.8 (39.3) | 58.9 (39.0) | 57.8 (39.3) | 57.7 (39.3) |
| 256 × 128 | 68.4 (33.3) | 68.5 (33.3) | 68.4 (33.4) | 68.4 (33.3) | 68.4 (33.3) |
| 256 × 1024 | 24.4 (93.8) | 24.4 (93.6) | 24.3 (93.8) | 24.4 (93.7) | 25.4 (91.1) |
| 256 × 4096 | 7.6 (301.3) | 7.8 (296.0) | 7.6 (302.3) | 7.6 (300.8) | 7.7 (301.2) |

## rate (256 × 1 KiB): blocks/s per replica (p50 ms)

| rate/replica | v0.1-control | v0.2-direct | v0.2-interfaces | v0.2-views | v0.2-net |
|---|---|---|---|---|---|
| 500 | 83.1 (26.6) | 80.4 (27.3) | 80.5 (27.4) | 80.1 (27.5) | 82.7 (27.4) |
| 2000 | 25.8 (91.6) | 25.8 (90.4) | 24.8 (93.5) | 24.7 (93.6) | 24.7 (93.4) |
| 8000 | 24.5 (93.7) | 25.5 (93.1) | 24.5 (93.9) | 24.5 (93.8) | 24.6 (93.5) |
| unlimited | 24.3 (93.7) | 24.5 (93.5) | 24.7 (93.2) | 24.4 (93.9) | 24.4 (93.6) |

## knee (256 × 1 KiB, offered ≈ 4 × rate)

| rate/replica | offered | control kcmd/s | control p50/p99 ms | direct kcmd/s | direct p50/p99 ms |
|---|---|---|---|---|---|
| 750  | 3k | 2.75 | 29.2 / 44.4 | 2.76 | 32.3 / 46.4 |
| 1000 | 4k | 3.67 | 38.7 / 57.6 | 3.68 | 38.6 / 59.4 |
| 1250 | 5k | 4.61 | 49.3 / 75.9 | 4.64 | 47.3 / 79.1 |
| 1500 | 6k | 5.53 | 67.2 / 94.5 | 5.49 | 59.2 / 94.1 |
| 1750 | 7k | 6.18 | 91.1 / 98.1 | 6.10 | 92.8 / 99.7 |

Committed load tracks ~92 % of offered up to saturation at ≈ 6.2–6.5k cmd/s.
Latency rises steadily with load (blocks fill), with no flat region.

## Reading

No variant is distinguishable from the control: differences are within the
rep-to-rep and run-to-run spread (control itself moved up to ±3 % against
the v0.1 run two days earlier). The lone outlier, interfaces at 16 × 1024
(+9 %), is not repeated by any neighbouring configuration.

So the domain↔protobuf translation was never on the critical path. A round
still takes ≈ 10 ms at batch 1 against a 0.4 ms RTT; the cost is elsewhere
(see the v0.1 bottleneck probe). The choice between variants is therefore
one of code, not speed: direct is the smallest (−417 non-test lines).

## scale (main = direct, batch 64; previously blocked, now run with CGO_ENABLED=0)

| n | empty: blocks/s | empty: p50/p99 ms | 1 KiB: blocks/s | 1 KiB: kcmd/s | 1 KiB: p50/p99 ms |
|---|---|---|---|---|---|
| 4  | 107.8 | 21.5 / 23.6 | 58.5 | 3.74 | 39.6 / 43.8 |
| 7  | 76.0  | 29.6 / 33.4 | 46.3 | 2.96 | 50.5 / 56.5 |
| 10 | 57.6  | 38.5 / 44.0 | 34.5 | 2.21 | 67.3 / 72.3 |
| 13 | 42.5  | 51.9 / 56.6 | 27.8 | 1.78 | 83.3 / 90.5 |

Latency grows ≈ 2.5 ms per added replica even with empty blocks — a
per-message cost, not a per-byte one.
