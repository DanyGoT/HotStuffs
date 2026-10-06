#!/usr/bin/env python3
"""Summarize benchkit sweep results: one row per configuration, reps pooled.

Usage: scripts/summarize.py SUITE_DIR [SUITE_DIR ...]

blocks/s is per replica (the mean of each node's throughput); kcmd/s comes
from the replicas' "committed N (M commands)" log lines; latency percentiles
pool every proposer-measured sample of every rep.
"""
import glob
import json
import os
import re
import statistics
import sys
from collections import defaultdict

RUN = re.compile(r"_N(\d+)_W(\d+)_P(\d+)(?:_R(\d+))?_S\w+_r(\d+)_")
COMMANDS = re.compile(r"committed \d+ \((\d+) commands\)")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))] if xs else float("nan")


def summarize(suite):
    rows = defaultdict(lambda: {"tput": [], "lat": [], "cmds": defaultdict(list)})
    durations = {}
    for path in glob.glob(os.path.join(suite, "*_9000.json")):
        m = RUN.search(os.path.basename(path))
        if not m:
            continue
        n, w, p, r, rep = m.groups()
        key = (int(n), int(w), int(p), int(r or 0))
        res = json.load(open(path))["results"][0]
        rows[key]["tput"].append(res["throughput"])
        # The first sample of a run includes connection setup.
        rows[key]["lat"].extend(int(x) / 1e6 for x in res.get("latencies", [])[1:])
        durations[key] = int(res["config"]["duration"]) / 1e9
    for log in glob.glob(os.path.join(suite, "logs", "*.log")):
        m = re.search(r"_N(\d+)_W(\d+)_P(\d+)(?:_R(\d+))?_S\w+_r(\d+)\.log$", log)
        if not m:
            continue
        n, w, p, r, rep = m.groups()
        key = (int(n), int(w), int(p), int(r or 0))
        for c in COMMANDS.findall(open(log).read()):
            rows[key]["cmds"][rep].append(int(c))
    print(f"\n{suite}\n")
    print("| n | batch | payload | rate | blocks/s | kcmd/s | p50 ms | p99 ms |")
    print("|---|---|---|---|---|---|---|---|")
    for key in sorted(rows):
        v = rows[key]
        per_rep = [statistics.mean(c) for c in v["cmds"].values()]
        kcmd = statistics.mean(per_rep) / durations[key] / 1e3 if per_rep else float("nan")
        n, w, p, r = key
        print(f"| {n} | {w} | {p} | {r or '-'} | {statistics.mean(v['tput']):.1f} | "
              f"{kcmd:.2f} | {pct(v['lat'], 50):.1f} | {pct(v['lat'], 99):.1f} |")


for d in sys.argv[1:]:
    summarize(d)
