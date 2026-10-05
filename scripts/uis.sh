#!/usr/bin/env bash
# uis.sh — run DiemBFT on the UiS VMs (pitter1-15) through Gorums' benchkit
# sweep, one replica per VM. sweep hands each node -self/-remotes; with no
# -keys the replicas derive the same seeded key set, so nothing but the binary
# is shipped.
#
# Usage: scripts/uis.sh <command>
#   ssh-config  print the ~/.ssh/config block sweep needs (needs UIS_USER)
#   check       sweep's own diagnostics: ssh, jump host, clocks, ports
#   smoke       n=4, 10s — does it commit at all
#   scale       n=4,7,10,13 x payload 0/1024, batch 64
#   load        n=4, payload 128/1024/4096 x batch 1/16/256
#   rate        n=4, 1 KiB commands, batch 256, at 500/2000/8000/unthrottled per second
#               scale, load and rate run 20s per point, 3 repetitions
#   long        n=4 for 10 minutes, detached on a driver VM
#   collect     fetch the results of the last detached run
#   plot DIR    render the report for one collected run directory under $OUT
#   all         check, smoke, scale, load and rate, back to back
#
# Environment:
#   HOSTS    sweep host pattern (default 'pitter[1-15]'); scale needs 14 and long 5,
#            because their driver sits out of the pool
#   GORUMS   Gorums checkout holding benchkit (default ~/sync/skole/26H/DAT620/gorums)
#   OUT      where results land (default <repo>/out/uis)
#   UIS_USER your UiS username, for ssh-config only
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
gorums=${GORUMS:-$HOME/sync/skole/26H/DAT620/gorums}
hosts=${HOSTS:-pitter[1-15]}
out=${OUT:-$repo/out/uis}
bin=$repo/bin/diem-linux-amd64
sweepbin=$repo/bin/sweep

# sweep is built with the command behind Gorums' "make sweep", minus that
# target's protobuf regeneration, which needs protoc.
build() {
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -C "$repo" -o "$bin" ./cmd/diem
    go build -C "$gorums/benchkit/cmd/sweep" -o "$sweepbin" .
}

# sweep refuses to run outside the benchkit module root.
sweep() {
    (cd "$gorums/benchkit" && "$sweepbin" "$@")
}

run() {
    local label=$1
    shift
    sweep -hosts "$hosts" -binary "$bin" -benchmarks diem -outdir "$out" -sweep "$label" "$@"
}

# -workers is diem's batch: commands per proposal. Payload 0 proposes empty
# blocks, so batch only matters with a payload.
scale() { run scale -driver first -n 4,7,10,13 -payload 0,1024 -workers 64 -reps 3 -duration 20s; }
load() { run load -n 4 -payload 128,1024,4096 -workers 1,16,256 -reps 3 -duration 20s; }
rate() { run rate -n 4 -payload 1024 -workers 256 -rate 500,2000,8000,0 -reps 3 -duration 20s; }

case ${1:-} in
ssh-config)
    : "${UIS_USER:?set UIS_USER to your UiS username}"
    cat <<EOF
Host uis
  HostName ssh4.ux.uis.no
  User $UIS_USER

Host pitter*
  User $UIS_USER
  ProxyJump uis
EOF
    ;;
check) build && sweep -hosts "$hosts" -check ;;
smoke) build && run smoke -n 4 -duration 10s ;;
scale) build && scale ;;
load) build && load ;;
rate) build && rate ;;
long) build && run long -n 4 -duration 10m -driver first -detach ;;
collect) build && sweep -outdir "$out" -collect ;;
plot) build && sweep -plot "${2:?pass a run directory under $out}" ;;
all)
    build
    sweep -hosts "$hosts" -check
    run smoke -n 4 -duration 10s
    scale
    load
    rate
    ls "$out"
    ;;
*)
    sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 2
    ;;
esac
