#!/usr/bin/env bash
# Builds, runs the unprivileged test suite, then runs the root experiments and
# saves every transcript under results/.
#
# The split matters. ctest needs no privilege and must be green before any
# experiment is believed: if the reassembly or the option encoder is wrong, the
# experiments still produce a confident-looking table, just a wrong one.

set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=${BUILD:-build}
RESULTS=results

echo "=== configure + build ==="
# Build as the invoking user, not as root. Building under sudo leaves build/
# owned by root, and then every later unprivileged `cmake --build` fails with
# "Permission denied" on a temp file -- which looks like a broken repo rather
# than a permissions footgun the run script created.
if [ -n "${SUDO_USER:-}" ]; then
  AS_USER=(sudo -u "$SUDO_USER")
else
  AS_USER=()
fi
"${AS_USER[@]}" cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
"${AS_USER[@]}" cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu)"

echo
echo "=== unit tests (no root) ==="
# Also as the invoking user: these need no privilege, and running them as root
# would not prove that they pass for someone who just cloned the repo.
( cd "$BUILD" && "${AS_USER[@]}" ctest --output-on-failure )

if [ "$(id -u)" -ne 0 ]; then
  echo
  echo "Unit tests passed. The experiments create a utun interface, which needs root:"
  echo "    sudo ./scripts/run_all.sh"
  exit 0
fi

EXPERIMENTS=(baseline hol dupack rto challenge_ack)

# Snapshot the knobs the experiments are allowed to write, so the restore can be
# verified at the end instead of printed for a human to eyeball.
GUARDED=(net.inet.tcp.rexmt_thresh net.inet.tcp.challengeack_limit)
declare -a BEFORE=()
for k in "${GUARDED[@]}"; do BEFORE+=("$(sysctl -n "$k")"); done

# Delete last run's transcripts before writing this run's metadata. Otherwise a
# run that dies half way leaves fresh metadata sitting next to stale tables from
# a previous run, and the two are indistinguishable afterwards -- which is worse
# than having no transcript at all, because the file looks current.
mkdir -p "$RESULTS"
for e in "${EXPERIMENTS[@]}"; do rm -f "$RESULTS/exp_$e.txt"; done
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$RESULTS" 2>/dev/null || true

# The kernel tag and the knob values belong with the numbers; the same binary
# on a different build of XNU, or after someone has touched rtt_min, produces a
# different table and nothing else in the file would say so.
{
  echo "# run at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# uname -v: $(uname -v)"
  echo "# hw: $(sysctl -n hw.model), $(sysctl -n hw.ncpu) cpus"
} > "$RESULTS/run-metadata.txt"

# A failing experiment must not abort the others: they are independent, and
# losing four tables to one transient utun failure is a bad trade. Exit codes
# are collected and reported at the end so a partial run cannot pass for a
# complete one.
FAILED=()
for e in "${EXPERIMENTS[@]}"; do
  echo
  echo "=== exp_$e ==="
  # tee, not redirect: a 30-second experiment with no output looks hung.
  # `set -o pipefail` would otherwise make tee's success mask the binary's
  # failure, so the status comes from PIPESTATUS.
  set +e
  "./$BUILD/exp_$e" "$@" 2>&1 | tee "$RESULTS/exp_$e.txt"
  rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "exp_$e exited $rc" | tee -a "$RESULTS/exp_$e.txt"
    FAILED+=("exp_$e($rc)")
  fi
done

echo
echo "Transcripts in $RESULTS/."

# Verify, do not merely display. The experiments write live kernel knobs, and a
# guard that failed to restore leaves the machine detuned for everything that
# runs afterwards -- including the next run of this script, which would then
# measure a different stack and say nothing about it.
drift=0
for i in "${!GUARDED[@]}"; do
  now=$(sysctl -n "${GUARDED[$i]}")
  if [ "$now" != "${BEFORE[$i]}" ]; then
    echo "FAIL: ${GUARDED[$i]} was ${BEFORE[$i]} before the run and is $now now."
    echo "      Restore it with: sudo sysctl -w ${GUARDED[$i]}=${BEFORE[$i]}"
    drift=1
  fi
done
if [ "$drift" -eq 0 ]; then
  echo "sysctls verified back at their pre-run values."
fi

# Report before exiting, and report both problems if both happened. Written as
# plain ifs on purpose: `[ cond ] && echo ...` here would take its non-zero
# status from the test under `set -e` and kill the script before the message.
status=0
if [ ${#FAILED[@]} -ne 0 ]; then
  echo "INCOMPLETE RUN -- these did not finish: ${FAILED[*]}"
  status=1
fi
if [ "$drift" -ne 0 ]; then
  status=1
fi
exit "$status"
