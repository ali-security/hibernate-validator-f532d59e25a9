#!/bin/sh
# Travis archives job logs asynchronously; keep the job open until its public log
# already contains the test summary, so the log harvested right after the build is complete.
# Heartbeat on every poll (Travis kills jobs silent for 10 min); capped so a ~12 min job
# stays inside the harness's ~50 min Travis poll window. after_script cannot change the build result.
leg="${1:-build}"
url="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
waited=0
while [ "$waited" -lt 1200 ]; do
  if curl -fsSL "$url" 2>/dev/null | grep -q "SEAL TEST SUMMARY COMPLETE"; then
    echo "[$leg] log archive contains the test summary after ${waited}s"
    exit 0
  fi
  echo "[$leg] waiting for log archive... (${waited}s)"
  sleep 20
  waited=$((waited + 20))
done
echo "[$leg] gave up waiting for log archive after ${waited}s"
exit 0
