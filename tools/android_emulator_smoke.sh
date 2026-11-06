#!/usr/bin/env bash
set -euo pipefail
log=$(mktemp)
LSCP_TEST_PORT=0 python3 source/linux/tests/TestDavServer.py >"$log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -f "$log"' EXIT
for _ in $(seq 1 60); do
  grep -q '^READY ' "$log" && break
  kill -0 "$server" || { cat "$log"; exit 1; }
  sleep 1
done
port=$(sed -n 's/^READY //p' "$log" | head -n 1)
test -n "$port"
# The package is the one the configuration names, read rather than repeated:
# a rename that reaches only some of these places would leave the harness
# driving an app that is not installed.
application=$(python3 tools/android_application_id.py)
adb reverse "tcp:$port" "tcp:$port"
adb install -r android-artifacts/linscp-android-debug.apk
adb shell am start -n "$application/.MainActivity"
for _ in $(seq 1 90); do
  pid=$(adb shell pidof "$application" | tr -d '\r' || true)
  if [[ -n "$pid" ]] && adb shell cat /proc/net/unix | grep -q "webview_devtools_remote_${pid}"; then break; fi
  sleep 1
done
if [[ -z "${pid:-}" ]]; then adb logcat -d -t 500; exit 1; fi
adb forward tcp:9222 "localabstract:webview_devtools_remote_${pid}"
if ! node tools/android_emulator_smoke.mjs "$port" "$application"; then
  adb logcat -d --pid="$pid" -t 200 || true
  exit 1
fi
