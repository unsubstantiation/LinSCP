#!/usr/bin/env bash
# Drive a granted Android folder on a real device and prove the SAF bridge
# behaves the way the in-memory mock says it does.
#
# The emulator smoke (tools/android_emulator_smoke.sh) proves the app reaches
# its own private storage through Rust. It cannot say anything about a granted
# folder, because a Storage Access Framework tree is granted by a system picker
# that no harness can click. This script starts from a tree that is *already*
# granted, which makes the provider real and the evidence reproducible: the
# same device and permission produce the same result on every run.
#
# WHAT THIS NEEDS
#   adb on PATH, one device or emulator attached, and the app installed with a
#   granted folder. Grant one by hand first:
#
#   1. Give the folder something the provider will serve. On a device with a
#      shared-storage provider, dropping files in /sdcard/Documents works:
#         adb shell mkdir -p /sdcard/Documents/linscp-saf
#         adb push some-file.txt /sdcard/Documents/linscp-saf/
#   2. Launch the app, open the local-root switcher, pick "Add folder" and
#      choose that folder in the system picker. tapPersistableUriPermission is
#      called by the shell, so the grant survives restarts.
#   3. Run this script. It reads the granted tree back from the shell rather
#      than being told one, so a stale or misspelt URI cannot pass.
#
# The suite is read-only with respect to your data: everything it creates lives
# under one folder it names itself and deletes afterwards, and it asserts on
# document names that carry a run id, so a folder that already holds files is
# not disturbed.
#
# Exit status is the harness's own. A missing grant is a skip, not a failure:
# it says so and exits 0, because "nobody granted a folder" is a fact about the
# device, not a defect in the build.
set -euo pipefail

application=$(python3 tools/android_application_id.py)

if ! command -v adb >/dev/null 2>&1; then
  echo "adb is not on PATH; install platform-tools and attach a device" >&2
  exit 2
fi

if ! adb get-state 2>/dev/null | grep -qx device; then
  echo "No device in 'device' state (adb gets one when it is unlocked and trusted)" >&2
  adb devices >&2 || true
  exit 2
fi

# The APK has to be the one this checkout builds. Without this, a suite run
# against a stale install proves something about some other commit.
if ! adb shell pm list packages --user 0 2>/dev/null | tr -d '\r' \
    | sed -n 's/^package://p' | grep -Fx "$application" >/dev/null; then
  echo "The app is not installed on this device: $application" >&2
  echo "Install it first (see tools/android_emulator_smoke.sh for the debug APK path)." >&2
  exit 1
fi

# A running app is required: the DevTools endpoint belongs to the WebView, and
# the SAF bridge belongs to the activity that owns it.
pid=$(adb shell pidof "$application" 2>/dev/null | tr -d '\r' || true)
if [[ -z "$pid" ]]; then
  echo "Starting $application"
  adb shell am start -n "$application/.MainActivity" >/dev/null
  for _ in $(seq 1 90); do
    pid=$(adb shell pidof "$application" 2>/dev/null | tr -d '\r' || true)
    [[ -n "$pid" ]] && break
    sleep 1
  done
fi
if [[ -z "$pid" ]]; then
  echo "The app did not start" >&2
  adb logcat -d -t 200 >&2 || true
  exit 1
fi

# Wait for the WebView's DevTools socket, which exists only once the page has
# begun loading.
for _ in $(seq 1 90); do
  if adb shell cat /proc/net/unix 2>/dev/null | grep -q "webview_devtools_remote_${pid}"; then
    break
  fi
  sleep 1
done
if ! adb shell cat /proc/net/unix 2>/dev/null | grep -q "webview_devtools_remote_${pid}"; then
  echo "The WebView never exposed a DevTools socket" >&2
  adb logcat -d --pid="$pid" -t 200 >&2 || true
  exit 1
fi

adb forward tcp:9222 "localabstract:webview_devtools_remote_${pid}" >/dev/null
trap 'adb forward --remove tcp:9222 >/dev/null 2>&1 || true' EXIT

exec node tools/android_saf_smoke.mjs "$application"
