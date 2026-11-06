#!/usr/bin/env bash
# Prove the signed release APK runs on a device.
#
# The WebView smoke test drives the page through its DevTools endpoint, which
# only a debuggable build has (prepare_android_project.py enables it under
# BuildConfig.DEBUG), so the artifact that actually ships cannot be driven that
# way. What a device can still answer is whether the release build installs,
# starts, keeps running as a non-debuggable package of the configured
# application ID, and stays free of the fatal exceptions a minified build
# introduces at startup.
set -euo pipefail
application=$(python3 tools/android_application_id.py)
apk=android-artifacts/linscp-android-release.apk
if [[ ! -f "$apk" ]]; then
  echo "Missing $apk; run tools/verify_android_apk.py --build-type release first" >&2
  exit 1
fi
# Android refuses to replace an install whose signing key changed, and the debug
# APK the smoke test used is signed with the development key.
adb uninstall "$application" >/dev/null 2>&1 || true
adb install "$apk"
adb logcat -c || true
adb shell am start -n "$application/.MainActivity"
pid=
for _ in $(seq 1 90); do
  pid=$(adb shell pidof "$application" | tr -d '\r' || true)
  [[ -n "$pid" ]] && break
  sleep 1
done
if [[ -z "$pid" ]]; then
  adb logcat -d -t 500 || true
  echo "$application did not start" >&2
  exit 1
fi
# A minified release build that dies on its first frame is exactly the failure
# the debug build cannot show, so give it time to fail before believing it.
sleep 10
if ! adb shell pidof "$application" | tr -d '\r' | grep -Fx "$pid" >/dev/null; then
  adb logcat -d --pid="$pid" -t 500 || true
  echo "$application stopped running after starting; the release build is not usable" >&2
  exit 1
fi
if adb logcat -d --pid="$pid" -t 500 | grep -q 'FATAL EXCEPTION'; then
  adb logcat -d --pid="$pid" -t 500 || true
  echo "$application raised a fatal exception while starting" >&2
  exit 1
fi
# The package, its install directory and its flags come from the system package
# manager, not from this repository's configuration, so none of the three can
# agree with a build that shipped something else.
if ! adb shell cmd package list packages --user 0 | tr -d '\r' \
    | sed -n 's/^package:\(.*\)$/\1/p' | grep -Fx "$application" >/dev/null; then
  echo "The installed package is not $application" >&2
  adb shell cmd package list packages --user 0 | tr -d '\r' | grep -i linscp >&2 || true
  exit 1
fi
data_dir=$(adb shell dumpsys package "$application" | tr -d '\r' \
  | sed -n 's/^ *dataDir=\(.*\)$/\1/p' | head -n 1)
if [[ "$data_dir" != "/data/user/0/$application" && "$data_dir" != "/data/data/$application" ]]; then
  echo "Unexpected data directory for $application: '$data_dir'" >&2
  exit 1
fi
# `run-as` is the device's own answer to "is this package debuggable?".
if adb shell run-as "$application" pwd >/dev/null 2>&1; then
  echo "$application is debuggable; a signed release build must not be" >&2
  exit 1
fi
echo "Signed release APK installs and runs as $application ($data_dir), not debuggable"
