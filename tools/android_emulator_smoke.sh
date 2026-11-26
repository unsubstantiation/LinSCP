#!/usr/bin/env bash
set -euo pipefail
log=$(mktemp)
LSCP_TEST_PORT=0 python3 source/linux/tests/TestDavServer.py >"$log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -f "$log" "${app_root_file:-}"' EXIT
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
# Avoid an interactive Android 13+ notification permission prompt in the
# emulator smoke run; production installs still request it on the first queue.
adb shell pm grant "$application" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
adb shell am start -n "$application/.MainActivity"
for _ in $(seq 1 90); do
  pid=$(adb shell pidof "$application" | tr -d '\r' || true)
  if [[ -n "$pid" ]] && adb shell cat /proc/net/unix | grep -q "webview_devtools_remote_${pid}"; then break; fi
  sleep 1
done
if [[ -z "${pid:-}" ]]; then adb logcat -d -t 500; exit 1; fi
adb forward tcp:9222 "localabstract:webview_devtools_remote_${pid}"
app_root_file=$(mktemp)
if ! node tools/android_emulator_smoke.mjs "$port" "$application" "$app_root_file"; then
  adb logcat -d --pid="$pid" -t 200 || true
  exit 1
fi
# The smoke test proves the app reads and writes the storage it calls its own,
# but it can only see the path string the Rust side reported. Ask the device
# which directory actually belongs to the running package: the package list and
# the app sandbox come from the system package manager, not from anything this
# repository built. A build whose install directory did not carry the configured
# name - a stale `gen/android`, a debug `applicationIdSuffix`, a launcher of a
# different app - fails here instead of silently installing beside the real app.
if ! adb shell cmd package list packages --user 0 | tr -d '\r' \
    | sed -n 's/^package:\(.*\)$/\1/p' | grep -Fx "$application" >/dev/null; then
  echo "The installed app is not $application; the APK was built under another application ID" >&2
  adb shell cmd package list packages --user 0 | tr -d '\r' | grep -i linscp >&2 || true
  exit 1
fi
sandbox=$(adb shell run-as "$application" pwd | tr -d '\r')
if [[ "$sandbox" != "/data/user/0/$application" && "$sandbox" != "/data/data/$application" ]]; then
  echo "Unexpected sandbox for $application: '$sandbox'" >&2
  exit 1
fi
# Tauri resolves `app_data_dir()` to the activity's data directory - this
# sandbox, the folder named after the application ID - so everything the app
# wrote is here. The marker was written through the WebView above; if the path
# the app calls its own were some other package's directory, it would not be.
app_root=$(cat "$app_root_file")
if [[ "$app_root" != "$sandbox" ]]; then
  echo "The app reported its storage as '$app_root'; the device says $application's is '$sandbox'" >&2
  exit 1
fi
if ! adb shell run-as "$application" ls "$sandbox" | tr -d '\r' | grep -Fx "android-smoke-marker.txt" >/dev/null; then
  echo "$application did not write its storage to $sandbox" >&2
  adb shell run-as "$application" ls -la "$sandbox" >&2 || true
  exit 1
fi
# Inspect app-private bytes from the debug sandbox, without printing secrets.
key_file=$(mktemp)
sessions_file=$(mktemp)
trap 'kill "$server" 2>/dev/null || true; rm -f "$log" "${app_root_file:-}" "$key_file" "$sessions_file"' EXIT
adb exec-out run-as "$application" cat "$sandbox/config/sessions.key" > "$key_file"
adb exec-out run-as "$application" cat "$sandbox/config/sessions.ini" > "$sessions_file"
python3 - "$key_file" "$sessions_file" <<'PYCODE'
import pathlib, sys
key, sessions = (pathlib.Path(p).read_bytes() for p in sys.argv[1:])
assert key.startswith(b'LSCPKST1'), 'vault key was not Android Keystore wrapped'
assert sessions.startswith(b'LSCP-SESSION-VAULT-1$'), 'saved sites were not sealed'
for secret in (b'android-smoke-vault-site', b'testuser', b'testpass', b'127.0.0.1'):
    assert secret not in sessions, 'saved site metadata appeared in plaintext'
PYCODE
# Force-stop actually destroys the app process and its in-memory vault key.
restart_and_run() {
  local phase=$1
  adb shell am force-stop "$application"
  adb shell am start -n "$application/.MainActivity"
  for _ in $(seq 1 90); do
    pid=$(adb shell pidof "$application" | tr -d '\r' || true)
    if [[ -n "$pid" ]] && adb shell cat /proc/net/unix | grep -q "webview_devtools_remote_${pid}"; then break; fi
    sleep 1
  done
  if [[ -z "${pid:-}" ]]; then adb logcat -d -t 500; exit 1; fi
  adb forward tcp:9222 "localabstract:webview_devtools_remote_${pid}"
  if ! node tools/android_emulator_smoke.mjs "$port" "$application" "$app_root_file" "$phase"; then
    adb logcat -d --pid="$pid" -t 200 || true
    exit 1
  fi
}
restart_and_run reopen-vault

# Snapshot after reconnect, which may update the site's last-used metadata.
# The emulator is disposable; run-as is debug-only and does not expose a
# production UI or add a test hook to the application.
adb exec-out run-as "$application" cat "$sandbox/config/sessions.key" > "$key_file"
adb exec-out run-as "$application" cat "$sandbox/config/sessions.ini" > "$sessions_file"
tampered=$(mktemp)
observed=$(mktemp)
trap 'kill "$server" 2>/dev/null || true; rm -f "$log" "${app_root_file:-}" "$key_file" "$sessions_file" "$tampered" "$observed"' EXIT
for target in key sessions; do
  adb shell am force-stop "$application"
  if [[ "$target" == key ]]; then original=$key_file; dest=sessions.key; else original=$sessions_file; dest=sessions.ini; fi
  python3 - "$target" "$original" "$tampered" <<'PYCODE'
import pathlib, sys
target, src, dst = sys.argv[1:]
data = bytearray(pathlib.Path(src).read_bytes())
if target == 'key':
    assert data.startswith(b'LSCPKST1') and len(data) > 36
    data[-1] ^= 1  # corrupt the GCM authentication tag, not the format marker
else:
    marker = b'LSCP-SESSION-VAULT-1$'
    assert data.startswith(marker) and len(data) > len(marker) + 8
    i = len(marker) + 4
    data[i] = ord('A') if data[i] != ord('A') else ord('B')
pathlib.Path(dst).write_bytes(data)
PYCODE
  adb shell run-as "$application" sh -c "'cat > config/$dest'" < "$tampered"
  restart_and_run "tampered-$target"
  adb exec-out run-as "$application" cat "$sandbox/config/$dest" > "$observed"
  cmp "$tampered" "$observed" || { echo "Damaged $dest was modified after refusal" >&2; exit 1; }
  # The other member of the pair must also remain unchanged.
  if [[ "$target" == key ]]; then other=sessions.ini; other_original=$sessions_file; else other=sessions.key; other_original=$key_file; fi
  adb exec-out run-as "$application" cat "$sandbox/config/$other" > "$observed"
  cmp "$other_original" "$observed" || { echo "Unmodified $other changed after refusal" >&2; exit 1; }
  adb shell am force-stop "$application"
  adb shell run-as "$application" sh -c "'cat > config/$dest'" < "$original"
done
# A clean restart must still recover and use the saved credential after restore.
restart_and_run reopen-vault
echo "Installed application ID and its install directory verified: $application ($sandbox)"
