#!/usr/bin/env bash
set -euo pipefail
log=$(mktemp)
sftp_log=$(mktemp)
sftp_root=$(mktemp -d)
ftp_root=$(mktemp -d)
ftp_log=$(mktemp)
ftps_log=$(mktemp)
LSCP_TEST_ROOT="$ftp_root" LSCP_TEST_FTP_PASSIVE_START=49000 /usr/bin/python3 source/linux/tests/TestFtpServer.py >"$ftp_log" 2>&1 &
ftp_server=$!
LSCP_TEST_ROOT="$ftp_root" LSCP_TEST_FTP_TLS=1 LSCP_TEST_FTP_PASSIVE_START=49016 /usr/bin/python3 source/linux/tests/TestFtpServer.py >"$ftps_log" 2>&1 &
ftps_server=$!
LSCP_TEST_ROOT="$sftp_root" LSCP_TEST_PORT=0 /usr/bin/python3 source/linux/tests/TestSftpServer.py >"$sftp_log" 2>&1 &
sftp_server=$!
LSCP_TEST_PORT=0 python3 source/linux/tests/TestDavServer.py >"$log" 2>&1 &
server=$!
trap 'kill "$server" "$sftp_server" "$ftp_server" "$ftps_server" 2>/dev/null || true; rm -f "$log" "$sftp_log" "$ftp_log" "$ftps_log"; rm -rf "$sftp_root" "$ftp_root"' EXIT
for _ in $(seq 1 60); do
  grep -q '^READY ' "$log" && break
  kill -0 "$server" || { cat "$log"; exit 1; }
  sleep 1
done
port=$(sed -n 's/^READY //p' "$log" | head -n 1)
test -n "$port"
for _ in $(seq 1 60); do
  grep -q '^READY ' "$sftp_log" && break
  kill -0 "$sftp_server" || { cat "$sftp_log"; exit 1; }
  sleep 1
done
sftp_port=$(sed -n 's/^READY //p' "$sftp_log" | head -n 1)
test -n "$sftp_port"
for _ in $(seq 1 60); do
  if grep -q '^READY ' "$ftp_log" && grep -q '^READY ' "$ftps_log"; then break; fi
  kill -0 "$ftp_server" "$ftps_server" || { cat "$ftp_log" "$ftps_log"; exit 1; }
  sleep 1
done
ftp_port=$(sed -n 's/^READY //p' "$ftp_log" | head -n 1)
ftps_port=$(sed -n 's/^READY //p' "$ftps_log" | head -n 1)
test -n "$ftp_port" && test -n "$ftps_port"
adb reverse "tcp:$ftp_port" "tcp:$ftp_port"
adb reverse "tcp:$ftps_port" "tcp:$ftps_port"
for passive in $(seq 49000 49031); do adb reverse "tcp:$passive" "tcp:$passive"; done
adb reverse "tcp:$sftp_port" "tcp:$sftp_port"
adb reverse "tcp:$port" "tcp:$port"
adb install -r android-artifacts/linscp-android-debug.apk
adb shell run-as io.linscp.commander sh -c 'mkdir -p files && cat > files/test-ca.pem' < source/linux/tests/fixtures/s3-server-cert.pem
adb shell am start -n io.linscp.commander/.MainActivity
for _ in $(seq 1 90); do
  pid=$(adb shell pidof io.linscp.commander | tr -d '\r' || true)
  if [[ -n "$pid" ]] && adb shell cat /proc/net/unix | grep -q "webview_devtools_remote_${pid}"; then break; fi
  sleep 1
done
if [[ -z "${pid:-}" ]]; then adb logcat -d -t 500; exit 1; fi
adb forward tcp:9222 "localabstract:webview_devtools_remote_${pid}"
if ! node tools/android_emulator_smoke.mjs "$port" "$sftp_port" "$ftp_port" "$ftps_port"; then
  adb logcat -d --pid="$pid" -t 200 || true
  exit 1
fi
