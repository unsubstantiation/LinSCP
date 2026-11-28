#!/usr/bin/env bash
# Disposable loopback-only MIT KDC + OpenSSH. Intended for an isolated CI VM.
set -euo pipefail
root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/linscp-krb.XXXXXX")"
chmod 755 "$root"
cleanup() {
  if [[ -s "$root/sshd.pid" ]]; then sudo kill "$(cat "$root/sshd.pid")" 2>/dev/null || true; fi
  if [[ -n "${sshd_pid:-}" ]]; then sudo kill "$sshd_pid" 2>/dev/null || true; fi
  if [[ -n "${kdc_pid:-}" ]]; then kill "$kdc_pid" 2>/dev/null || true; fi
  if [[ "${user_created:-0}" == 1 ]]; then sudo userdel "$fixture_user" 2>/dev/null || true; fi
  rm -rf "$root"
}
trap cleanup EXIT
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
kdcport=$(port)
sshport=$(port)
realm=LINSCP.TEST
# A disposable unlocked account is needed because GitHub's runner account is
# locked. sshd below disables password and public-key authentication.
fixture_user="lscpkrb${RANDOM}"
sudo useradd -M -d /tmp -s /bin/sh -p "$(openssl passwd -6 'unused-fixture-password')" "$fixture_user"
user_created=1
export KRB5_CONFIG="$root/krb5.conf" KRB5_KDC_PROFILE="$root/kdc.conf"
cat > "$KRB5_CONFIG" <<CONF
[libdefaults]
 default_realm = $realm
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_canonicalize_hostname = false
 rdns = false
 forwardable = true
[realms]
 $realm = {
  kdc = 127.0.0.1:$kdcport
 }
[domain_realm]
 linscp-fixture.invalid = $realm
CONF
cat > "$KRB5_KDC_PROFILE" <<CONF
[kdcdefaults]
 kdc_ports = $kdcport
 kdc_tcp_ports = $kdcport
[realms]
 $realm = {
  database_name = $root/principal
  key_stash_file = $root/stash
  acl_file = $root/acl
  max_life = 10h
  max_renewable_life = 7d
 }
CONF
kdb5_util create -s -P fixture-master -r "$realm"
kadmin.local -r "$realm" -q "addprinc -randkey host/linscp-fixture.invalid@$realm"
kadmin.local -r "$realm" -q "ktadd -k $root/host.keytab host/linscp-fixture.invalid@$realm"
kadmin.local -r "$realm" -q "addprinc -randkey $fixture_user@$realm"
kadmin.local -r "$realm" -q "ktadd -k $root/user.keytab $fixture_user@$realm"
krb5kdc -n -r "$realm" >"$root/kdc.log" 2>&1 & kdc_pid=$!
export KRB5CCNAME="FILE:$root/client.ccache"
ready=0
for _ in {1..30}; do
  if kinit -f -k -t "$root/user.keytab" "$fixture_user@$realm" 2>/dev/null; then ready=1; break; fi
  sleep .1
done
if [[ "$ready" != 1 ]]; then cat "$root/kdc.log"; echo 'KDC failed to issue credentials' >&2; exit 1; fi
ssh-keygen -q -t ed25519 -N '' -f "$root/ssh_host_key"
cat > "$root/sshd_config" <<CONF
ListenAddress 127.0.0.1
Port $sshport
HostKey $root/ssh_host_key
PidFile $root/sshd.pid
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIStrictAcceptorCheck no
AllowUsers $fixture_user
Subsystem sftp internal-sftp
LogLevel DEBUG3
CONF
sudo mkdir -p /run/sshd
sudo env KRB5_CONFIG="$KRB5_CONFIG" KRB5_KTNAME="FILE:$root/host.keytab" /usr/sbin/sshd -D -e -f "$root/sshd_config" >"$root/sshd.log" 2>&1 & sshd_pid=$!
export LINSCP_KRB_PORT="$sshport" LINSCP_KRB_USER="$fixture_user" LINSCP_KRB_CACHE="$KRB5CCNAME"
export LINSCP_KRB_HOSTKEY="$(ssh-keygen -lf "$root/ssh_host_key.pub" | awk '{print $2}')"
# A single readiness check retries the TCP connection; failure is a test failure.
python3 - "$sshport" <<'PY'
import socket, sys, time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=.2): break
    except OSError: time.sleep(.1)
else: raise SystemExit('sshd fixture did not start')
PY
if ! cargo test -q -p linscp-engine --test live_kerberos -- --ignored --nocapture >"$root/test.log" 2>&1; then
  echo '--- test log ---'; tail -80 "$root/test.log"
  echo '--- sshd log ---'; tail -100 "$root/sshd.log"
  echo '--- KDC log ---'; tail -40 "$root/kdc.log"
  exit 1
fi
cat "$root/test.log"
