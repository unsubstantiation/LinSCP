#!/usr/bin/env python3
"""Check the idle Linux GUI exposes only its authenticated activation socket.

This is a smoke check, not an IPC isolation or same-user security proof. Run it
against a disposable GUI process with its own configuration directory.
"""
import argparse
import os
from pathlib import Path
import socket
import stat


def listening_tcp_sockets(pid):
    """Return (address, port, inode) for TCP listeners owned by this process."""
    proc = Path('/proc') / str(pid)
    inodes = set()
    for fd in (proc / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:  # The process may close unrelated fds concurrently.
            continue
        if target.startswith('socket:[') and target.endswith(']'):
            inodes.add(target[8:-1])
    listeners = set()
    for filename, family in [('tcp', socket.AF_INET), ('tcp6', socket.AF_INET6)]:
        table = proc / 'net' / filename
        if not table.exists():
            continue
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] != '0A' or fields[9] not in inodes:
                continue
            addr_hex, port_hex = fields[1].split(':')
            raw = bytes.fromhex(addr_hex)
            # Linux /proc writes each address as little-endian 32-bit words.
            raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            listeners.add((socket.inet_ntop(family, raw), int(port_hex, 16), fields[9]))
    return listeners


def assert_no_reply(port, request):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        try:
            response = connection.recv(1024)
        except ConnectionResetError:
            response = b''
        if response:
            raise AssertionError('unexpected response to unauthenticated request')


def check(pid, config_dir):
    endpoint = Path(config_dir) / '.instance-ipc'
    mode = stat.S_IMODE(endpoint.stat().st_mode)
    if mode & 0o077:
        raise AssertionError(f'activation record has non-private permissions: {mode:o}')
    address, token = endpoint.read_text().split()
    if not address.startswith('127.0.0.1:') or len(token) != 64:
        raise AssertionError('unexpected activation record')
    port = int(address.rsplit(':', 1)[1])
    listeners = listening_tcp_sockets(pid)
    if len(listeners) != 1 or {(ip, number) for ip, number, _ in listeners} != {('127.0.0.1', port)}:
        raise AssertionError(f'unexpected GUI TCP listeners: {listeners}')
    assert_no_reply(port, b'GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n')
    wrong_token = ('1' if token[0] == '0' else '0') + token[1:]
    assert_no_reply(port, b'ACTIVATE ' + wrong_token.encode('ascii') + b'\n')
    print('GUI has only the private loopback activation listener; unauthenticated HTTP and activation were refused')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('config_dir')
    args = parser.parse_args()
    check(args.pid, args.config_dir)


if __name__ == '__main__':
    main()
