#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
import sys
from itertools import product
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

CORE_LEN = 40
CHUNK_LEN = 5

OP_END = 0x00
OP_XORC = 0x11
OP_ADDC = 0x12
OP_ROL = 0x13
OP_ROR = 0x14
OP_SWAP = 0x15
OP_XORXY = 0x16
OP_ADDXY = 0x17
OP_SUBXY = 0x18
OP_MULADD = 0x19
OP_TRIAD = 0x1A

U32 = 0xFFFFFFFF


class PE:
    def __init__(self, raw: bytes):
        self.raw = raw
        if raw[:2] != b"MZ":
            raise ValueError("not an MZ/PE file")
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")

        coff = e_lfanew + 4
        self.num_sections = struct.unpack_from("<H", raw, coff + 2)[0]
        opt_size = struct.unpack_from("<H", raw, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", raw, opt)[0]
        if magic != 0x20B:
            raise ValueError("expected PE32+ x64 binary")
        self.image_base = struct.unpack_from("<Q", raw, opt + 24)[0]

        sec_off = opt + opt_size
        self.sections: Dict[str, Tuple[int, int, int, int]] = {}
        for i in range(self.num_sections):
            off = sec_off + i * 40
            name = raw[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, off + 8)
            self.sections[name] = (virtual_address, virtual_size, raw_ptr, raw_size)

    def section(self, name: str) -> bytes:
        if name not in self.sections:
            raise ValueError(f"missing section {name}")
        _, virtual_size, raw_ptr, raw_size = self.sections[name]
        return self.raw[raw_ptr:raw_ptr + min(virtual_size, raw_size)]

    def va_to_file_offset(self, va: int) -> int:
        rva = va - self.image_base
        for _, (sva, vsz, ptr, rsz) in self.sections.items():
            size = max(vsz, rsz)
            if sva <= rva < sva + size:
                return ptr + (rva - sva)
        raise ValueError(f"VA outside mapped sections: 0x{va:x}")

    def va_to_section_relative(self, va: int, section_name: str) -> int:
        file_off = self.va_to_file_offset(va)
        _, _, raw_ptr, _ = self.sections[section_name]
        return file_off - raw_ptr


def rol8(x: int, s: int) -> int:
    s &= 7
    x &= 0xFF
    return ((x << s) | (x >> (8 - s))) & 0xFF if s else x


def ror8(x: int, s: int) -> int:
    s &= 7
    x &= 0xFF
    return ((x >> s) | (x << (8 - s))) & 0xFF if s else x


def rotl32(x: int, s: int) -> int:
    s &= 31
    x &= U32
    return ((x << s) | (x >> (32 - s))) & U32 if s else x


def u32s(buf: bytes) -> List[int]:
    if len(buf) % 4:
        raise ValueError("u32 array length must be divisible by four")
    return list(struct.unpack("<" + "I" * (len(buf) // 4), buf))


def parse_vm(program: bytes) -> List[Tuple[int, ...]]:
    pc = 0
    out: List[Tuple[int, ...]] = []
    while pc < len(program):
        op = program[pc]
        pc += 1
        if op == OP_END:
            out.append((op,))
            return out
        if op in (OP_XORC, OP_ADDC, OP_ROL, OP_ROR, OP_SWAP, OP_XORXY, OP_ADDXY, OP_SUBXY):
            if pc + 1 >= len(program):
                raise ValueError("truncated VM instruction")
            a, b = program[pc], program[pc + 1]
            pc += 2
            if a >= CORE_LEN:
                raise ValueError("VM byte index outside core")
            if op in (OP_SWAP, OP_XORXY, OP_ADDXY, OP_SUBXY) and b >= CORE_LEN:
                raise ValueError("VM byte index outside core")
            out.append((op, a, b))
            continue
        if op in (OP_MULADD, OP_TRIAD):
            if pc + 2 >= len(program):
                raise ValueError("truncated VM instruction")
            a, b, c = program[pc], program[pc + 1], program[pc + 2]
            pc += 3
            if a >= CORE_LEN:
                raise ValueError("VM byte index outside core")
            if op == OP_TRIAD and (b >= CORE_LEN or c >= CORE_LEN):
                raise ValueError("VM byte index outside core")
            out.append((op, a, b, c))
            continue
        raise ValueError(f"unknown VM opcode 0x{op:02x} at pc={pc - 1}")
    raise ValueError("VM program did not end with OP_END")


def decode_stage(enc: bytes, key: bytes, stage_id: int, mix_mult: int) -> bytes:
    dec = bytearray()
    for i, x in enumerate(enc):
        x = ror8(x, ((i + stage_id) % 7) + 1)
        x ^= key[(i * 3 + stage_id) % len(key)]
        x ^= (0x41 + i * mix_mult + stage_id * 17) & 0xFF
        dec.append(x)
    parse_vm(bytes(dec))
    return bytes(dec)


def run_vm(program: bytes, buf: bytearray) -> None:
    for ins in parse_vm(program):
        op = ins[0]
        if op == OP_END:
            return
        if op == OP_XORC:
            _, a, b = ins
            buf[a] ^= b
        elif op == OP_ADDC:
            _, a, b = ins
            buf[a] = (buf[a] + b) & 0xFF
        elif op == OP_ROL:
            _, a, b = ins
            buf[a] = rol8(buf[a], b)
        elif op == OP_ROR:
            _, a, b = ins
            buf[a] = ror8(buf[a], b)
        elif op == OP_SWAP:
            _, a, b = ins
            buf[a], buf[b] = buf[b], buf[a]
        elif op == OP_XORXY:
            _, a, b = ins
            buf[a] ^= buf[b]
        elif op == OP_ADDXY:
            _, a, b = ins
            buf[a] = (buf[a] + buf[b]) & 0xFF
        elif op == OP_SUBXY:
            _, a, b = ins
            buf[a] = (buf[a] - buf[b]) & 0xFF
        elif op == OP_MULADD:
            _, a, mul, add = ins
            buf[a] = (buf[a] * mul + add) & 0xFF
        elif op == OP_TRIAD:
            _, a, b, c = ins
            tmp = buf[a]
            buf[a] = buf[b]
            buf[b] = buf[c]
            buf[c] = tmp
        else:
            raise AssertionError(op)


def must_find(buf: bytes, needle: bytes, name: str) -> int:
    off = buf.find(needle)
    if off < 0:
        raise ValueError(f"could not locate {name}")
    return off


def find_stage_blobs(pe: PE, rdata: bytes) -> List[bytes]:
    """Locate the three struct vm_blob entries and return decoded bytecode."""
    hits: List[List[bytes]] = []
    for off in range(0, len(rdata) - 40 * 3 + 1, 8):
        decoded: List[bytes] = []
        ok = True
        for sid in range(3):
            boff = off + sid * 40
            enc_va, enc_len, key_va, key_len = struct.unpack_from("<QQQQ", rdata, boff)
            stage_id = rdata[boff + 32]
            mix_mult = rdata[boff + 33]
            if stage_id != sid or mix_mult != (5 + sid * 2):
                ok = False
                break
            if not (64 <= enc_len <= 2048 and 1 <= key_len <= 32):
                ok = False
                break
            try:
                enc_off = pe.va_to_section_relative(enc_va, ".rdata")
                key_off = pe.va_to_section_relative(key_va, ".rdata")
            except ValueError:
                ok = False
                break
            if enc_off < 0 or key_off < 0 or enc_off + enc_len > len(rdata) or key_off + key_len > len(rdata):
                ok = False
                break
            enc = rdata[enc_off:enc_off + enc_len]
            key = rdata[key_off:key_off + key_len]
            try:
                decoded.append(decode_stage(enc, key, stage_id, mix_mult))
            except Exception:
                ok = False
                break
        if ok and len(decoded) == 3:
            hits.append(decoded)
    if not hits:
        raise ValueError("stage_blobs not found")
    return hits[0]


def extract_validator(exe_path: Path) -> Dict[str, object]:
    pe = PE(exe_path.read_bytes())
    rdata = pe.section(".rdata")

    prefix_off = must_find(rdata, b"ITECHNO26{", "flag prefix")
    prefix = rdata[prefix_off:rdata.find(b"\0", prefix_off)].decode("ascii")
    primary_seed = b"\\DACL\x00\\Device"
    shadow_seed = b"\\DosDevice"
    for needle, name in (
        (primary_seed, "primary_seed"),
        (shadow_seed, "shadow_seed"),
    ):
        must_find(rdata, needle, name)

    chunk_words = CORE_LEN // CHUNK_LEN

    chunk_mask_hi_pat = struct.pack(
        "<8I",
        0x7C6A5D4B, 0x1F2E3D4C, 0x55667788, 0xCAFEBABE,
        0x0BADF00D, 0x12345678, 0x89ABCDEF, 0x13579BDF,
    )
    chunk_mask_hi_off = must_find(rdata, chunk_mask_hi_pat, "chunk_mask_hi")
    chunk_mask_hi = u32s(rdata[chunk_mask_hi_off:chunk_mask_hi_off + (chunk_words * 4)])

    chunk_mask_lo_pat = struct.pack(
        "<8I",
        0x10111213, 0x20212223, 0x30313233, 0x40414243,
        0x50515253, 0x60616263, 0x70717273, 0x80818283,
    )
    chunk_mask_lo_off = must_find(rdata, chunk_mask_lo_pat, "chunk_mask_lo")
    chunk_mask_lo = u32s(rdata[chunk_mask_lo_off:chunk_mask_lo_off + (chunk_words * 4)])

    chunk_target_hi_pat = struct.pack(
        "<8I",
        0x0DAEFF17, 0x526BF1FB, 0x18319A9C, 0xCF30F38F,
        0x41C988C1, 0x81AF5B0E, 0x6EE702F9, 0xEE5F4153,
    )
    chunk_target_hi_off = must_find(rdata, chunk_target_hi_pat, "chunk_target_hi")
    chunk_target_hi = u32s(rdata[chunk_target_hi_off:chunk_target_hi_off + (chunk_words * 4)])

    chunk_target_lo_pat = struct.pack(
        "<8I",
        0x0A0B0C0D, 0x1A1B1C1D, 0x2A2B2C2D, 0x3A3B3C3D,
        0x4A4B4C4D, 0x5A5B5C5D, 0x6A6B6C6D, 0x7A7B7C7D,
    )
    chunk_target_lo_off = must_find(rdata, chunk_target_lo_pat, "chunk_target_lo")
    chunk_target_lo = u32s(rdata[chunk_target_lo_off:chunk_target_lo_off + (chunk_words * 4)])
    chunk_targets = [
        ((chunk_target_lo[i] ^ chunk_target_hi[i]) ^ (chunk_mask_lo[i] ^ chunk_mask_hi[i])) & U32
        for i in range(chunk_words)
    ]

    return {
        "prefix": prefix,
        "primary_seed": primary_seed,
        "shadow_seed": shadow_seed,
        "chunk_mask_lo": chunk_mask_lo,
        "chunk_mask_hi": chunk_mask_hi,
        "chunk_target_lo": chunk_target_lo,
        "chunk_target_hi": chunk_target_hi,
        "chunk_targets": chunk_targets,
    }


def premix_primary(buf: bytearray, seed: bytes) -> None:
    for i in range(len(buf)):
        buf[i] ^= seed[i % len(seed)]
        buf[i] ^= (0x31 + i * 7) & 0xFF
        buf[i] = rol8(buf[i], ((i ^ 3) % 5) + 1)


def premix_shadow(buf: bytearray, seed: bytes) -> None:
    for i in range(len(buf)):
        buf[i] ^= seed[(i * 3 + 1) % len(seed)]
        buf[i] ^= (0x22 + i * 9) & 0xFF
        buf[i] = ror8(buf[i], ((i + 1) % 5) + 1)


def decoy_a(buf: bytearray, seed: bytes) -> None:
    n = len(buf)
    for i in range(n):
        buf[i] ^= seed[(i * 5 + 2) % len(seed)]
        buf[i] ^= (0x20 + i * 13) & 0xFF
        buf[i] = rol8(buf[i], (i % 5) + 1)
    for i in range(0, n - 3, 4):
        buf[i], buf[i + 3] = buf[i + 3], buf[i]


def decoy_b(buf: bytearray, seed: bytes) -> None:
    n = len(buf)
    i = n
    while i > 0:
        idx = i - 1
        peer = buf[(idx + 7) % n]
        buf[idx] = (buf[idx] + peer) & 0xFF
        buf[idx] = (buf[idx] + seed[(idx * 2 + 1) % len(seed)]) & 0xFF
        buf[idx] = (buf[idx] + idx) & 0xFF
        buf[idx] ^= (0x48 + idx * 3) & 0xFF
        buf[idx] = ror8(buf[idx], ((idx ^ 0x48) & 3) + 1)
        i = idx


def decoy_c(buf: bytearray, seed: bytes) -> None:
    n = len(buf)
    for i in range(0, n - 2, 3):
        tmp = buf[i]
        buf[i] = buf[i + 1] ^ seed[i % len(seed)]
        buf[i + 1] = (buf[i + 2] + seed[(i + 1) % len(seed)]) & 0xFF
        buf[i + 2] = tmp ^ ((0x26 + i) & 0xFF)
    for i in range(n):
        buf[i] = (buf[i] - ((i * 5 + 0x11) & 0xFF)) & 0xFF


def fold_chunk(primary: bytes, shadow: bytes) -> int:
    n = len(primary)
    acc = 0xA5C39E17
    for rnd in range(4):
        for i in range(n):
            a = primary[(i + rnd) % n]
            b = shadow[(i * 3 + rnd + 1) % n]
            c = primary[(i + 2) % n] ^ shadow[(i + rnd + 2) % n]
            d = shadow[(i + 3) % n]
            word = a | (b << 8) | (c << 16) | (d << 24)
            step = (rnd + 1) * (i + 1)
            acc ^= (word + ((step * 0x45D9F3B) & U32)) & U32
            acc = rotl32(acc, ((a ^ b ^ c ^ d ^ rnd) & 7) + 5)
            acc = (acc + (0x9E3779B9 ^ ((a * 0x01010101) & U32) ^ ((b * 257) & U32))) & U32
    return acc


def chunk_state(chunk: bytes, v: Dict[str, object]) -> int:
    primary = bytearray(chunk)
    shadow = bytearray(chunk)
    premix_primary(primary, v["primary_seed"])
    premix_shadow(shadow, v["shadow_seed"])
    return fold_chunk(primary, shadow)


def check_chunk(chunk: str, chunk_index: int, v: Dict[str, object]) -> bool:
    if len(chunk) != CHUNK_LEN:
        return False
    targets: List[int] = v["chunk_targets"]
    return chunk_state(chunk.encode("ascii"), v) == targets[chunk_index]


def validate_flag(flag: str, v: Dict[str, object]) -> bool:
    prefix = v["prefix"]
    if not isinstance(prefix, str):
        return False
    if not flag.startswith(prefix) or not flag.endswith("}"):
        return False
    core = flag[len(prefix):-1]
    if len(core) != CORE_LEN:
        return False
    if not all((ch.islower() or ch.isdigit() or ch == "_") for ch in core):
        return False
    for idx in range(CORE_LEN // CHUNK_LEN):
        start = idx * CHUNK_LEN
        if not check_chunk(core[start:start + CHUNK_LEN], idx, v):
            return False
    return True


def solve_by_chunks(v: Dict[str, object]) -> str:
    charset = b"abcdefghijklmnopqrstuvwxyz0123456789_"
    targets: List[int] = v["chunk_targets"]
    pending: Dict[int, List[int]] = {}
    solved: List[str | None] = [None] * (CORE_LEN // CHUNK_LEN)

    for idx, target in enumerate(targets):
        pending.setdefault(target, []).append(idx)

    print("[*] extracted chunk validator from EXE")
    print("[*] chunk_targets = " + " ".join(f"0x{x:08x}" for x in targets))
    print(f"[*] brute-forcing {len(targets)} chunks over {len(charset)}^{CHUNK_LEN} candidates...")

    for cand in product(charset, repeat=CHUNK_LEN):
        candidate = bytes(cand)
        state = chunk_state(candidate, v)
        if state not in pending:
            continue
        chunk_text = candidate.decode("ascii")
        for idx in pending.pop(state):
            solved[idx] = chunk_text
            print(f"[*] chunk {idx:02d} = {chunk_text}")
        if not pending:
            break

    if pending:
        missing = ", ".join(str(idx) for indexes in pending.values() for idx in indexes)
        raise SystemExit(f"failed to recover chunk(s): {missing}")

    core = "".join(part for part in solved if part is not None)
    flag = f"{v['prefix']}{core}}}"
    if not validate_flag(flag, v):
        raise SystemExit("recovered chunks did not pass the extracted validator emulator")
    return flag


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Solve ITECHNO Vault from the public EXE only")
    ap.add_argument("exe", type=Path, help="path to itechno_vault.exe")
    ap.add_argument("--verify", help="verify a candidate flag using constants extracted from the EXE")
    args = ap.parse_args(argv[1:])

    v = extract_validator(args.exe)

    if args.verify:
        print("OK" if validate_flag(args.verify, v) else "NO")
        return 0

    flag = solve_by_chunks(v)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
