#!/usr/bin/env python3
import os
from pathlib import Path
import sys


MASK = 0xFFFFFFFFFFFFFFFF
REC12_OFFSET = 0x858
HASH_NODE = 0xC1FDF006
CLIENT_NODE = 0xC1FDF007
OWNER_DELTA = 0x38
ARCHIVE_DELTA = 0x40
BASE_DELTA = 0x48
LAST_DELTA = 0x50
RESTART_DELTA = 0x58
NONCE_DELTA = 0x60
PROOF_DELTA = 0x68
REGION_TAIL = 0x30

OWNER_VALUE = 0xFFFFFFFF00FF0001
REC12_VALUE = 0x0369
NONCE_LIMIT = 0x40000000
TARGET32 = 0x36EE86B0
EXTRA16 = 0x5AF9
OUTER_PASSWORD = b"$ivm_gate_seed_for_blf_path_26$"
OUTER_SEED_XOR = 0x49544543482D564D


def rol64(x: int, r: int) -> int:
    r &= 63
    if r == 0:
        return x & MASK
    x &= MASK
    return ((x << r) & MASK) | (x >> (64 - r))


def mix64(x: int) -> int:
    x &= MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    x ^= x >> 31
    return x & MASK


def fold32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= x >> 13
    x = (x * 0x45D9F3B) & 0xFFFFFFFF
    x ^= x >> 16
    return x & 0xFFFFFFFF


def hash_region(buf: bytes) -> int:
    x = 0xCBF29CE484222325
    for i, b in enumerate(buf):
        x ^= (b + ((i * 0x9D) & 0xFF)) & 0xFF
        x = (x * 0x100000001B3) & MASK
        x = rol64(x, 7) ^ 0xA0761D6478BD642F
    return x & MASK


def derive_outer_passseed() -> int:
    qwords_le = [
        int.from_bytes(OUTER_PASSWORD[i:i + 8], "little")
        for i in range(0, len(OUTER_PASSWORD), 8)
    ]
    mem0, mem1, mem2, mem3 = list(reversed(qwords_le))
    seed = mem0
    seed ^= rol64(mem1, 7)
    seed ^= rol64(mem2, 13)
    seed ^= rol64(mem3, 29)
    seed ^= OUTER_SEED_XOR
    return mix64(seed)


def locate_client_context(blob: bytes) -> tuple[int, int]:
    hash_off = blob.find(HASH_NODE.to_bytes(4, "little"))
    if hash_off < 0:
        raise ValueError("hash node not found")

    ctx_off = blob.find(CLIENT_NODE.to_bytes(4, "little"), hash_off + 4)
    if ctx_off < 0:
        raise ValueError("client context not found")

    return hash_off, ctx_off


def derive_stage1(region_hash: int, distance: int, passseed: int) -> tuple[int, int, int, int, int]:
    archive = rol64(
        OWNER_VALUE ^ 0x0F1E2D3C4B5A6978,
        (REC12_VALUE ^ distance) & 31,
    ) ^ 0x6A09E667F3BCC909
    base = mix64((OWNER_VALUE + archive + region_hash + REC12_VALUE) & MASK)
    base ^= 0x94D049BB133111EB
    last = rol64(((base ^ region_hash) + 0x9E3779B97F4A7C15) & MASK, 17)
    last ^= 0xD1B54A32D192ED03
    restart = mix64(((OWNER_VALUE ^ archive) + last + region_hash) & MASK)
    restart ^= 0x8C6F736B8DDF1234
    stage1_seed = mix64(
        (((((OWNER_VALUE ^ archive) + base) & MASK) ^ last) + restart) & MASK
        ^ region_hash
        ^ 0x53EED1F0CAFE4242
    )
    stage1_seed = mix64(stage1_seed ^ passseed)
    return archive, base, last, restart, stage1_seed


def derive_proof(stage1_seed: int, owner: int, archive: int, base: int, last: int, restart: int, region_hash: int, passseed: int, nonce: int) -> int:
    const_a = 0x7F4A7C159E3779B9
    proof_const = 0x13579BDF2468ACE0

    r0 = stage1_seed ^ ((nonce * 0x10001) & MASK)
    r0 = mix64((r0 + const_a) & MASK)
    r0 = rol64(r0, nonce & 31)
    r0 ^= owner
    r0 = mix64((r0 + archive) & MASK)
    r0 ^= base
    r0 = mix64((r0 + last + restart) & MASK)
    r0 ^= (nonce * 0x1F123BB5) & MASK
    r0 = mix64((r0 + region_hash) & MASK)
    return (r0 ^ proof_const ^ passseed) & MASK


def is_valid_candidate(stage1_seed: int, proof: int, nonce: int) -> bool:
    if fold32((proof ^ (proof >> 32) ^ nonce) & 0xFFFFFFFF) != TARGET32:
        return False

    if (mix64(((proof >> 8) ^ stage1_seed) & MASK) & 0xFFFF) != EXTRA16:
        return False

    return True


def brute_nonce(stage1_seed: int, owner: int, archive: int, base: int, last: int, restart: int, region_hash: int, passseed: int) -> tuple[int, int]:
    for nonce in range(NONCE_LIMIT):
        proof = derive_proof(stage1_seed, owner, archive, base, last, restart, region_hash, passseed, nonce)

        if not is_valid_candidate(stage1_seed, proof, nonce):
            continue

        return nonce, proof & MASK

    raise ValueError("nonce not found")


def patch_qword(buf: bytearray, offset: int, value: int) -> None:
    buf[offset:offset + 8] = value.to_bytes(8, "little")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "handout" / "client.blf"
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "solve" / "client_solved.blf"
    nonce_override = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("ITECHVM_KNOWN_NONCE")

    data = bytearray(src.read_bytes())
    hash_off, ctx_off = locate_client_context(data)
    region_hash = hash_region(data[hash_off:ctx_off + REGION_TAIL])
    distance = ctx_off - hash_off
    passseed = derive_outer_passseed()
    archive, base, last, restart, stage1_seed = derive_stage1(region_hash, distance, passseed)
    if nonce_override is None:
        nonce, proof = brute_nonce(stage1_seed, OWNER_VALUE, archive, base, last, restart, region_hash, passseed)
        nonce_source = "brute-forced"
    else:
        nonce = int(nonce_override, 0)
        if nonce < 0 or nonce >= NONCE_LIMIT:
            raise ValueError("nonce override out of range")
        proof = derive_proof(stage1_seed, OWNER_VALUE, archive, base, last, restart, region_hash, passseed, nonce)
        if not is_valid_candidate(stage1_seed, proof, nonce):
            raise ValueError("nonce override does not satisfy stage-2 checks")
        nonce_source = "override"

    data[REC12_OFFSET:REC12_OFFSET + 2] = REC12_VALUE.to_bytes(2, "little")
    patch_qword(data, ctx_off + OWNER_DELTA, OWNER_VALUE)
    patch_qword(data, ctx_off + ARCHIVE_DELTA, archive)
    patch_qword(data, ctx_off + BASE_DELTA, base)
    patch_qword(data, ctx_off + LAST_DELTA, last)
    patch_qword(data, ctx_off + RESTART_DELTA, restart)
    patch_qword(data, ctx_off + NONCE_DELTA, nonce)
    patch_qword(data, ctx_off + PROOF_DELTA, proof)
    dst.write_bytes(data)

    print(f"patched {src} -> {dst}")
    print(f"hash node        : 0x{hash_off:x}")
    print(f"client context   : 0x{ctx_off:x}")
    print(f"record_offset[12]: 0x{REC12_VALUE:04x}")
    print(f"lsnOwnerPage     : 0x{OWNER_VALUE:016x}")
    print(f"lsnArchiveTail   : 0x{archive:016x}")
    print(f"lsnBase          : 0x{base:016x}")
    print(f"lsnLast          : 0x{last:016x}")
    print(f"lsnRestart       : 0x{restart:016x}")
    print(f"lsnPhysicalBase  : 0x{nonce:016x}")
    print(f"lsnUnused1       : 0x{proof:016x}")
    print(f"outer passseed   : 0x{passseed:016x}")
    print(f"nonce search     : {nonce_source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
