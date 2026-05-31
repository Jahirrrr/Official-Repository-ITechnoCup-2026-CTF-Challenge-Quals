#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from time import perf_counter


IMAGE_SIZE = 4096
FORWARD_STEPS = 96
BACKWARD_STEPS = 48
SPICE_LEN = 256
PAD_LEN = 64
SCHEDULE_LEN = 128
BLOB_MAGIC = b"N0TRACE1"
STAGE_GATE_WORDS = 4


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def rol32(value: int, shift: int) -> int:
    value = u32(value)
    shift &= 31
    return u32((value << shift) | (value >> ((32 - shift) & 31)))


def ror32(value: int, shift: int) -> int:
    value = u32(value)
    shift &= 31
    return u32((value >> shift) | (value << ((32 - shift) & 31)))


def parse_elf_rodata(path: Path) -> bytes:
    data = path.read_bytes()

    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("expected ELF64 little-endian")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr_off + 0x18)[0]
    shstr_size = struct.unpack_from("<Q", data, shstr_hdr_off + 0x20)[0]
    shstr = data[shstr_off:shstr_off + shstr_size]

    for idx in range(e_shnum):
        sh_off = e_shoff + idx * e_shentsize
        name_off = struct.unpack_from("<I", data, sh_off)[0]
        sec_off = struct.unpack_from("<Q", data, sh_off + 0x18)[0]
        sec_size = struct.unpack_from("<Q", data, sh_off + 0x20)[0]
        end = shstr.find(b"\x00", name_off)
        name = shstr[name_off:end].decode("ascii")
        if name == ".rodata":
            return data[sec_off:sec_off + sec_size]

    raise ValueError("missing .rodata")


def unpack_u32(buf: bytes, offset: int, count: int) -> list[int]:
    return list(struct.unpack_from(f"<{count}I", buf, offset))


def extract_constants(binary_path: Path) -> dict[str, object]:
    rodata = parse_elf_rodata(binary_path)
    blob_off = rodata.find(BLOB_MAGIC)
    if blob_off < 0:
        raise ValueError("challenge blob magic not found")

    cursor = blob_off + len(BLOB_MAGIC)
    flag_len = struct.unpack_from("<I", rodata, cursor)[0]
    cursor += 4
    trace_prefix_len = struct.unpack_from("<I", rodata, cursor)[0]
    cursor += 4
    stage_count = struct.unpack_from("<I", rodata, cursor)[0]
    cursor += 4
    stage_gate_words = struct.unpack_from("<I", rodata, cursor)[0]
    cursor += 4
    max_stage_charset_len = struct.unpack_from("<I", rodata, cursor)[0]
    cursor += 4
    stage_lengths = list(rodata[cursor:cursor + stage_count])
    cursor += stage_count
    stage_charset_lens = list(rodata[cursor:cursor + stage_count])
    cursor += stage_count
    stage_burn_rounds = unpack_u32(rodata, cursor, stage_count)
    cursor += stage_count * 4

    raw_stage_charsets = rodata[cursor:cursor + stage_count * max_stage_charset_len]
    cursor += stage_count * max_stage_charset_len
    stage_charsets: list[str] = []
    for idx in range(stage_count):
        start = idx * max_stage_charset_len
        raw = raw_stage_charsets[start:start + max_stage_charset_len]
        stage_charsets.append(raw[:stage_charset_lens[idx]].decode("ascii"))

    flat_stage_gates = unpack_u32(rodata, cursor, stage_count * stage_gate_words)
    cursor += stage_count * stage_gate_words * 4
    stage_gates = [
        flat_stage_gates[idx * stage_gate_words:(idx + 1) * stage_gate_words]
        for idx in range(stage_count)
    ]

    final_seal = unpack_u32(rodata, cursor, 8)
    cursor += 8 * 4
    trace_gates = unpack_u32(rodata, cursor, trace_prefix_len)
    cursor += trace_prefix_len * 4
    spice = unpack_u32(rodata, cursor, SPICE_LEN)
    cursor += SPICE_LEN * 4
    pad = unpack_u32(rodata, cursor, PAD_LEN)
    cursor += PAD_LEN * 4
    sbox = list(rodata[cursor:cursor + 256])
    cursor += 256
    lane_schedule = list(rodata[cursor:cursor + 256])
    cursor += 256
    rot_schedule = list(rodata[cursor:cursor + SCHEDULE_LEN])
    cursor += SCHEDULE_LEN
    exec_ops = list(rodata[cursor:cursor + SCHEDULE_LEN])
    cursor += SCHEDULE_LEN
    boot_ops = list(rodata[cursor:cursor + SCHEDULE_LEN])
    cursor += SCHEDULE_LEN
    init_state = unpack_u32(rodata, cursor, 8)
    cursor += 8 * 4

    if stage_gate_words != STAGE_GATE_WORDS:
        raise ValueError(f"unsupported stage gate width: {stage_gate_words}")

    blob = rodata[blob_off:cursor]
    return {
        "fingerprint": hashlib.sha256(blob).hexdigest(),
        "flag_len": flag_len,
        "trace_prefix_len": trace_prefix_len,
        "stage_count": stage_count,
        "stage_gate_words": stage_gate_words,
        "max_stage_charset_len": max_stage_charset_len,
        "stage_lengths": stage_lengths,
        "stage_charset_lens": stage_charset_lens,
        "stage_burn_rounds": stage_burn_rounds,
        "stage_charsets": stage_charsets,
        "stage_gates": stage_gates,
        "final_seal": final_seal,
        "trace_gates": trace_gates,
        "spice": spice,
        "pad": pad,
        "sbox": sbox,
        "lane_schedule": lane_schedule,
        "rot_schedule": rot_schedule,
        "exec_ops": exec_ops,
        "boot_ops": boot_ops,
        "init_state": init_state,
    }


def sub_word(word: int, sbox: list[int]) -> int:
    word = u32(word)
    return (
        sbox[word & 0xFF]
        | (sbox[(word >> 8) & 0xFF] << 8)
        | (sbox[(word >> 16) & 0xFF] << 16)
        | (sbox[(word >> 24) & 0xFF] << 24)
    )


def vm_step(
    local: list[int],
    sigma: list[int],
    round_keys: list[int],
    lane: int,
    op: int,
    rot: int,
    sp: int,
    arg: int,
    idx: int,
    tweak: int,
    sbox: list[int],
) -> None:
    arg = u32(arg)
    sp = u32(sp)
    a = lane & 7
    b = (lane + 1) & 7
    c = (lane + 3) & 7
    d = (lane + 5) & 7

    if op == 0:
        local[a] = rol32(local[a] + sp + arg, rot)
    elif op == 1:
        local[a] ^= rol32(sub_word((arg ^ sp) + local[d], sbox), rot)
    elif op == 2:
        local[a] = u32(local[a] + (local[b] ^ rol32(local[c], rot)))
    elif op == 3:
        local[a] = rol32(local[a] ^ local[d] ^ sub_word(sp + arg, sbox), rot)
        local[b] = u32(local[b] + local[a] + 0x7F4A7C15)
    elif op == 4:
        tmp = local[a]
        local[a] = local[b] ^ ror32(local[c] + sp + arg, rot)
        local[c] = u32(local[c] + tmp + 0x01020304)
    elif op == 5:
        local[a] = u32((local[a] * (sp | 1)) + rol32(arg ^ 0x41A7C35F, rot))
    elif op == 6:
        local[a] = rol32(local[a] + sub_word(local[d] ^ sp, sbox) + arg, rot)
        local[d] ^= rol32(sp ^ arg, a + 1)
    elif op == 7:
        local[a] ^= u32(ror32(local[b], rot) + sp + (sub_word(arg, sbox) << (((tweak ^ lane) % 3) + 1)))
    elif op == 8:
        local[a] = u32(sub_word(local[a] ^ rol32(local[b] + sp, rot), sbox) + local[c])
        local[d] = ror32(local[d] ^ local[a], (rot % 13) + 1)
    else:
        local[a] = ror32(local[a] + local[b] + sp + arg, rot)
        local[b] ^= rol32(sub_word(local[c] ^ arg, sbox), ((a + rot) % 31) + 1)

    swap_i = (idx + local[a] + arg) & 0xFF
    swap_j = (sigma[(idx + rot + (local[b] & 0xFF)) & 0xFF] + (local[d] & 0xFF) + op) & 0xFF
    sigma[swap_i], sigma[swap_j] = sigma[swap_j], sigma[swap_i]

    rk0 = (idx + op + a) & 0x7F
    rk1 = (tweak + a + op) & 0x7F
    round_keys[rk0] ^= rol32(local[a] ^ sp ^ arg, rot)
    round_keys[rk1] = u32(round_keys[rk1] + local[d] + sigma[swap_i] + 0x9E3779B9)
    local[(a + op + 2) & 7] ^= rol32(u32(0x9E3779B9 ^ tweak ^ arg), ((a + rot + op) % 31) + 1)

    for pos in range(8):
        local[pos] = u32(local[pos])
    for pos in (rk0, rk1):
        round_keys[pos] = u32(round_keys[pos])


def bootstrap_vm(consts: dict[str, object], image: bytes) -> tuple[list[int], list[int], list[int]]:
    init_state = list(consts["init_state"])
    spice = consts["spice"]
    pad = consts["pad"]
    sbox = consts["sbox"]
    lane_schedule = consts["lane_schedule"]
    rot_schedule = consts["rot_schedule"]
    boot_ops = consts["boot_ops"]

    state = init_state[:]
    sigma = list(range(256))
    round_keys = [
        u32(
            u32(0x9E3779B9 * (idx + 1))
            ^ spice[idx]
            ^ rol32(spice[(idx + 17) & 0xFF], idx % 31 + 1)
        )
        for idx in range(SCHEDULE_LEN)
    ]

    for pc in range(IMAGE_SIZE):
        idx = (
            pc
            ^ sigma[(pc + (state[pc & 7] & 0xFF)) & 0xFF]
            ^ ((state[(pc + 3) & 7] >> ((pc & 3) * 8)) & 0xFF)
            ^ image[pc]
        ) & 0xFF
        lane = lane_schedule[idx] & 7
        op = boot_ops[(idx ^ sigma[(idx + lane + pc) & 0xFF] ^ (pc >> 5)) & 0x7F]
        rot = rot_schedule[(idx + sigma[pc & 0xFF] + lane) & 0x7F]
        sp = u32(spice[(idx + sigma[(pc ^ lane) & 0xFF]) & 0xFF] ^ pad[(pc + lane) & 0x3F])
        arg = u32((pc * 0x045D9F3B) ^ sp ^ sigma[(pc + idx) & 0xFF])
        vm_step(state, sigma, round_keys, lane, op, rot, sp, arg, idx, pc, sbox)

    boot_state = [
        u32(
            state[idx]
            ^ rol32(state[(idx + 3) & 7], ((idx * 7 + 5) % 31) + 1)
            ^ round_keys[(idx * 17 + sigma[idx]) & 0x7F]
            ^ spice[(sigma[(idx * 13) & 0xFF] + idx) & 0xFF]
        )
        for idx in range(8)
    ]
    return boot_state, sigma, round_keys


def seed_context(consts: dict[str, object], image: bytes) -> tuple[list[int], list[int], list[int]]:
    spice = consts["spice"]
    boot_state, sigma, round_keys = bootstrap_vm(consts, image)
    state = [
        u32(boot_state[idx] ^ spice[(idx * 29 + sigma[idx]) & 0xFF] ^ round_keys[(idx * 13 + idx) & 0x7F])
        for idx in range(8)
    ]
    return state, sigma, round_keys


def compress_trace(
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    spice: list[int],
    pad: list[int],
    sbox: list[int],
    pos: int,
    ch: int,
) -> int:
    x = u32(
        state[pos & 7]
        ^ rol32(state[(pos + 3) & 7], 5)
        ^ round_keys[(pos * 13 + sigma[(ch + pos) & 0xFF]) & 0x7F]
    )
    y = u32(
        state[(pos + 5) & 7]
        + ror32(state[(pos + 1) & 7], 7)
        + spice[(sigma[pos] + ch) & 0xFF]
        + pad[pos & 0x3F]
    )
    z = sub_word(x ^ y ^ ch ^ pad[(pos * 5 + 3) & 0x3F], sbox)
    return u32(
        z
        ^ rol32(u32(x + spice[(pos * 7 + ch) & 0xFF]), (y & 15) + 1)
        ^ round_keys[(x ^ y) & 0x7F]
    )


def forward_char(
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    trace: list[int],
    pos: int,
    ch: int,
    consts: dict[str, object],
) -> tuple[list[int], list[int], list[int], int]:
    spice = consts["spice"]
    pad = consts["pad"]
    sbox = consts["sbox"]
    lane_schedule = consts["lane_schedule"]
    rot_schedule = consts["rot_schedule"]
    exec_ops = consts["exec_ops"]

    local = state[:]
    sigma = sigma[:]
    round_keys = round_keys[:]

    for step in range(FORWARD_STEPS):
        pc = pos * FORWARD_STEPS + step
        tap = sigma[(ch + step + pos + (local[(step + pos) & 7] & 0xFF)) & 0xFF]
        idx = (
            pc
            + tap
            + ((local[(pos + 2) & 7] >> ((step & 3) * 8)) & 0xFF)
            + sbox[(ch + step) & 0xFF]
        ) & 0xFF
        lane = lane_schedule[idx] & 7
        op = exec_ops[(idx ^ round_keys[(pc + lane) & 0x7F] ^ sigma[(idx + pc) & 0xFF]) & 0x7F]
        rot = rot_schedule[(idx + lane + sigma[(pc ^ pos) & 0xFF]) & 0x7F]
        sp = u32(
            spice[(idx + sigma[(lane + ch + step) & 0xFF]) & 0xFF]
            ^ round_keys[(idx + pos) & 0x7F]
            ^ pad[(pc + lane) & 0x3F]
        )
        arg = u32((ch << 24) ^ (pos << 16) ^ (step << 8) ^ tap ^ local[(lane + 5) & 7])
        vm_step(local, sigma, round_keys, lane, op, rot, sp, arg, idx, pc ^ (pos << 8) ^ ch, sbox)
        local[(lane + op + 3) & 7] ^= rol32(
            u32(0x85EBCA6B ^ pc ^ ch ^ (trace[pos - 1] if pos else round_keys[0])),
            ((lane + pos + step) % 31) + 1,
        )
        local[(lane + op + 3) & 7] = u32(local[(lane + op + 3) & 7])

    prev_trace = trace[pos - 1] if pos else round_keys[3]
    next_state = [0] * 8
    next_state[0] = u32(local[0] ^ rol32(local[5], 3) ^ round_keys[(pos * 9 + sigma[pos]) & 0x7F])
    next_state[1] = u32(local[1] + ror32(local[6], 5) + spice[(pos * 11 + 1 + sigma[(pos + 13) & 0xFF]) & 0xFF])
    next_state[2] = u32(rol32(local[2] ^ next_state[0] ^ sub_word(ch * 0x045D9F3B, sbox), (pos % 13) + 5))
    next_state[3] = u32(local[3] ^ next_state[1] ^ ror32(local[7] + 0xA5A5A5A5 + pos + sigma[(pos + 31) & 0xFF], 7))
    next_state[4] = u32(local[4] + sub_word(next_state[2] ^ round_keys[(pos * 5 + 4) & 0x7F], sbox))
    next_state[5] = u32(rol32(local[5] ^ next_state[3] ^ spice[(pos * 3 + 17) & 0xFF], 11))
    next_state[6] = u32(local[6] ^ ror32(next_state[4] + prev_trace, 9))
    next_state[7] = u32(local[7] + rol32(next_state[5] ^ local[0] ^ round_keys[(pos * 7 + 7) & 0x7F], 13))

    trace_val = compress_trace(next_state, sigma, round_keys, spice, pad, sbox, pos, ch)

    pivot = (trace_val ^ sigma[(ch + pos) & 0xFF]) & 0xFF
    buddy = (pivot + sbox[(trace_val >> 8) & 0xFF] + pos) & 0xFF
    sigma[pivot], sigma[buddy] = sigma[buddy], sigma[pivot]
    round_keys[(pos + pivot) & 0x7F] = u32(round_keys[(pos + pivot) & 0x7F] ^ rol32(trace_val, (pos % 31) + 1))
    round_keys[(buddy + pos * 3) & 0x7F] = u32(round_keys[(buddy + pos * 3) & 0x7F] + trace_val + sigma[pivot])

    return next_state, sigma, round_keys, trace_val


def stage_digest(
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    trace: list[int],
    processed_len: int,
    parity: int,
    stage_idx: int,
    burn_rounds: int,
    consts: dict[str, object],
) -> list[int]:
    spice = consts["spice"]
    pad = consts["pad"]
    sbox = consts["sbox"]
    acc = [0] * STAGE_GATE_WORDS

    for idx in range(STAGE_GATE_WORDS):
        anchor = trace[(processed_len - 1 - idx) % processed_len]
        twist = trace[(sigma[(stage_idx * 29 + idx * 17) & 0xFF] + idx) % processed_len]
        key = round_keys[(parity + stage_idx * 11 + idx * 19 + anchor) & 0x7F]
        acc[idx] = u32(
            state[(stage_idx + idx * 2) & 7]
            ^ rol32(state[(stage_idx + idx * 2 + 3) & 7], ((stage_idx + idx * 5) % 31) + 1)
            ^ key
            ^ spice[(twist + sigma[(stage_idx * 31 + idx * 7) & 0xFF]) & 0xFF]
            ^ twist
        )

    for rnd in range(burn_rounds):
        lane = sigma[(rnd + stage_idx + (acc[0] & 0xFF)) & 0xFF] & 7
        trace_word = trace[(rnd + sigma[(rnd + lane + stage_idx) & 0xFF]) % processed_len]
        key = round_keys[(rnd + stage_idx + (trace_word & 0x7F)) & 0x7F]
        spice_word = u32(
            spice[(sigma[(trace_word + rnd) & 0xFF] + lane + stage_idx) & 0xFF]
            ^ pad[(rnd + stage_idx + lane) & 0x3F]
        )
        mix = sub_word(trace_word ^ key ^ spice_word ^ parity ^ rnd, sbox)

        acc[0] = u32(rol32(acc[0] + mix + state[(lane + 1) & 7], ((mix >> 27) & 31) + 1))
        acc[1] = u32(acc[1] ^ ror32(mix + acc[0] + state[(lane + 3) & 7], ((lane + rnd) % 31) + 1))
        acc[2] = u32(
            rol32(
                acc[2] ^ acc[1] ^ round_keys[(lane * 9 + rnd) & 0x7F],
                ((stage_idx + lane + 7) % 31) + 1,
            )
        )
        acc[3] = u32(acc[3] + sub_word(acc[2] ^ spice_word ^ trace[(rnd + lane + stage_idx * 5) % processed_len], sbox))
        acc[3] = u32(ror32(acc[3], ((acc[0] ^ acc[2]) & 15) + 1))
        slot = (rnd + stage_idx) % STAGE_GATE_WORDS
        acc[slot] = u32(acc[slot] ^ rol32(trace_word ^ parity ^ key, ((rnd >> 3) & 31) + 1))

    for idx in range(STAGE_GATE_WORDS):
        acc[idx] = u32(
            acc[idx]
            ^ round_keys[(processed_len * 7 + stage_idx * 13 + idx * 19) & 0x7F]
            ^ trace[(processed_len + idx * 11) % processed_len]
        )

    return acc


def recover_prefix(
    consts: dict[str, object],
    image: bytes,
    charset: str,
) -> tuple[str, list[int], list[int], list[int], list[int], int]:
    trace_gates = consts["trace_gates"]
    trace_prefix_len = consts["trace_prefix_len"]
    flag_len = consts["flag_len"]

    state, sigma, round_keys = seed_context(consts, image)
    trace = [0] * flag_len
    parity = 0
    recovered: list[str] = []

    for pos in range(trace_prefix_len):
        matches: list[tuple[str, list[int], list[int], list[int], int]] = []
        for ch in charset.encode("ascii"):
            next_state, next_sigma, next_keys, trace_val = forward_char(
                state,
                sigma,
                round_keys,
                trace,
                pos,
                ch,
                consts,
            )
            if trace_val == trace_gates[pos]:
                matches.append((chr(ch), next_state, next_sigma, next_keys, trace_val))

        if len(matches) != 1:
            preview = ", ".join(repr(item[0]) for item in matches[:8])
            raise RuntimeError(f"position {pos}: expected 1 match, got {len(matches)} [{preview}]")

        ch, state, sigma, round_keys, trace_val = matches[0]
        recovered.append(ch)
        trace[pos] = trace_val
        parity = u32(parity ^ trace_val)

    prefix = "".join(recovered)
    print(f"prefix recovered: {prefix}", file=sys.stderr, flush=True)
    return prefix, state, sigma, round_keys, trace, parity


def simulate_stage_part(
    consts: dict[str, object],
    stage_idx: int,
    part: str,
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    trace: list[int],
    parity: int,
    processed_len: int,
) -> tuple[list[int], list[int], list[int], list[int], int]:
    state = state[:]
    sigma = sigma[:]
    round_keys = round_keys[:]
    trace = trace[:]

    for depth, ch in enumerate(part.encode("ascii")):
        pos = processed_len + depth
        state, sigma, round_keys, trace_val = forward_char(state, sigma, round_keys, trace, pos, ch, consts)
        trace[pos] = trace_val
        parity = u32(parity ^ trace_val)

    return state, sigma, round_keys, trace, parity


def brute_stage(
    consts: dict[str, object],
    stage_idx: int,
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    trace: list[int],
    parity: int,
    processed_len: int,
) -> tuple[str, list[int], list[int], list[int], list[int], int, int, int]:
    stage_lengths = consts["stage_lengths"]
    stage_charsets = consts["stage_charsets"]
    stage_burn_rounds = consts["stage_burn_rounds"]
    stage_gates = consts["stage_gates"]
    stage_count = consts["stage_count"]

    stage_len = stage_lengths[stage_idx]
    stage_charset = stage_charsets[stage_idx]
    burn_rounds = stage_burn_rounds[stage_idx]
    target_gate = stage_gates[stage_idx]
    search_space = len(stage_charset) ** stage_len
    attempt_counter = 0
    candidate = [""] * stage_len
    charset_bytes = stage_charset.encode("ascii")
    end_len = processed_len + stage_len

    print(
        f"stage {stage_idx + 1}/{stage_count}: len={stage_len} charset={len(stage_charset)} search_space={search_space}",
        file=sys.stderr,
        flush=True,
    )

    def dfs(
        depth: int,
        cur_state: list[int],
        cur_sigma: list[int],
        cur_round_keys: list[int],
        cur_parity: int,
    ) -> tuple[str, list[int], list[int], list[int], list[int], int, int] | None:
        nonlocal attempt_counter

        if depth == stage_len:
            attempt_counter += 1
            digest = stage_digest(
                cur_state,
                cur_sigma,
                cur_round_keys,
                trace,
                end_len,
                cur_parity,
                stage_idx,
                burn_rounds,
                consts,
            )
            if digest == target_gate:
                return "".join(candidate), cur_state, cur_sigma, cur_round_keys, trace[:], cur_parity, attempt_counter
            return None

        pos = processed_len + depth
        saved_trace = trace[pos]
        for ch in charset_bytes:
            next_state, next_sigma, next_keys, trace_val = forward_char(
                cur_state,
                cur_sigma,
                cur_round_keys,
                trace,
                pos,
                ch,
                consts,
            )
            trace[pos] = trace_val
            candidate[depth] = chr(ch)
            found = dfs(depth + 1, next_state, next_sigma, next_keys, u32(cur_parity ^ trace_val))
            if found is not None:
                return found
        trace[pos] = saved_trace
        return None

    solved = dfs(0, state, sigma, round_keys, parity)
    if solved is None:
        raise RuntimeError(f"stage {stage_idx + 1}: brute-force failed")

    part, next_state, next_sigma, next_round_keys, next_trace, next_parity, attempts = solved
    return part, next_state, next_sigma, next_round_keys, next_trace, next_parity, attempts, search_space


def recover_flag(consts: dict[str, object], image: bytes, charset: str) -> str:
    prefix, state, sigma, round_keys, trace, parity = recover_prefix(consts, image, charset)
    partial = prefix
    processed_len = len(prefix)

    for stage_idx in range(consts["stage_count"]):
        part, state, sigma, round_keys, trace, parity, attempts, search_space = brute_stage(
            consts,
            stage_idx,
            state,
            sigma,
            round_keys,
            trace,
            parity,
            processed_len,
        )
        partial += part
        processed_len += len(part)
        print(
            f"stage {stage_idx + 1} solved after {attempts}/{search_space} attempts: {part}",
            file=sys.stderr,
            flush=True,
        )
        print(f"partial flag: {partial}", file=sys.stderr, flush=True)

    return partial


def verify_flag(candidate: str, consts: dict[str, object], image: bytes) -> bool:
    final_seal = consts["final_seal"]
    trace_gates = consts["trace_gates"]
    trace_prefix_len = consts["trace_prefix_len"]
    flag_len = consts["flag_len"]
    stage_lengths = consts["stage_lengths"]
    stage_burn_rounds = consts["stage_burn_rounds"]
    stage_gates = consts["stage_gates"]
    stage_count = consts["stage_count"]
    spice = consts["spice"]
    pad = consts["pad"]
    sbox = consts["sbox"]
    lane_schedule = consts["lane_schedule"]
    rot_schedule = consts["rot_schedule"]
    boot_ops = consts["boot_ops"]

    if len(candidate) != flag_len:
        return False
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in candidate):
        return False

    flag = candidate.encode("ascii")
    state, sigma, round_keys = seed_context(consts, image)
    trace = [0] * flag_len
    parity = 0
    stage_idx = 0
    stage_cursor = trace_prefix_len + stage_lengths[0]

    for pos, ch in enumerate(flag):
        state, sigma, round_keys, trace[pos] = forward_char(state, sigma, round_keys, trace, pos, ch, consts)
        if pos < trace_prefix_len and trace[pos] != trace_gates[pos]:
            return False
        parity = u32(parity ^ trace[pos])

        if stage_idx < stage_count and pos + 1 == stage_cursor:
            digest = stage_digest(
                state,
                sigma,
                round_keys,
                trace,
                pos + 1,
                parity,
                stage_idx,
                stage_burn_rounds[stage_idx],
                consts,
            )
            if digest != stage_gates[stage_idx]:
                return False
            stage_idx += 1
            if stage_idx < stage_count:
                stage_cursor += stage_lengths[stage_idx]

    if stage_idx != stage_count:
        return False

    rev_state = [
        u32(state[idx] ^ round_keys[(idx * 13 + (parity & 0x7F)) & 0x7F] ^ spice[(parity + idx * 29) & 0xFF])
        for idx in range(8)
    ]

    for rev in range(flag_len):
        pos = flag_len - 1 - rev
        ch = flag[pos]
        witness = trace[(pos ^ sigma[(rev + ch) & 0xFF]) % flag_len]
        local = rev_state[:]

        for step in range(BACKWARD_STEPS):
            pc = rev * BACKWARD_STEPS + step
            tap = sigma[(pc + pos + step + (witness & 0xFF)) & 0xFF]
            idx = (
                witness
                + tap
                + ((local[(step + 3) & 7] >> ((pos + step) & 7)) & 0xFF)
                + sbox[(ch + step + rev) & 0xFF]
            ) & 0xFF
            lane = lane_schedule[idx] & 7
            op = boot_ops[(idx ^ round_keys[(pc + (witness & 0x7F)) & 0x7F] ^ sigma[(idx + (witness & 0xFF)) & 0xFF]) & 0x7F]
            rot = rot_schedule[(idx + lane + sigma[(pc + rev) & 0xFF]) & 0x7F]
            sp = u32(
                spice[(idx + sigma[(lane + ch + rev) & 0xFF]) & 0xFF]
                ^ round_keys[(idx + rev + pos) & 0x7F]
                ^ pad[(pc + witness) & 0x3F]
            )
            arg = u32(witness ^ (ch << 16) ^ (step << 8) ^ local[(lane + 2) & 7])
            vm_step(local, sigma, round_keys, lane, op, rot, sp, arg, idx, pc ^ witness ^ pos, sbox)
            trace_idx = (pos + lane + sigma[(step + pos) & 0xFF]) % flag_len
            trace[trace_idx] = u32(trace[trace_idx] ^ rol32(local[lane] ^ sp ^ arg, ((rot + step) % 31) + 1))
            round_keys[(idx + trace_idx + op) & 0x7F] = u32(round_keys[(idx + trace_idx + op) & 0x7F] + trace[trace_idx] + local[(lane + 4) & 7])

        rev_state[0] = u32(local[0] ^ ror32(local[6], 3) ^ trace[(pos + 1) % flag_len])
        rev_state[1] = u32(local[1] + rol32(local[7], 5) + trace[pos % flag_len])
        rev_state[2] = u32(ror32(local[2] ^ rev_state[0] ^ round_keys[(pos * 9 + 2) & 0x7F], 7))
        rev_state[3] = u32(local[3] ^ rev_state[1] ^ sub_word(trace[(pos + 5) % flag_len], sbox))
        rev_state[4] = u32(local[4] + ror32(rev_state[2] ^ spice[(pos * 5 + 9) & 0xFF], 11))
        rev_state[5] = u32(local[5] ^ rol32(rev_state[3] + pad[(pos * 3 + 1) & 0x3F], 13))
        rev_state[6] = u32(local[6] + sub_word(rev_state[4] ^ round_keys[(pos * 11 + 6) & 0x7F], sbox))
        rev_state[7] = u32(local[7] ^ ror32(rev_state[5] + trace[(pos + 11) % flag_len], 17))

    computed = []
    for idx in range(8):
        word = u32(rev_state[idx] ^ rol32(rev_state[(idx + 3) & 7], ((idx * 5) + 3) % 31 + 1))
        word ^= trace[(idx * 7 + sigma[(idx * 19) & 0xFF]) % flag_len]
        word = u32(word + round_keys[(idx * 11 + word) & 0x7F] + spice[(sigma[(idx * 23 + 5) & 0xFF] + idx) & 0xFF])
        word ^= sub_word(trace[(idx * 5 + 3) % flag_len] ^ round_keys[(idx * 13 + 9) & 0x7F], sbox)
        computed.append(u32(word))

    return computed == final_seal


def default_charset() -> str:
    return "".join(chr(value) for value in range(0x20, 0x7F))


def rank_in_charset(part: str, charset: str) -> int:
    base = len(charset)
    index = {ch: idx for idx, ch in enumerate(charset)}
    rank = 0
    for ch in part:
        rank = rank * base + index[ch]
    return rank + 1


def split_author_parts(flag: str, consts: dict[str, object]) -> list[str]:
    trace_prefix_len = consts["trace_prefix_len"]
    stage_lengths = consts["stage_lengths"]
    cursor = trace_prefix_len
    parts: list[str] = []
    for stage_len in stage_lengths:
        parts.append(flag[cursor:cursor + stage_len])
        cursor += stage_len
    return parts


def estimate_runtime(consts: dict[str, object], image: bytes, charset: str) -> int:
    author_flag_path = Path("author/flag.txt")
    author_flag = author_flag_path.read_text().strip() if author_flag_path.exists() else None

    prefix, state, sigma, round_keys, trace, parity = recover_prefix(consts, image, charset)
    if author_flag is not None and not author_flag.startswith(prefix):
        print("author/flag.txt does not match recovered prefix", file=sys.stderr)
        return 1

    actual_parts = split_author_parts(author_flag, consts) if author_flag is not None else None
    total_avg = 0.0
    total_worst = 0.0
    total_expected = 0.0
    processed_len = len(prefix)

    for stage_idx in range(consts["stage_count"]):
        stage_charset = consts["stage_charsets"][stage_idx]
        stage_len = consts["stage_lengths"][stage_idx]
        search_space = len(stage_charset) ** stage_len
        probe_part = actual_parts[stage_idx] if actual_parts is not None else stage_charset[0] * stage_len

        start = perf_counter()
        for _ in range(2):
            probe_state, probe_sigma, probe_keys, probe_trace, probe_parity = simulate_stage_part(
                consts,
                stage_idx,
                probe_part,
                state,
                sigma,
                round_keys,
                trace,
                parity,
                processed_len,
            )
            stage_digest(
                probe_state,
                probe_sigma,
                probe_keys,
                probe_trace,
                processed_len + len(probe_part),
                probe_parity,
                stage_idx,
                consts["stage_burn_rounds"][stage_idx],
                consts,
            )
        per_candidate = (perf_counter() - start) / 2.0

        avg_seconds = per_candidate * search_space / 2.0
        worst_seconds = per_candidate * search_space
        total_avg += avg_seconds
        total_worst += worst_seconds

        print(f"stage_{stage_idx + 1}_per_candidate={per_candidate:.6f}s")
        print(f"stage_{stage_idx + 1}_search_space={search_space}")
        print(f"stage_{stage_idx + 1}_avg_seconds={avg_seconds:.2f}")
        print(f"stage_{stage_idx + 1}_worst_seconds={worst_seconds:.2f}")

        if actual_parts is not None:
            target_rank = rank_in_charset(actual_parts[stage_idx], stage_charset)
            target_seconds = per_candidate * target_rank
            total_expected += target_seconds
            print(f"stage_{stage_idx + 1}_target_rank={target_rank}")
            print(f"stage_{stage_idx + 1}_target_seconds={target_seconds:.2f}")

            state, sigma, round_keys, trace, parity = simulate_stage_part(
                consts,
                stage_idx,
                actual_parts[stage_idx],
                state,
                sigma,
                round_keys,
                trace,
                parity,
                processed_len,
            )
        else:
            state, sigma, round_keys, trace, parity = simulate_stage_part(
                consts,
                stage_idx,
                probe_part,
                state,
                sigma,
                round_keys,
                trace,
                parity,
                processed_len,
            )

        processed_len += stage_len

    print(f"total_avg_seconds={total_avg:.2f}")
    print(f"total_worst_seconds={total_worst:.2f}")
    if actual_parts is not None:
        print(f"total_target_seconds={total_expected:.2f}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Binary-driven staged solver for the 0-day challenge.")
    parser.add_argument("binary", nargs="?", default="dist/0day", help="challenge ELF path")
    parser.add_argument("image", nargs="?", default="dist/void.ns0", help="NULL-0 image path")
    parser.add_argument("--charset", default=default_charset(), help="candidate charset for prefix recovery")
    parser.add_argument("--dump-fingerprint", action="store_true", help="print the extracted blob fingerprint and exit")
    parser.add_argument("--estimate-only", action="store_true", help="estimate staged brute runtime and exit")
    args = parser.parse_args()

    binary_path = Path(args.binary)
    image_path = Path(args.image)
    consts = extract_constants(binary_path)

    if args.dump_fingerprint:
        print(consts["fingerprint"])
        return 0

    image = image_path.read_bytes()
    if len(image) != IMAGE_SIZE or any(image):
        print("invalid image: expected 4096 zero bytes", file=sys.stderr)
        return 1

    if args.estimate_only:
        return estimate_runtime(consts, image, args.charset)

    flag = recover_flag(consts, image, args.charset)
    if not verify_flag(flag, consts, image):
        print("recovered flag did not verify against the binary", file=sys.stderr)
        return 1

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
