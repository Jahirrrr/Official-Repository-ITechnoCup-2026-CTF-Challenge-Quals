#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

FLAG = "ITECHNO26{z3r0_vm_still_h4rd_t0_s0lv3}"
FLAG_LEN = 38
IMAGE_SIZE = 4096
FORWARD_STEPS = 96
BACKWARD_STEPS = 48
SCHEDULE_LEN = 128
SPICE_LEN = 256
PAD_LEN = 64
BUILD_SEED = 0xC0FFEE1234ABCDEF
CHALLENGE_MAGIC = b"N0TRACE1"
TRACE_PREFIX_LEN = 18
STAGE_PARTS = [b"still_", b"h4rd_", b"t0_s0", b"lv3}"]
STAGE_CHARSETS = [
    b"xitls_",
    b"0x_tdrh4",
    b"xv_ls0t4",
    b"0123456l}v",
]
STAGE_BURN_ROUNDS = [10240, 10240, 10240, 10240]
STAGE_GATE_WORDS = 4
STAGE_COUNT = len(STAGE_PARTS)
MAX_STAGE_CHARSET_LEN = max(len(item) for item in STAGE_CHARSETS)
INIT_STATE = (
    0x13579BDF,
    0x2468ACE0,
    0xC0DEC0DE,
    0x5A17F00D,
    0x1BADB002,
    0x0D15EA5E,
    0x31415926,
    0xFEEDFACE,
)


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


class SplitMix64:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.state
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF

    def next32(self) -> int:
        return self.next64() & 0xFFFFFFFF


def sub_word(word: int, sbox: list[int]) -> int:
    word = u32(word)
    return (
        sbox[word & 0xFF]
        | (sbox[(word >> 8) & 0xFF] << 8)
        | (sbox[(word >> 16) & 0xFF] << 16)
        | (sbox[(word >> 24) & 0xFF] << 24)
    )


def build_tables() -> tuple[list[int], list[int], list[int], list[int], list[int], list[int], list[int]]:
    rng = SplitMix64(BUILD_SEED)
    boot_ops: list[int] = []
    exec_ops: list[int] = []
    rot_schedule: list[int] = []
    lane_schedule: list[int] = []
    spice: list[int] = []
    pad: list[int] = []
    sbox = list(range(256))

    for idx in range(SCHEDULE_LEN):
        word = rng.next32()
        boot_ops.append(((word >> 27) ^ idx ^ (word >> 3)) % 10)
        exec_ops.append(((word >> 11) ^ idx ^ (word >> 19)) % 10)
        rot_schedule.append((word % 31) + 1)

    for idx in range(SPICE_LEN):
        word = rng.next32()
        lane_schedule.append(((word >> 9) ^ idx ^ word) & 7)
        spice_word = word ^ rol32(u32(0x9E3779B9 * (idx + 1)), idx % 17) ^ (rng.next32() | 1)
        spice.append(u32(spice_word))

    for idx in range(PAD_LEN):
        pad.append(u32(rng.next32() ^ rol32(rng.next32(), idx % 19)))

    for idx in range(255, 0, -1):
        swap_idx = rng.next64() % (idx + 1)
        sbox[idx], sbox[swap_idx] = sbox[swap_idx], sbox[idx]

    return boot_ops, exec_ops, rot_schedule, lane_schedule, spice, pad, sbox


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


def bootstrap_vm(
    boot_ops: list[int],
    rot_schedule: list[int],
    lane_schedule: list[int],
    spice: list[int],
    pad: list[int],
    sbox: list[int],
) -> tuple[list[int], list[int], list[int]]:
    state = list(INIT_STATE)
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


def stage_digest(
    state: list[int],
    sigma: list[int],
    round_keys: list[int],
    trace: list[int],
    processed_len: int,
    parity: int,
    stage_idx: int,
    burn_rounds: int,
    spice: list[int],
    pad: list[int],
    sbox: list[int],
) -> list[int]:
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


def evaluate_flag(
    flag: bytes,
    boot_ops: list[int],
    exec_ops: list[int],
    rot_schedule: list[int],
    lane_schedule: list[int],
    spice: list[int],
    pad: list[int],
    sbox: list[int],
) -> tuple[list[int], list[list[int]], list[int]]:
    boot_state, sigma, round_keys = bootstrap_vm(
        boot_ops,
        rot_schedule,
        lane_schedule,
        spice,
        pad,
        sbox,
    )
    state = [
        u32(boot_state[idx] ^ spice[(idx * 29 + sigma[idx]) & 0xFF] ^ round_keys[(idx * 13 + idx) & 0x7F])
        for idx in range(8)
    ]
    trace = [0] * FLAG_LEN
    parity = 0
    stage_gates: list[list[int]] = []
    stage_cursor = TRACE_PREFIX_LEN + len(STAGE_PARTS[0])
    stage_idx = 0

    for pos, ch in enumerate(flag):
        local = state[:]
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
        state = [0] * 8
        state[0] = u32(local[0] ^ rol32(local[5], 3) ^ round_keys[(pos * 9 + sigma[pos]) & 0x7F])
        state[1] = u32(local[1] + ror32(local[6], 5) + spice[(pos * 11 + 1 + sigma[(pos + 13) & 0xFF]) & 0xFF])
        state[2] = u32(rol32(local[2] ^ state[0] ^ sub_word(ch * 0x045D9F3B, sbox), (pos % 13) + 5))
        state[3] = u32(local[3] ^ state[1] ^ ror32(local[7] + 0xA5A5A5A5 + pos + sigma[(pos + 31) & 0xFF], 7))
        state[4] = u32(local[4] + sub_word(state[2] ^ round_keys[(pos * 5 + 4) & 0x7F], sbox))
        state[5] = u32(rol32(local[5] ^ state[3] ^ spice[(pos * 3 + 17) & 0xFF], 11))
        state[6] = u32(local[6] ^ ror32(state[4] + prev_trace, 9))
        state[7] = u32(local[7] + rol32(state[5] ^ local[0] ^ round_keys[(pos * 7 + 7) & 0x7F], 13))

        trace[pos] = compress_trace(state, sigma, round_keys, spice, pad, sbox, pos, ch)
        parity = u32(parity ^ trace[pos])

        pivot = (trace[pos] ^ sigma[(ch + pos) & 0xFF]) & 0xFF
        buddy = (pivot + sbox[(trace[pos] >> 8) & 0xFF] + pos) & 0xFF
        sigma[pivot], sigma[buddy] = sigma[buddy], sigma[pivot]
        round_keys[(pos + pivot) & 0x7F] = u32(
            round_keys[(pos + pivot) & 0x7F] ^ rol32(trace[pos], (pos % 31) + 1)
        )
        round_keys[(buddy + pos * 3) & 0x7F] = u32(
            round_keys[(buddy + pos * 3) & 0x7F] + trace[pos] + sigma[pivot]
        )

        if stage_idx < STAGE_COUNT and pos + 1 == stage_cursor:
            stage_gates.append(
                stage_digest(
                    state,
                    sigma,
                    round_keys,
                    trace,
                    pos + 1,
                    parity,
                    stage_idx,
                    STAGE_BURN_ROUNDS[stage_idx],
                    spice,
                    pad,
                    sbox,
                )
            )
            stage_idx += 1
            if stage_idx < STAGE_COUNT:
                stage_cursor += len(STAGE_PARTS[stage_idx])

    rev_state = [
        u32(state[idx] ^ round_keys[(idx * 13 + (parity & 0x7F)) & 0x7F] ^ spice[(parity + idx * 29) & 0xFF])
        for idx in range(8)
    ]
    forward_gates = trace[:]

    for rev in range(FLAG_LEN):
        pos = FLAG_LEN - 1 - rev
        ch = flag[pos]
        witness = trace[(pos ^ sigma[(rev + ch) & 0xFF]) % FLAG_LEN]
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
            op = boot_ops[
                (idx ^ round_keys[(pc + (witness & 0x7F)) & 0x7F] ^ sigma[(idx + (witness & 0xFF)) & 0xFF]) & 0x7F
            ]
            rot = rot_schedule[(idx + lane + sigma[(pc + rev) & 0xFF]) & 0x7F]
            sp = u32(
                spice[(idx + sigma[(lane + ch + rev) & 0xFF]) & 0xFF]
                ^ round_keys[(idx + rev + pos) & 0x7F]
                ^ pad[(pc + witness) & 0x3F]
            )
            arg = u32(witness ^ (ch << 16) ^ (step << 8) ^ local[(lane + 2) & 7])
            vm_step(local, sigma, round_keys, lane, op, rot, sp, arg, idx, pc ^ witness ^ pos, sbox)
            trace_idx = (pos + lane + sigma[(step + pos) & 0xFF]) % FLAG_LEN
            trace[trace_idx] = u32(
                trace[trace_idx] ^ rol32(local[lane] ^ sp ^ arg, ((rot + step) % 31) + 1)
            )
            round_keys[(idx + trace_idx + op) & 0x7F] = u32(
                round_keys[(idx + trace_idx + op) & 0x7F] + trace[trace_idx] + local[(lane + 4) & 7]
            )

        rev_state[0] = u32(local[0] ^ ror32(local[6], 3) ^ trace[(pos + 1) % FLAG_LEN])
        rev_state[1] = u32(local[1] + rol32(local[7], 5) + trace[pos % FLAG_LEN])
        rev_state[2] = u32(ror32(local[2] ^ rev_state[0] ^ round_keys[(pos * 9 + 2) & 0x7F], 7))
        rev_state[3] = u32(local[3] ^ rev_state[1] ^ sub_word(trace[(pos + 5) % FLAG_LEN], sbox))
        rev_state[4] = u32(local[4] + ror32(rev_state[2] ^ spice[(pos * 5 + 9) & 0xFF], 11))
        rev_state[5] = u32(local[5] ^ rol32(rev_state[3] + pad[(pos * 3 + 1) & 0x3F], 13))
        rev_state[6] = u32(local[6] + sub_word(rev_state[4] ^ round_keys[(pos * 11 + 6) & 0x7F], sbox))
        rev_state[7] = u32(local[7] ^ ror32(rev_state[5] + trace[(pos + 11) % FLAG_LEN], 17))

    seal: list[int] = []
    for idx in range(8):
        word = u32(rev_state[idx] ^ rol32(rev_state[(idx + 3) & 7], ((idx * 5) + 3) % 31 + 1))
        word ^= trace[(idx * 7 + sigma[(idx * 19) & 0xFF]) % FLAG_LEN]
        word = u32(
            word
            + round_keys[(idx * 11 + word) & 0x7F]
            + spice[(sigma[(idx * 23 + 5) & 0xFF] + idx) & 0xFF]
        )
        word ^= sub_word(trace[(idx * 5 + 3) % FLAG_LEN] ^ round_keys[(idx * 13 + 9) & 0x7F], sbox)
        seal.append(u32(word))

    return forward_gates, stage_gates, seal


def fmt_u8_array(values: list[int]) -> str:
    rows = []
    for idx in range(0, len(values), 8):
        chunk = ", ".join(f"{value}u" for value in values[idx:idx + 8])
        rows.append(f"        {chunk},")
    return "{\n" + "\n".join(rows) + "\n    }"


def fmt_u32_array(values: list[int]) -> str:
    rows = []
    for idx in range(0, len(values), 4):
        chunk = ", ".join(f"0x{value:08X}u" for value in values[idx:idx + 4])
        rows.append(f"        {chunk},")
    return "{\n" + "\n".join(rows) + "\n    }"


def fmt_u8_matrix(rows_in: list[list[int]]) -> str:
    rows = []
    for row in rows_in:
        chunk = ", ".join(f"{value}u" for value in row)
        rows.append(f"        {{{chunk}}},")
    return "{\n" + "\n".join(rows) + "\n    }"


def fmt_u32_matrix(rows_in: list[list[int]]) -> str:
    rows = []
    for row in rows_in:
        chunk = ", ".join(f"0x{value:08X}u" for value in row)
        rows.append(f"        {{{chunk}}},")
    return "{\n" + "\n".join(rows) + "\n    }"


def main() -> None:
    flag_bytes = FLAG.encode("ascii")

    if len(FLAG) != FLAG_LEN:
        raise SystemExit(f"FLAG must be {FLAG_LEN} bytes, got {len(FLAG)}")
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in FLAG):
        raise SystemExit("FLAG must stay printable ASCII")
    if not FLAG.endswith("}"):
        raise SystemExit("FLAG must end with '}'")
    if TRACE_PREFIX_LEN <= 0 or TRACE_PREFIX_LEN >= FLAG_LEN:
        raise SystemExit("TRACE_PREFIX_LEN must hide at least one staged segment")
    if STAGE_COUNT == 0:
        raise SystemExit("need at least one brute stage")
    if not (len(STAGE_PARTS) == len(STAGE_CHARSETS) == len(STAGE_BURN_ROUNDS)):
        raise SystemExit("stage metadata length mismatch")
    if sum(len(part) for part in STAGE_PARTS) + TRACE_PREFIX_LEN != FLAG_LEN:
        raise SystemExit("staged parts do not cover the flag tail")
    if flag_bytes[TRACE_PREFIX_LEN:] != b"".join(STAGE_PARTS):
        raise SystemExit("stage parts do not match the hidden flag tail")

    for idx, (part, charset, burn_rounds) in enumerate(zip(STAGE_PARTS, STAGE_CHARSETS, STAGE_BURN_ROUNDS)):
        if not part:
            raise SystemExit(f"stage {idx} is empty")
        if burn_rounds <= 0:
            raise SystemExit(f"stage {idx} burn rounds must be positive")
        if any(ch not in charset for ch in part):
            raise SystemExit(f"stage {idx} part contains chars outside its charset")

    boot_ops, exec_ops, rot_schedule, lane_schedule, spice, pad, sbox = build_tables()
    trace_gates, stage_gates, final_seal = evaluate_flag(
        flag_bytes,
        boot_ops,
        exec_ops,
        rot_schedule,
        lane_schedule,
        spice,
        pad,
        sbox,
    )

    root = Path(__file__).resolve().parents[1]
    header_path = root / "src" / "generated.h"
    author_flag_path = root / "author" / "flag.txt"

    padded_charsets = [
        list(charset) + [0] * (MAX_STAGE_CHARSET_LEN - len(charset))
        for charset in STAGE_CHARSETS
    ]

    header = [
        "/* Auto-generated by tools/gen_header.py */",
        "#ifndef GENERATED_H",
        "#define GENERATED_H",
        "",
        "#include <stdint.h>",
        "",
        f"#define FLAG_LEN {FLAG_LEN}u",
        f"#define IMAGE_SIZE {IMAGE_SIZE}u",
        f"#define FORWARD_STEPS {FORWARD_STEPS}u",
        f"#define BACKWARD_STEPS {BACKWARD_STEPS}u",
        f"#define SPICE_LEN {SPICE_LEN}u",
        f"#define PAD_LEN {PAD_LEN}u",
        f"#define SCHEDULE_LEN {SCHEDULE_LEN}u",
        f"#define TRACE_PREFIX_LEN {TRACE_PREFIX_LEN}u",
        f"#define STAGE_COUNT {STAGE_COUNT}u",
        f"#define STAGE_GATE_WORDS {STAGE_GATE_WORDS}u",
        f"#define MAX_STAGE_CHARSET_LEN {MAX_STAGE_CHARSET_LEN}u",
        "",
        "typedef struct {",
        "    uint8_t magic[8];",
        "    uint32_t flag_len;",
        "    uint32_t trace_prefix_len;",
        "    uint32_t stage_count;",
        "    uint32_t stage_gate_words;",
        "    uint32_t max_stage_charset_len;",
        "    uint8_t stage_lengths[STAGE_COUNT];",
        "    uint8_t stage_charset_lens[STAGE_COUNT];",
        "    uint32_t stage_burn_rounds[STAGE_COUNT];",
        "    uint8_t stage_charsets[STAGE_COUNT][MAX_STAGE_CHARSET_LEN];",
        "    uint32_t stage_gates[STAGE_COUNT][STAGE_GATE_WORDS];",
        "    uint32_t final_seal[8];",
        "    uint32_t trace_gates[TRACE_PREFIX_LEN];",
        "    uint32_t spice[SPICE_LEN];",
        "    uint32_t pad[PAD_LEN];",
        "    uint8_t sbox[256];",
        "    uint8_t lane_schedule[256];",
        "    uint8_t rot_schedule[SCHEDULE_LEN];",
        "    uint8_t exec_ops[SCHEDULE_LEN];",
        "    uint8_t boot_ops[SCHEDULE_LEN];",
        "    uint32_t init_state[8];",
        "} challenge_blob_t;",
        "",
        "static const challenge_blob_t CHALLENGE_BLOB = {",
        f"    .magic = {fmt_u8_array(list(CHALLENGE_MAGIC))},",
        f"    .flag_len = {FLAG_LEN}u,",
        f"    .trace_prefix_len = {TRACE_PREFIX_LEN}u,",
        f"    .stage_count = {STAGE_COUNT}u,",
        f"    .stage_gate_words = {STAGE_GATE_WORDS}u,",
        f"    .max_stage_charset_len = {MAX_STAGE_CHARSET_LEN}u,",
        f"    .stage_lengths = {fmt_u8_array([len(part) for part in STAGE_PARTS])},",
        f"    .stage_charset_lens = {fmt_u8_array([len(charset) for charset in STAGE_CHARSETS])},",
        f"    .stage_burn_rounds = {fmt_u32_array(STAGE_BURN_ROUNDS)},",
        f"    .stage_charsets = {fmt_u8_matrix(padded_charsets)},",
        f"    .stage_gates = {fmt_u32_matrix(stage_gates)},",
        f"    .final_seal = {fmt_u32_array(final_seal)},",
        f"    .trace_gates = {fmt_u32_array(trace_gates[:TRACE_PREFIX_LEN])},",
        f"    .spice = {fmt_u32_array(spice)},",
        f"    .pad = {fmt_u32_array(pad)},",
        f"    .sbox = {fmt_u8_array(sbox)},",
        f"    .lane_schedule = {fmt_u8_array(lane_schedule)},",
        f"    .rot_schedule = {fmt_u8_array(rot_schedule)},",
        f"    .exec_ops = {fmt_u8_array(exec_ops)},",
        f"    .boot_ops = {fmt_u8_array(boot_ops)},",
        f"    .init_state = {fmt_u32_array(list(INIT_STATE))},",
        "};",
        "",
        "#define TRACE_PREFIX_COUNT (CHALLENGE_BLOB.trace_prefix_len)",
        "#define STAGE_COUNT_META (CHALLENGE_BLOB.stage_count)",
        "#define STAGE_GATE_WORDS_META (CHALLENGE_BLOB.stage_gate_words)",
        "#define MAX_STAGE_CHARSET_LEN_META (CHALLENGE_BLOB.max_stage_charset_len)",
        "#define STAGE_LENGTHS (CHALLENGE_BLOB.stage_lengths)",
        "#define STAGE_CHARSET_LENS (CHALLENGE_BLOB.stage_charset_lens)",
        "#define STAGE_BURN_ROUNDS (CHALLENGE_BLOB.stage_burn_rounds)",
        "#define STAGE_CHARSETS (CHALLENGE_BLOB.stage_charsets)",
        "#define STAGE_GATES (CHALLENGE_BLOB.stage_gates)",
        "#define FINAL_SEAL (CHALLENGE_BLOB.final_seal)",
        "#define TRACE_GATES (CHALLENGE_BLOB.trace_gates)",
        "#define SPICE (CHALLENGE_BLOB.spice)",
        "#define PAD (CHALLENGE_BLOB.pad)",
        "#define SBOX (CHALLENGE_BLOB.sbox)",
        "#define LANE_SCHEDULE (CHALLENGE_BLOB.lane_schedule)",
        "#define ROT_SCHEDULE (CHALLENGE_BLOB.rot_schedule)",
        "#define EXEC_OPS (CHALLENGE_BLOB.exec_ops)",
        "#define BOOT_OPS (CHALLENGE_BLOB.boot_ops)",
        "#define INIT_STATE (CHALLENGE_BLOB.init_state)",
        "",
        "#endif",
    ]

    header_path.write_text("\n".join(header) + "\n", encoding="ascii")
    author_flag_path.write_text(FLAG + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
