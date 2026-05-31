#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "generated.h"

typedef struct {
    uint32_t v[8];
    uint8_t sigma[256];
    uint32_t round_keys[128];
} vm_ctx_t;

#ifdef DEBUG_SEAL
static void dump_words(const char *label, const uint32_t *words, size_t count) {
    fprintf(stderr, "%s", label);
    for (size_t i = 0; i < count; ++i) {
        fprintf(stderr, " %08x", words[i]);
    }
    fputc('\n', stderr);
}

static void dump_bytes(const char *label, const uint8_t *bytes, size_t count) {
    fprintf(stderr, "%s", label);
    for (size_t i = 0; i < count; ++i) {
        fprintf(stderr, " %02x", bytes[i]);
    }
    fputc('\n', stderr);
}
#endif

static uint32_t rol32(uint32_t value, unsigned shift) {
    shift &= 31u;
    return (value << shift) | (value >> ((32u - shift) & 31u));
}

static uint32_t ror32(uint32_t value, unsigned shift) {
    shift &= 31u;
    return (value >> shift) | (value << ((32u - shift) & 31u));
}

static uint32_t sub_word(uint32_t word) {
    return (uint32_t)SBOX[word & 0xFFu]
         | ((uint32_t)SBOX[(word >> 8) & 0xFFu] << 8)
         | ((uint32_t)SBOX[(word >> 16) & 0xFFu] << 16)
         | ((uint32_t)SBOX[(word >> 24) & 0xFFu] << 24);
}

static bool load_image(const char *path, uint8_t *image) {
    FILE *fp = fopen(path, "rb");
    size_t offset = 0;

    if (fp == NULL) {
        return false;
    }

    while (offset < IMAGE_SIZE) {
        size_t got = fread(image + offset, 1, IMAGE_SIZE - offset, fp);
        if (got == 0) {
            break;
        }
        offset += got;
    }

    {
        int extra = fgetc(fp);
        fclose(fp);
        if (offset != IMAGE_SIZE || extra != EOF) {
            return false;
        }
    }

    for (size_t idx = 0; idx < IMAGE_SIZE; ++idx) {
        if (image[idx] != 0u) {
            return false;
        }
    }

    return true;
}

static void vm_step(
    uint32_t local[8],
    uint8_t sigma[256],
    uint32_t round_keys[128],
    uint32_t lane,
    uint32_t op,
    uint32_t rot,
    uint32_t sp,
    uint32_t arg,
    uint32_t idx,
    uint32_t tweak
) {
    static void *dispatch[10] = {
        &&op0, &&op1, &&op2, &&op3, &&op4, &&op5, &&op6, &&op7, &&op8, &&op9,
    };
    uint32_t a = lane & 7u;
    uint32_t b = (lane + 1u) & 7u;
    uint32_t c = (lane + 3u) & 7u;
    uint32_t d = (lane + 5u) & 7u;
    uint32_t tmp;
    uint32_t swap_i;
    uint32_t swap_j;
    uint8_t hold;

    goto *dispatch[op % 10u];
op0:
        local[a] = rol32(local[a] + sp + arg, rot);
        goto epilogue;
op1:
        local[a] ^= rol32(sub_word((arg ^ sp) + local[d]), rot);
        goto epilogue;
op2:
        local[a] += local[b] ^ rol32(local[c], rot);
        goto epilogue;
op3:
        local[a] = rol32(local[a] ^ local[d] ^ sub_word(sp + arg), rot);
        local[b] += local[a] + 0x7F4A7C15u;
        goto epilogue;
op4:
        tmp = local[a];
        local[a] = local[b] ^ ror32(local[c] + sp + arg, rot);
        local[c] += tmp + 0x01020304u;
        goto epilogue;
op5:
        local[a] = (local[a] * (sp | 1u)) + rol32(arg ^ 0x41A7C35Fu, rot);
        goto epilogue;
op6:
        local[a] = rol32(local[a] + sub_word(local[d] ^ sp) + arg, rot);
        local[d] ^= rol32(sp ^ arg, a + 1u);
        goto epilogue;
op7:
        local[a] ^= ror32(local[b], rot) + sp + (sub_word(arg) << (((tweak ^ lane) % 3u) + 1u));
        goto epilogue;
op8:
        local[a] = sub_word(local[a] ^ rol32(local[b] + sp, rot)) + local[c];
        local[d] = ror32(local[d] ^ local[a], (rot % 13u) + 1u);
        goto epilogue;
op9:
        local[a] = ror32(local[a] + local[b] + sp + arg, rot);
        local[b] ^= rol32(sub_word(local[c] ^ arg), ((a + rot) % 31u) + 1u);
        goto epilogue;

epilogue:
        swap_i = (idx + local[a] + arg) & 0xFFu;
        swap_j = (sigma[(idx + rot + (local[b] & 0xFFu)) & 0xFFu] + (local[d] & 0xFFu) + op) & 0xFFu;
        hold = sigma[swap_i];
        sigma[swap_i] = sigma[swap_j];
        sigma[swap_j] = hold;

        round_keys[(idx + op + a) & 0x7Fu] ^= rol32(local[a] ^ sp ^ arg, rot);
        round_keys[(tweak + a + op) & 0x7Fu] += local[d] + sigma[swap_i] + 0x9E3779B9u;
        local[(a + op + 2u) & 7u] ^= rol32(0x9E3779B9u ^ tweak ^ arg, ((a + rot + op) % 31u) + 1u);
}

static void bootstrap_vm(vm_ctx_t *ctx, const uint8_t *image) {
    for (uint32_t i = 0; i < 8u; ++i) {
        ctx->v[i] = INIT_STATE[i];
    }
    for (uint32_t i = 0; i < 256u; ++i) {
        ctx->sigma[i] = (uint8_t)i;
    }
    for (uint32_t i = 0; i < 128u; ++i) {
        ctx->round_keys[i] = (0x9E3779B9u * (i + 1u))
                           ^ SPICE[i]
                           ^ rol32(SPICE[(i + 17u) & 0xFFu], (i % 31u) + 1u);
    }

    for (uint32_t pc = 0; pc < IMAGE_SIZE; ++pc) {
        uint32_t token = image[pc];
        uint32_t idx = (
            pc
            ^ ctx->sigma[(pc + (ctx->v[pc & 7u] & 0xFFu)) & 0xFFu]
            ^ ((ctx->v[(pc + 3u) & 7u] >> ((pc & 3u) * 8u)) & 0xFFu)
            ^ token
        ) & 0xFFu;
        uint32_t lane = LANE_SCHEDULE[idx] & 7u;
        uint32_t op = BOOT_OPS[(idx ^ ctx->sigma[(idx + lane + pc) & 0xFFu] ^ (pc >> 5u)) & 0x7Fu];
        uint32_t rot = ROT_SCHEDULE[(idx + ctx->sigma[pc & 0xFFu] + lane) & 0x7Fu];
        uint32_t sp = SPICE[(idx + ctx->sigma[(pc ^ lane) & 0xFFu]) & 0xFFu] ^ PAD[(pc + lane) & 0x3Fu];
        uint32_t arg = (pc * 0x045D9F3Bu) ^ sp ^ ctx->sigma[(pc + idx) & 0xFFu];
        vm_step(ctx->v, ctx->sigma, ctx->round_keys, lane, op, rot, sp, arg, idx, pc);
#ifdef DEBUG_SEAL
        if (pc < 4u) {
            fprintf(stderr, "boot_pc=%u idx=%u lane=%u op=%u rot=%u sp=%08x arg=%08x\n", pc, idx, lane, op, rot, sp, arg);
            dump_words("boot_v_step:", ctx->v, 8u);
            dump_words("boot_rk_step:", ctx->round_keys, 8u);
            dump_bytes("boot_sigma_step:", ctx->sigma, 16u);
        }
#endif
    }

    {
        uint32_t boot_state[8];
        for (uint32_t i = 0; i < 8u; ++i) {
            boot_state[i] = ctx->v[i]
                          ^ rol32(ctx->v[(i + 3u) & 7u], ((i * 7u + 5u) % 31u) + 1u)
                          ^ ctx->round_keys[(i * 17u + ctx->sigma[i]) & 0x7Fu]
                          ^ SPICE[(ctx->sigma[(i * 13u) & 0xFFu] + i) & 0xFFu];
        }
        memcpy(ctx->v, boot_state, sizeof(boot_state));
    }

#ifdef DEBUG_SEAL
    dump_words("boot_state:", ctx->v, 8u);
    dump_words("boot_rk:", ctx->round_keys, 8u);
    dump_bytes("boot_sigma:", ctx->sigma, 16u);
#endif
}

static uint32_t compress_trace(
    const uint32_t state[8],
    const uint8_t sigma[256],
    const uint32_t round_keys[128],
    uint32_t pos,
    uint8_t ch
) {
    uint32_t x = state[pos & 7u]
               ^ rol32(state[(pos + 3u) & 7u], 5u)
               ^ round_keys[(pos * 13u + sigma[(ch + pos) & 0xFFu]) & 0x7Fu];
    uint32_t y = state[(pos + 5u) & 7u]
               + ror32(state[(pos + 1u) & 7u], 7u)
               + SPICE[(sigma[pos] + ch) & 0xFFu]
               + PAD[pos & 0x3Fu];
    uint32_t z = sub_word(x ^ y ^ ch ^ PAD[(pos * 5u + 3u) & 0x3Fu]);
    return z ^ rol32(x + SPICE[(pos * 7u + ch) & 0xFFu], (y & 15u) + 1u) ^ round_keys[(x ^ y) & 0x7Fu];
}

static void stage_digest(
    const uint32_t state[8],
    const uint8_t sigma[256],
    const uint32_t round_keys[128],
    const uint32_t *trace,
    uint32_t processed_len,
    uint32_t parity,
    uint32_t stage_idx,
    uint32_t out[STAGE_GATE_WORDS]
) {
    uint32_t burn = STAGE_BURN_ROUNDS[stage_idx];

    for (uint32_t i = 0; i < STAGE_GATE_WORDS; ++i) {
        uint32_t anchor = trace[(processed_len - 1u - i) % processed_len];
        uint32_t twist = trace[(sigma[(stage_idx * 29u + i * 17u) & 0xFFu] + i) % processed_len];
        uint32_t key = round_keys[(parity + stage_idx * 11u + i * 19u + anchor) & 0x7Fu];
        out[i] = state[(stage_idx + i * 2u) & 7u]
               ^ rol32(state[(stage_idx + i * 2u + 3u) & 7u], ((stage_idx + i * 5u) % 31u) + 1u)
               ^ key
               ^ SPICE[(twist + sigma[(stage_idx * 31u + i * 7u) & 0xFFu]) & 0xFFu]
               ^ twist;
    }

    for (uint32_t round = 0; round < burn; ++round) {
        uint32_t lane = sigma[(round + stage_idx + (out[0] & 0xFFu)) & 0xFFu] & 7u;
        uint32_t trace_word = trace[(round + sigma[(round + lane + stage_idx) & 0xFFu]) % processed_len];
        uint32_t key = round_keys[(round + stage_idx + (trace_word & 0x7Fu)) & 0x7Fu];
        uint32_t spice_word = SPICE[(sigma[(trace_word + round) & 0xFFu] + lane + stage_idx) & 0xFFu]
                            ^ PAD[(round + stage_idx + lane) & 0x3Fu];
        uint32_t mix = sub_word(trace_word ^ key ^ spice_word ^ parity ^ round);

        out[0] = rol32(out[0] + mix + state[(lane + 1u) & 7u], ((mix >> 27u) & 31u) + 1u);
        out[1] ^= ror32(mix + out[0] + state[(lane + 3u) & 7u], ((lane + round) % 31u) + 1u);
        out[2] = rol32(out[2] ^ out[1] ^ round_keys[(lane * 9u + round) & 0x7Fu], ((stage_idx + lane + 7u) % 31u) + 1u);
        out[3] += sub_word(out[2] ^ spice_word ^ trace[(round + lane + stage_idx * 5u) % processed_len]);
        out[3] = ror32(out[3], ((out[0] ^ out[2]) & 15u) + 1u);
        out[(round + stage_idx) % STAGE_GATE_WORDS] ^= rol32(trace_word ^ parity ^ key, ((round >> 3u) & 31u) + 1u);
    }

    for (uint32_t i = 0; i < STAGE_GATE_WORDS; ++i) {
        out[i] ^= round_keys[(processed_len * 7u + stage_idx * 13u + i * 19u) & 0x7Fu]
               ^ trace[(processed_len + i * 11u) % processed_len];
    }
}

static bool verify_flag(const char *input, const uint8_t *image) {
    size_t len = strlen(input);
    vm_ctx_t ctx;
    uint32_t trace[FLAG_LEN];
    uint32_t parity = 0u;
    uint32_t mismatch = 0u;
    uint32_t rev_state[8];
    uint32_t stage_buf[STAGE_GATE_WORDS];
    uint32_t stage_idx = 0u;
    uint32_t stage_cursor = TRACE_PREFIX_COUNT + STAGE_LENGTHS[0];
#ifdef DEBUG_SEAL
    uint32_t computed_seal[8];
#endif

    if (len != FLAG_LEN) {
        return false;
    }

    bootstrap_vm(&ctx, image);
    for (uint32_t i = 0; i < 8u; ++i) {
        ctx.v[i] ^= SPICE[(i * 29u + ctx.sigma[i]) & 0xFFu] ^ ctx.round_keys[(i * 13u + i) & 0x7Fu];
    }

    for (uint32_t pos = 0; pos < FLAG_LEN; ++pos) {
        unsigned char ch = (unsigned char)input[pos];
        uint32_t local[8];
        uint32_t state[8];

        if (ch < 0x20u || ch > 0x7Eu) {
            return false;
        }

        memcpy(local, ctx.v, sizeof(local));
        for (uint32_t step = 0; step < FORWARD_STEPS; ++step) {
            uint32_t pc = pos * FORWARD_STEPS + step;
            uint32_t tap = ctx.sigma[(ch + step + pos + (local[(step + pos) & 7u] & 0xFFu)) & 0xFFu];
            uint32_t idx = (
                pc
                + tap
                + ((local[(pos + 2u) & 7u] >> ((step & 3u) * 8u)) & 0xFFu)
                + SBOX[(ch + step) & 0xFFu]
            ) & 0xFFu;
            uint32_t lane = LANE_SCHEDULE[idx] & 7u;
            uint32_t op = EXEC_OPS[(idx ^ ctx.round_keys[(pc + lane) & 0x7Fu] ^ ctx.sigma[(idx + pc) & 0xFFu]) & 0x7Fu];
            uint32_t rot = ROT_SCHEDULE[(idx + lane + ctx.sigma[(pc ^ pos) & 0xFFu]) & 0x7Fu];
            uint32_t sp = SPICE[(idx + ctx.sigma[(lane + ch + step) & 0xFFu]) & 0xFFu]
                        ^ ctx.round_keys[(idx + pos) & 0x7Fu]
                        ^ PAD[(pc + lane) & 0x3Fu];
            uint32_t arg = ((uint32_t)ch << 24)
                         ^ (pos << 16)
                         ^ (step << 8)
                         ^ tap
                         ^ local[(lane + 5u) & 7u];
            vm_step(local, ctx.sigma, ctx.round_keys, lane, op, rot, sp, arg, idx, pc ^ (pos << 8) ^ ch);
            local[(lane + op + 3u) & 7u] ^= rol32(
                0x85EBCA6Bu ^ pc ^ ch ^ (pos ? trace[pos - 1u] : ctx.round_keys[0]),
                ((lane + pos + step) % 31u) + 1u
            );
        }

        state[0] = local[0] ^ rol32(local[5], 3u) ^ ctx.round_keys[(pos * 9u + ctx.sigma[pos]) & 0x7Fu];
        state[1] = local[1] + ror32(local[6], 5u) + SPICE[(pos * 11u + 1u + ctx.sigma[(pos + 13u) & 0xFFu]) & 0xFFu];
        state[2] = rol32(local[2] ^ state[0] ^ sub_word((uint32_t)ch * 0x045D9F3Bu), (pos % 13u) + 5u);
        state[3] = local[3] ^ state[1] ^ ror32(local[7] + 0xA5A5A5A5u + pos + ctx.sigma[(pos + 31u) & 0xFFu], 7u);
        state[4] = local[4] + sub_word(state[2] ^ ctx.round_keys[(pos * 5u + 4u) & 0x7Fu]);
        state[5] = rol32(local[5] ^ state[3] ^ SPICE[(pos * 3u + 17u) & 0xFFu], 11u);
        state[6] = local[6] ^ ror32(state[4] + (pos ? trace[pos - 1u] : ctx.round_keys[3]), 9u);
        state[7] = local[7] + rol32(state[5] ^ local[0] ^ ctx.round_keys[(pos * 7u + 7u) & 0x7Fu], 13u);
        memcpy(ctx.v, state, sizeof(state));

        trace[pos] = compress_trace(ctx.v, ctx.sigma, ctx.round_keys, pos, (uint8_t)ch);
        if (pos < TRACE_PREFIX_COUNT) {
            mismatch |= trace[pos] ^ TRACE_GATES[pos];
        }
        parity ^= trace[pos];

        {
            uint32_t pivot = (trace[pos] ^ ctx.sigma[(ch + pos) & 0xFFu]) & 0xFFu;
            uint32_t buddy = (pivot + SBOX[(trace[pos] >> 8) & 0xFFu] + pos) & 0xFFu;
            uint8_t hold = ctx.sigma[pivot];
            ctx.sigma[pivot] = ctx.sigma[buddy];
            ctx.sigma[buddy] = hold;
            ctx.round_keys[(pos + pivot) & 0x7Fu] ^= rol32(trace[pos], (pos % 31u) + 1u);
            ctx.round_keys[(buddy + pos * 3u) & 0x7Fu] += trace[pos] + ctx.sigma[pivot];
        }

        if (stage_idx < STAGE_COUNT && pos + 1u == stage_cursor) {
            stage_digest(ctx.v, ctx.sigma, ctx.round_keys, trace, pos + 1u, parity, stage_idx, stage_buf);
            for (uint32_t i = 0; i < STAGE_GATE_WORDS; ++i) {
                mismatch |= stage_buf[i] ^ STAGE_GATES[stage_idx][i];
            }
            stage_idx += 1u;
            if (stage_idx < STAGE_COUNT) {
                stage_cursor += STAGE_LENGTHS[stage_idx];
            }
        }
    }

    if (stage_idx != STAGE_COUNT_META) {
        return false;
    }

    for (uint32_t i = 0; i < 8u; ++i) {
        rev_state[i] = ctx.v[i]
                     ^ ctx.round_keys[(i * 13u + (parity & 0x7Fu)) & 0x7Fu]
                     ^ SPICE[(parity + i * 29u) & 0xFFu];
    }

#ifdef DEBUG_SEAL
    dump_words("forward_state:", ctx.v, 8u);
    dump_words("forward_trace:", trace, FLAG_LEN);
    dump_words("forward_rk:", ctx.round_keys, 8u);
    dump_bytes("forward_sigma:", ctx.sigma, 16u);
    dump_words("rev_seed:", rev_state, 8u);
#endif

    for (uint32_t rev = 0; rev < FLAG_LEN; ++rev) {
        uint32_t pos = FLAG_LEN - 1u - rev;
        uint8_t ch = (uint8_t)input[pos];
        uint32_t witness = trace[(pos ^ ctx.sigma[(rev + ch) & 0xFFu]) % FLAG_LEN];
        uint32_t local[8];

        memcpy(local, rev_state, sizeof(local));
        for (uint32_t step = 0; step < BACKWARD_STEPS; ++step) {
            uint32_t pc = rev * BACKWARD_STEPS + step;
            uint32_t tap = ctx.sigma[(pc + pos + step + (witness & 0xFFu)) & 0xFFu];
            uint32_t idx = (
                witness
                + tap
                + ((local[(step + 3u) & 7u] >> ((pos + step) & 7u)) & 0xFFu)
                + SBOX[(ch + step + rev) & 0xFFu]
            ) & 0xFFu;
            uint32_t lane = LANE_SCHEDULE[idx] & 7u;
            uint32_t op = BOOT_OPS[
                (idx ^ ctx.round_keys[(pc + (witness & 0x7Fu)) & 0x7Fu] ^ ctx.sigma[(idx + (witness & 0xFFu)) & 0xFFu]) & 0x7Fu
            ];
            uint32_t rot = ROT_SCHEDULE[(idx + lane + ctx.sigma[(pc + rev) & 0xFFu]) & 0x7Fu];
            uint32_t sp = SPICE[(idx + ctx.sigma[(lane + ch + rev) & 0xFFu]) & 0xFFu]
                        ^ ctx.round_keys[(idx + rev + pos) & 0x7Fu]
                        ^ PAD[(pc + witness) & 0x3Fu];
            uint32_t arg = witness ^ ((uint32_t)ch << 16) ^ (step << 8) ^ local[(lane + 2u) & 7u];
            uint32_t trace_idx;

            vm_step(local, ctx.sigma, ctx.round_keys, lane, op, rot, sp, arg, idx, pc ^ witness ^ pos);
            trace_idx = (pos + lane + ctx.sigma[(step + pos) & 0xFFu]) % FLAG_LEN;
            trace[trace_idx] ^= rol32(local[lane] ^ sp ^ arg, ((rot + step) % 31u) + 1u);
            ctx.round_keys[(idx + trace_idx + op) & 0x7Fu] += trace[trace_idx] + local[(lane + 4u) & 7u];
        }

        rev_state[0] = local[0] ^ ror32(local[6], 3u) ^ trace[(pos + 1u) % FLAG_LEN];
        rev_state[1] = local[1] + rol32(local[7], 5u) + trace[pos % FLAG_LEN];
        rev_state[2] = ror32(local[2] ^ rev_state[0] ^ ctx.round_keys[(pos * 9u + 2u) & 0x7Fu], 7u);
        rev_state[3] = local[3] ^ rev_state[1] ^ sub_word(trace[(pos + 5u) % FLAG_LEN]);
        rev_state[4] = local[4] + ror32(rev_state[2] ^ SPICE[(pos * 5u + 9u) & 0xFFu], 11u);
        rev_state[5] = local[5] ^ rol32(rev_state[3] + PAD[(pos * 3u + 1u) & 0x3Fu], 13u);
        rev_state[6] = local[6] + sub_word(rev_state[4] ^ ctx.round_keys[(pos * 11u + 6u) & 0x7Fu]);
        rev_state[7] = local[7] ^ ror32(rev_state[5] + trace[(pos + 11u) % FLAG_LEN], 17u);
    }

#ifdef DEBUG_SEAL
    dump_words("backward_trace:", trace, FLAG_LEN);
    dump_words("backward_state:", rev_state, 8u);
    dump_words("backward_rk:", ctx.round_keys, 8u);
    dump_bytes("backward_sigma:", ctx.sigma, 16u);
#endif

    for (uint32_t i = 0; i < 8u; ++i) {
        uint32_t word = rev_state[i] ^ rol32(rev_state[(i + 3u) & 7u], ((i * 5u) + 3u) % 31u + 1u);
        word ^= trace[(i * 7u + ctx.sigma[(i * 19u) & 0xFFu]) % FLAG_LEN];
        word += ctx.round_keys[(i * 11u + word) & 0x7Fu] + SPICE[(ctx.sigma[(i * 23u + 5u) & 0xFFu] + i) & 0xFFu];
        word ^= sub_word(trace[(i * 5u + 3u) % FLAG_LEN] ^ ctx.round_keys[(i * 13u + 9u) & 0x7Fu]);
#ifdef DEBUG_SEAL
        computed_seal[i] = word;
#endif
        mismatch |= word ^ FINAL_SEAL[i];
    }

#ifdef DEBUG_SEAL
    dump_words("computed:", computed_seal, 8u);
    dump_words("expected:", FINAL_SEAL, 8u);
#endif

    return mismatch == 0u;
}

int main(int argc, char **argv) {
    const char *image_path = (argc > 1) ? argv[1] : "void.ns0";
    uint8_t image[IMAGE_SIZE];
    char input[128];

    if (!load_image(image_path, image)) {
        puts("program image rejected");
        return 1;
    }

    fputs("flag> ", stdout);
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    input[strcspn(input, "\r\n")] = '\0';

    if (verify_flag(input, image)) {
        puts("accepted");
        return 0;
    }

    puts("rejected");
    return 1;
}
