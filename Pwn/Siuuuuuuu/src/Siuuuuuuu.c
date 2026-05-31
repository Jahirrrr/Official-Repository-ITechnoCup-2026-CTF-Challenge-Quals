#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHALL_NAME "Siuuuuuuu"
#define ALG_NAME "matchday-elite-catalog"
#define KEY_MAGIC "VIP-ORDER-2026:"
#define PIPE_CAP 0x60
#define MAX_COPY 0x180

#define F_SOCKET 0x01u
#define F_BIND 0x02u
#define F_KEY 0x04u
#define F_NULL_KEY 0x08u
#define F_CMSG 0x10u

#define ALL_FLAGS (F_SOCKET | F_BIND | F_KEY | F_NULL_KEY | F_CMSG)

#define SEAL_ADD 0x6a09e667f3bcc909ULL
#define AAD_MAGIC 0x31431ee7c0decafeULL
#define SPLICE_MAGIC 0xd6e8feb86659fd93ULL
#define RECV_MAGIC 0xa4093822299f31d0ULL
#define TICKET_MAGIC 0x85d35a47c0f2b91eULL

struct siu_ctx {
    uint64_t boot_cookie;
    uint32_t flags;
    uint32_t cmsg_count;
    uint64_t key_hash;
    uint64_t cmsg_hash;
    uint64_t request_len;
    char alg_name[0x40];
    char key_hex[0xb0];
    uint8_t pipe_buf[PIPE_CAP];
    uint64_t copied;
    uint64_t epoch;
    uint64_t guard;
    uint64_t sealed_cb;
    uint64_t ticket;
    uint64_t tag;
    uint64_t audit[0x20];
};

typedef void (*completion_t)(struct siu_ctx *);

static struct siu_ctx *g_ctx;

static void reject_completion(struct siu_ctx *ctx);
static int service_main(void);

_Static_assert(offsetof(struct siu_ctx, copied) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x60,
               "unexpected pipe-to-copied offset");
_Static_assert(offsetof(struct siu_ctx, epoch) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x68,
               "unexpected pipe-to-epoch offset");
_Static_assert(offsetof(struct siu_ctx, guard) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x70,
               "unexpected pipe-to-guard offset");
_Static_assert(offsetof(struct siu_ctx, sealed_cb) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x78,
               "unexpected pipe-to-callback offset");
_Static_assert(offsetof(struct siu_ctx, ticket) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x80,
               "unexpected pipe-to-ticket offset");
_Static_assert(offsetof(struct siu_ctx, tag) -
                   offsetof(struct siu_ctx, pipe_buf) ==
               0x88,
               "unexpected pipe-to-tag offset");

static uint64_t rol64(uint64_t x, unsigned int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t ror64(uint64_t x, unsigned int r) {
    return (x >> r) | (x << (64 - r));
}

static uint64_t mix64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static uint64_t fnv1a64(const void *buf, size_t len) {
    const uint8_t *p = buf;
    uint64_t h = 0xcbf29ce484222325ULL;

    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }

    return h;
}

static uint64_t seal_ptr(const void *ptr, uint64_t guard, uint64_t tag) {
    uint64_t x = (uint64_t)(uintptr_t)ptr;

    x ^= guard;
    x = rol64(x, 17);
    x += SEAL_ADD;
    x ^= tag;

    return x;
}

static void *unseal_ptr(uint64_t sealed, uint64_t guard, uint64_t tag) {
    uint64_t x = sealed ^ tag;

    x -= SEAL_ADD;
    x = ror64(x, 17);
    x ^= guard;

    return (void *)(uintptr_t)x;
}

static uint64_t entropy64(void) {
    uint64_t x = 0;
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd >= 0) {
        ssize_t n = read(fd, &x, sizeof(x));
        close(fd);
        if (n == (ssize_t)sizeof(x)) {
            return x;
        }
    }

    x ^= (uint64_t)time(NULL);
    x ^= (uint64_t)getpid() << 32;
    x ^= (uint64_t)(uintptr_t)&x;
    x ^= (uint64_t)(uintptr_t)&service_main;
    return mix64(x);
}

static void read_exact(int fd, void *buf, size_t len) {
    uint8_t *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            puts("\nshort read");
            exit(1);
        }
        p += n;
        len -= (size_t)n;
    }
}

static void read_line(char *buf, size_t len) {
    size_t pos = 0;

    if (len == 0) {
        return;
    }

    while (pos + 1 < len) {
        char c = 0;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            exit(0);
        }
        if (c == '\n') {
            break;
        }
        buf[pos++] = c;
    }

    buf[pos] = '\0';
}

static uint64_t read_u64(const char *prompt) {
    char buf[0x40];

    fputs(prompt, stdout);
    fflush(stdout);
    read_line(buf, sizeof(buf));
    return strtoull(buf, NULL, 0);
}

static uint32_t splice_token(const struct siu_ctx *ctx, uint64_t len) {
    return (uint32_t)mix64(len ^ ctx->key_hash ^ rol64(ctx->cmsg_hash, 5) ^
                           SPLICE_MAGIC);
}

static uint32_t recv_token(const struct siu_ctx *ctx, uint64_t off,
                           uint64_t len) {
    return (uint32_t)mix64(off ^ rol64(len, 17) ^ ctx->cmsg_hash ^
                           ctx->copied ^ RECV_MAGIC);
}

static uint64_t wanted_ticket(const struct siu_ctx *ctx) {
    uint64_t x = TICKET_MAGIC;

    x ^= ctx->key_hash;
    x ^= rol64(ctx->cmsg_hash, 13);
    x ^= ctx->epoch;
    x ^= ctx->request_len;
    x ^= ctx->copied << 7;

    return mix64(x);
}

static void reject_completion(struct siu_ctx *ctx) {
    (void)ctx;
    puts("checkout rejected: loyalty stamp did not validate");
}

static void build_flag_path(char out[9]) {
    static const volatile uint8_t enc[8] = {
        0x3c, 0x36, 0x3b, 0x3d, 0x74, 0x2e, 0x22, 0x2e,
    };
    volatile uint8_t key = 0x5a;

    for (size_t i = 0; i < 8; i++) {
        out[i] = (char)(enc[i] ^ key);
    }
    out[8] = '\0';
}

static void __attribute__((used, noinline))
copy_escalated_cred_back_to_user(struct siu_ctx *ctx) {
    char path[9];
    char flag[0x100];
    FILE *fp = NULL;

    if ((ctx->flags & ALL_FLAGS) != ALL_FLAGS) {
        puts("ledger check: incomplete order");
        return;
    }

    if (ctx->ticket != wanted_ticket(ctx)) {
        puts("ledger check: invalid manager stamp");
        return;
    }

    if ((ctx->copied & 0xff) != 0 || ctx->copied < 0x90) {
        puts("ledger check: package window too small");
        return;
    }

    build_flag_path(path);
    fp = fopen(path, "r");
    if (fp == NULL) {
        puts("backend missing");
        exit(1);
    }

    if (fgets(flag, sizeof(flag), fp) == NULL) {
        puts("backend empty");
        fclose(fp);
        exit(1);
    }

    fclose(fp);
    printf("%s", flag);
    exit(0);
}

static void init_ctx(void) {
    uint64_t entropy = 0;

    g_ctx = calloc(1, sizeof(*g_ctx));
    if (g_ctx == NULL) {
        perror("calloc");
        exit(1);
    }

    entropy = entropy64();
    g_ctx->boot_cookie = mix64(entropy ^ 0x9e3779b97f4a7c15ULL);
    g_ctx->guard = mix64(entropy ^ (uint64_t)(uintptr_t)g_ctx ^
                         (uint64_t)(uintptr_t)&service_main);
    g_ctx->epoch = mix64(g_ctx->guard ^ (uint64_t)(uintptr_t)g_ctx ^
                         0x31431aead5f11ceULL);
    g_ctx->tag = mix64(g_ctx->epoch ^ 0xf23a9d0487c6b51eULL);
    g_ctx->sealed_cb =
        seal_ptr((const void *)reject_completion, g_ctx->guard, g_ctx->tag);
    g_ctx->ticket = mix64(g_ctx->tag ^ 0xbadc0ffee0ddf00dULL);

    for (size_t i = 0; i < sizeof(g_ctx->audit) / sizeof(g_ctx->audit[0]);
         i++) {
        g_ctx->audit[i] = mix64(g_ctx->boot_cookie + i);
    }
}

static int ready_for_copy(void) {
    return (g_ctx->flags & ALL_FLAGS) == ALL_FLAGS;
}

static void banner(void) {
    puts("== " CHALL_NAME " ==");
    puts("Matchday souvenir checkout. Keep the line moving.");
}

static void menu(void) {
    puts("");
    puts("1. clock in cashier");
    puts("2. load catalog shelf");
    puts("3. register price rule");
    puts("4. attach order note");
    puts("5. pack gift box");
    puts("6. print receipt");
    puts("7. close register");
    puts("8. inventory status");
    puts("9. leave shop");
}

static void do_socket(void) {
    uint64_t family = read_u64("terminal id: ");
    uint64_t type = read_u64("lane id: ");
    uint64_t proto = read_u64("drawer seed: ");

    if (family == 38 && type == 5 && proto == 0) {
        g_ctx->flags |= F_SOCKET;
        puts("cashier terminal opened");
    } else {
        puts("terminal refused");
    }
}

static void do_bind(void) {
    if ((g_ctx->flags & F_SOCKET) == 0) {
        puts("catalog: cashier is offline");
        return;
    }

    fputs("catalog name: ", stdout);
    fflush(stdout);
    read_line(g_ctx->alg_name, sizeof(g_ctx->alg_name));

    if (strcmp(g_ctx->alg_name, ALG_NAME) == 0) {
        g_ctx->flags |= F_BIND;
        puts("premium shelf loaded");
    } else {
        puts("catalog unavailable");
    }
}

static void do_setsockopt(void) {
    uint64_t opt = 0;

    if ((g_ctx->flags & F_BIND) == 0) {
        puts("price rule: no shelf selected");
        return;
    }

    opt = read_u64("rule id: ");
    if (opt == 1) {
        size_t key_len = 0;

        fputs("loyalty blob: ", stdout);
        fflush(stdout);
        read_line(g_ctx->key_hex, sizeof(g_ctx->key_hex));
        key_len = strlen(g_ctx->key_hex);
        g_ctx->key_hash = fnv1a64(g_ctx->key_hex, key_len);

        if (key_len >= 0x40 &&
            strncmp(g_ctx->key_hex, KEY_MAGIC, strlen(KEY_MAGIC)) == 0) {
            g_ctx->flags |= F_KEY;
            puts("loyalty profile accepted");
        } else {
            g_ctx->flags &= ~F_KEY;
            puts("loyalty profile rejected");
        }
        return;
    }

    if (opt == 5) {
        uint64_t optlen = read_u64("stamp length: ");
        if (optlen == 4) {
            g_ctx->flags |= F_NULL_KEY;
            puts("blank stamp queued");
        } else {
            g_ctx->flags &= ~F_NULL_KEY;
            puts("stamp rejected");
        }
        return;
    }

    puts("unknown rule");
}

static void do_sendmsg(void) {
    char prefix[0x30];
    uint64_t op = 0;
    uint64_t assoc = 0;
    uint64_t iv = 0;
    uint64_t aad = 0;

    if ((g_ctx->flags & (F_KEY | F_NULL_KEY)) != (F_KEY | F_NULL_KEY)) {
        puts("order note: price rule incomplete");
        return;
    }

    fputs("note header hex: ", stdout);
    fflush(stdout);
    read_line(prefix, sizeof(prefix));
    op = read_u64("badge tier: ");
    assoc = read_u64("coupon family: ");
    iv = read_u64("wrap format: ");
    aad = read_u64("receipt echo: ");

    g_ctx->cmsg_hash =
        mix64(op ^ (assoc << 11) ^ (iv << 22) ^ aad ^
              rol64(g_ctx->key_hash, 9));
    g_ctx->cmsg_count++;

    if (strcmp(prefix, "41414141") == 0 && op == 3 && assoc == 2 && iv == 4 &&
        aad == (g_ctx->key_hash ^ AAD_MAGIC)) {
        g_ctx->flags |= F_CMSG;
        puts("order note accepted");
    } else {
        g_ctx->flags &= ~F_CMSG;
        puts("order note dropped");
    }
}

static void do_splice(void) {
    uint64_t len = 0;
    uint64_t token = 0;
    uint8_t checked = 0;

    if (!ready_for_copy()) {
        puts("packing: order is not ready");
        return;
    }

    len = read_u64("box size: ");
    token = read_u64("packing token: ");
    checked = (uint8_t)len;

    if (len > MAX_COPY) {
        puts("packing: box too large");
        return;
    }

    printf("counter scale reads: %" PRIu8 "/%u\n", checked, PIPE_CAP);
    if (checked > PIPE_CAP) {
        puts("packing: rejected");
        return;
    }

    if ((uint32_t)token != splice_token(g_ctx, len)) {
        puts("packing: invalid supervisor token");
        return;
    }

    g_ctx->request_len = len;
    puts("gift wrap bytes:");
    read_exact(STDIN_FILENO, g_ctx->pipe_buf, (size_t)len);
    g_ctx->copied = len;
    puts("parcel queued");
}

static void do_recv(void) {
    uint64_t off = 0;
    uint64_t len = 0;
    uint64_t token = 0;
    uint8_t checked = 0;

    if (!ready_for_copy()) {
        puts("receipt: order is not ready");
        return;
    }

    off = read_u64("receipt offset: ");
    len = read_u64("receipt length: ");
    token = read_u64("printer token: ");
    checked = (uint8_t)len;

    if (off > MAX_COPY || len > MAX_COPY || off + len > MAX_COPY) {
        puts("receipt: range outside ledger");
        return;
    }

    printf("printer scale reads: %" PRIu8 "/%u\n", checked, PIPE_CAP);
    if (checked > PIPE_CAP) {
        puts("receipt: rejected");
        return;
    }

    if ((uint32_t)token != recv_token(g_ctx, off, len)) {
        puts("receipt: invalid printer token");
        return;
    }

    puts("-----BEGIN RECEIPT-----");
    if (write(STDOUT_FILENO, g_ctx->pipe_buf + off, (size_t)len) !=
        (ssize_t)len) {
        puts("\nreceipt: printer jam");
        exit(1);
    }
    puts("\n-----END RECEIPT-----");
}

static void do_finish(void) {
    completion_t cb = NULL;

    puts("closing register...");
    cb = (completion_t)unseal_ptr(g_ctx->sealed_cb, g_ctx->guard, g_ctx->tag);
    cb(g_ctx);
}

static void do_status(void) {
    printf("shelf=0x%x notes=%u packed=%" PRIu64 " tray=%u\n",
           g_ctx->flags, g_ctx->cmsg_count, g_ctx->copied, PIPE_CAP);
}

static int service_main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(90);

    init_ctx();
    banner();

    for (;;) {
        uint64_t choice = 0;

        menu();
        choice = read_u64("> ");

        switch (choice) {
        case 1:
            do_socket();
            break;
        case 2:
            do_bind();
            break;
        case 3:
            do_setsockopt();
            break;
        case 4:
            do_sendmsg();
            break;
        case 5:
            do_splice();
            break;
        case 6:
            do_recv();
            break;
        case 7:
            do_finish();
            break;
        case 8:
            do_status();
            break;
        case 9:
            puts("bye");
            return 0;
        default:
            puts("?");
            break;
        }
    }
}

int main(void) {
    return service_main();
}
