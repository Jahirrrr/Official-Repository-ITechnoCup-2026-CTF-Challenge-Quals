#include <stdint.h>
#include "emulate.h"
#include "bigint.h"
#include "syscall.h"
#include "util.h"


/**
 * Virtual code loaded from a .itech image
 */
uint8_t *vcode;


/**
 * 1 MB of virtual memory
 */
uint8_t *vmem;

enum {
    GUEST_STATUS = 0x0000,
    GUEST_REC12 = 0x0008,
    GUEST_OWNER = 0x0010,
    GUEST_ARCHIVE = 0x0018,
    GUEST_BASE = 0x0020,
    GUEST_LAST = 0x0028,
    GUEST_RESTART = 0x0030,
    GUEST_NONCE = 0x0038,
    GUEST_PROOF = 0x0040,
    GUEST_DISTANCE = 0x0048,
    GUEST_REGION_HASH = 0x0050,
};

enum {
    BLF_REC12_OFFSET = 0x858,
    BLF_OWNER_OFFSET = 0x38,
    BLF_ARCHIVE_OFFSET = 0x40,
    BLF_BASE_OFFSET = 0x48,
    BLF_LAST_OFFSET = 0x50,
    BLF_RESTART_OFFSET = 0x58,
    BLF_NONCE_OFFSET = 0x60,
    BLF_PROOF_OFFSET = 0x68,
    BLF_REGION_TAIL = 0x30,
    BLF_EXPECTED_SIZE = 0x10000,
    BLF_EXPECTED_DISTANCE = 0x30,
    CLFS_HASH_NODE = 0xC1FDF006,
    CLFS_CLIENT_NODE = 0xC1FDF007
};


/**
 * The header of an Itech image contains a magic number, version, public RSA data, and an XOR key
 */
typedef struct ItechImageHeader {
    char magic[4];
    uint8_t version;
    uint8_t mod[128];
    uint8_t exp[3];
    uint8_t sig[128];
    uint8_t key[4];
} ItechImageHeader;

size_t get_file_sz(char *path);

static uint16_t read_u16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t read_u64le(const uint8_t *p) {
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint64_t rol64(uint64_t x, uint64_t r) {
    r &= 63u;
    if(r == 0)
        return x;
    return (x << r) | (x >> (64u - r));
}

static size_t cstr_len(const char *s) {
    size_t n = 0;
    while(s[n] != '\0')
        n++;
    return n;
}

static uint64_t hash_region(const uint8_t *buffer, size_t size) {
    uint64_t x = 0xcbf29ce484222325ULL;
    for(size_t i = 0; i < size; i++) {
        x ^= (uint64_t)((buffer[i] + ((i * 0x9dU) & 0xffU)) & 0xffU);
        x *= 0x100000001b3ULL;
        x = rol64(x, 7) ^ 0xa0761d6478bd642fULL;
    }
    return x;
}

static size_t find_u32(const uint8_t *buffer, size_t size, uint32_t marker, size_t start) {
    if(size < 4 || start >= size)
        return (size_t)-1;

    for(size_t i = start; i + 4 <= size; i++) {
        if(read_u32le(buffer + i) == marker)
            return i;
    }

    return (size_t)-1;
}

static void guest_write64(uint32_t addr, uint64_t value) {
    *(uint64_t *)(&vmem[ITECH_VMEM_SCRATCH_LO + addr]) = value;
}

static void load_blf_guest_state(char *blf_path) {
    size_t blf_sz;
    int blf_fd;
    uint8_t *buffer;
    size_t hash_off;
    size_t ctx_off;
    size_t region_len;

    guest_write64(GUEST_STATUS, 0);
    guest_write64(GUEST_REC12, 0);
    guest_write64(GUEST_OWNER, 0);
    guest_write64(GUEST_ARCHIVE, 0);
    guest_write64(GUEST_BASE, 0);
    guest_write64(GUEST_LAST, 0);
    guest_write64(GUEST_RESTART, 0);
    guest_write64(GUEST_NONCE, 0);
    guest_write64(GUEST_PROOF, 0);
    guest_write64(GUEST_DISTANCE, 0);
    guest_write64(GUEST_REGION_HASH, 0);

    blf_sz = get_file_sz(blf_path);
    if(blf_sz == (size_t)~0ULL || blf_sz == 0)
        return;

    blf_fd = sys_open(blf_path, O_RDONLY);
    if(blf_fd < 0)
        return;

    buffer = (uint8_t *)sys_mmap(blf_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    if((int64_t)buffer < 0) {
        sys_close(blf_fd);
        return;
    }

    if(sys_read(blf_fd, buffer, blf_sz) < 0) {
        sys_close(blf_fd);
        sys_munmap(buffer, blf_sz);
        return;
    }
    sys_close(blf_fd);

    hash_off = find_u32(buffer, blf_sz, CLFS_HASH_NODE, 0);
    ctx_off = find_u32(buffer, blf_sz, CLFS_CLIENT_NODE, hash_off == (size_t)-1 ? 0 : hash_off + 4);

    if(blf_sz != BLF_EXPECTED_SIZE ||
       hash_off == (size_t)-1 ||
       ctx_off == (size_t)-1 ||
       hash_off >= ctx_off ||
       (ctx_off - hash_off) != BLF_EXPECTED_DISTANCE ||
       (ctx_off + BLF_PROOF_OFFSET + 8) > blf_sz ||
       (BLF_REC12_OFFSET + 2) > blf_sz ||
       buffer[ctx_off + 4] != 0x88 ||
       buffer[ctx_off + 5] != 0x00) {
        sys_munmap(buffer, blf_sz);
        return;
    }

    region_len = (ctx_off + BLF_REGION_TAIL) - hash_off;

    guest_write64(GUEST_STATUS, 1);
    guest_write64(GUEST_REC12, read_u16le(buffer + BLF_REC12_OFFSET));
    guest_write64(GUEST_OWNER, read_u64le(buffer + ctx_off + BLF_OWNER_OFFSET));
    guest_write64(GUEST_ARCHIVE, read_u64le(buffer + ctx_off + BLF_ARCHIVE_OFFSET));
    guest_write64(GUEST_BASE, read_u64le(buffer + ctx_off + BLF_BASE_OFFSET));
    guest_write64(GUEST_LAST, read_u64le(buffer + ctx_off + BLF_LAST_OFFSET));
    guest_write64(GUEST_RESTART, read_u64le(buffer + ctx_off + BLF_RESTART_OFFSET));
    guest_write64(GUEST_NONCE, read_u64le(buffer + ctx_off + BLF_NONCE_OFFSET));
    guest_write64(GUEST_PROOF, read_u64le(buffer + ctx_off + BLF_PROOF_OFFSET));
    guest_write64(GUEST_DISTANCE, (uint64_t)(ctx_off - hash_off));
    guest_write64(GUEST_REGION_HASH, hash_region(buffer + hash_off, region_len));

    sys_munmap(buffer, blf_sz);
}


/**
 * Compute x**p (mod m) for BigInts.
 * @param x - Data to encrypt.
 * @param p - Public encryption exponent.
 * @param m - Public modulus.
 * @return x**p (mod m) as a BigInt
 */
BigInt *modpow(BigInt *x, BigInt *p, BigInt *m) {
    // Initialize working variables
    BigInt *result = NULL;
    BigInt *zero = BI_fromPrimitive(0);
    BigInt *base = BI_fromBig(x);
    BigInt *pow = BI_fromBig(p);

    // Modulo 0 is undefined
    if(BI_equals(m, zero))
        goto finish;

    // Simplify the base
    result = BI_fromPrimitive(1);
    BI_mod(base, m);

    // Perform THE LOOP
    while(BI_greaterThan(pow, zero)) {
        if(AL_get(pow->n, 0) & 1) {
            BI_multiply(result, base);
            BI_mod(result, m);
        }
        BI_multiply(base, base);
        BI_mod(base, m);
        BI_shiftRight(pow, 1);
    }

    // Cleanup and return
    finish:
    BI_free(zero); BI_free(base); BI_free(pow);
    return result;
}


/**
 * Compute the FNV1A hash of an array of bytes
 * @param bytes - Bytes to compute the hash for.
 * @param sz - Number of bytes.
 * @return the FNV1A hash (or at least a variant of it).
 */
uint64_t fnv1a_hash(const uint8_t *bytes, size_t sz) {
    uint64_t hash = 0x3140101438;
    for(size_t i = 0; i < sz; i++) {
        uint64_t b = 0;
        for(int j = 0; j < 8; j++)
            b |= ((uint64_t)bytes[i]) << (8 * j);
        hash = (hash * 8675309) ^ b;
    }
    return hash;
}


/**
 * Get the size of a file in bytes
 * @param path - Path to file to query
 * @return size of file at path, max of uint64_t on error.
 */
size_t get_file_sz(char *path) {
    int fd = sys_open(path, O_RDONLY);
    if(fd < 0) {
        return -1;
    }
    size_t sz = sys_lseek(fd, 0, SEEK_END);
    if(sz < 0) {
        sys_close(fd);
        return -1;
    }
    sys_close(fd);
    return sz;
}


/**
 * Driver function to...
 * @param argc - Number of arguments.
 * @param argv - List of arguments (argv[0] path/to/crackme.itech).
 * @return if an error occurred.
 */
int main(int argc, char *argv[]) {
    // Use a specific or default virtual image
    char *image_path;
    char *blf_path;
    if(argc < 2) {
        image_path = "crackme.itech";
        blf_path = "client.blf";
    } else if(argc < 3) {
        image_path = "crackme.itech";
        blf_path = argv[1];
    } else {
        image_path = argv[1];
        blf_path = argv[2];
    }

    // Open the Itech image
    int image_fd = sys_open(image_path, O_RDONLY);
    if(image_fd < 0)
        sys_exit(SYS_open);
    
    // Validate the image is at least large enough for the header
    size_t image_sz = get_file_sz(image_path);
    if(image_sz == ~0ULL || image_sz < sizeof(ItechImageHeader)) {
        sys_close(image_fd);
        sys_exit(image_sz);
    }

    // Read the header into a structure
    ItechImageHeader hdr;
    sys_read(image_fd, &hdr, sizeof(ItechImageHeader));

    // Validate the magic number and format version
    if(hdr.magic[0] != 'I' || hdr.magic[1] != 'T' || hdr.magic[2] != 'E' || hdr.magic[3] != 'C' || hdr.version != 1) {
        sys_close(image_fd);
        sys_exit(1);
    }

    // Read the code bytes from the image
    size_t vcode_sz = image_sz - sizeof(ItechImageHeader);
    vcode = (uint8_t *)sys_mmap(vcode_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS);
    if(vcode < 0) {
        sys_close(image_fd);
        sys_exit(1);
    }
    if(sys_read(image_fd, vcode, vcode_sz) < 0) {
        sys_close(image_fd);
        sys_munmap(vcode, vcode_sz);
        sys_exit(1);
    }
    sys_close(image_fd);
    sys_mprotect(vcode, vcode_sz, PROT_READ);

    // Compute the signature of the code
    BigInt *hash = BI_fromPrimitive(fnv1a_hash(vcode, vcode_sz));
    BigInt *exponent = BI_fromBytes(hdr.exp, 3);
    BigInt *modulus = BI_fromBytes(hdr.mod, 128);
    BigInt *cipher = modpow(hash, exponent, modulus);
    BI_free(hash); BI_free(exponent); BI_free(modulus);
    

    // Compute the entry point from the signature and key
    BigInt *xor = BI_fromBytes(hdr.key, 4);
    uint32_t entry = cipher->n->arr[0] ^ xor->n->arr[0];
    BI_free(xor);

    // Validate the signature
    BigInt *signature = BI_fromBytes(hdr.sig, 128);
    bool isMatch = BI_equals(signature, cipher);
    BI_free(signature); BI_free(cipher);
    if(!isMatch) {
        sys_exit(1);
    }

    // Allocate 1 MB buffer for virtual memory
    vmem = (uint8_t *)sys_mmap(ITECH_VMEM_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS);
    if(vmem < 0) {
        sys_munmap(vcode, vcode_sz);
        sys_exit(1);
    }

    load_blf_guest_state(blf_path);

    // Begin emulation
    DEBUG_PRINT("Beginning emulation from +0x%x...\n", entry);
    emulate(entry);

    // Cleanup dynamically allocated architecture
    sys_munmap(vcode, vcode_sz);
    sys_munmap(vmem, ITECH_VMEM_SIZE);

    return 0;
}


/**
 * Entrypoint, since we are not using LIBC.
 * Parameters are passed on the stack to the entrypoint by convention.
 * The naked attribute tells GCC to not add a function prologue.
 */
__attribute__((naked)) void _start() {
    // Get the stack pointer
    uint64_t *rsp;
    __asm__ volatile("mov %0, rsp" : "=r"(rsp));

    // Extract the usual argc and argv from it
    int argc = (int) rsp[0];
    char **argv = (char **) &rsp[1];

    // Call main with argc and argv
    sys_printf("\n");
    int exit_code = main(argc, argv);
    sys_printf("\n");
    sys_exit(exit_code);
}
