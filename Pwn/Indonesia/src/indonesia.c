#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOC_SIZE 0x600
#define SEAL_OFF 0x3a0
#define SEAL_SLOTS 2
#define SEAL_MAC_OFF (SEAL_OFF + SEAL_SLOTS * sizeof(uintptr_t))
#define SEAL_LEN (SEAL_SLOTS * sizeof(uintptr_t) + sizeof(uint64_t))
#define MAX_READ 0x10
#define STAMP_LIMIT 0x30

typedef void (*service_fn)(void);

struct borrowed_page {
	size_t off;
	int valid;
	int borrowed;
};

static unsigned char document[DOC_SIZE];
static struct borrowed_page borrowed;
static unsigned stamp_count;
static volatile unsigned char path_key = 0x23;

static uint64_t rol64(uint64_t x, unsigned n)
{
	return (x << n) | (x >> (64 - n));
}

static uint64_t read_u64(size_t off)
{
	uint64_t raw;

	memcpy(&raw, document + off, sizeof(raw));
	return raw;
}

static void write_u64(size_t off, uint64_t raw)
{
	memcpy(document + off, &raw, sizeof(raw));
}

static uint64_t seal_mac(uintptr_t a, uintptr_t b)
{
	uint64_t x = (uint64_t)a ^ 0x243f6a8885a308d3ULL;
	uint64_t y = (uint64_t)b ^ 0x13198a2e03707344ULL;
	uint64_t z = 0xa4093822299f31d0ULL ^ ((uint64_t)SEAL_OFF << 32) ^ DOC_SIZE;

	for (unsigned i = 0; i < 5; i++) {
		x += rol64(y ^ z, 17);
		y ^= rol64(x + 0x9e3779b97f4a7c15ULL + i, 23);
		z += rol64(y, 41) ^ x;
		x ^= rol64(z, 29);
	}

	return x ^ rol64(y, 7) ^ rol64(z, 33) ^ 0x452821e638d01377ULL;
}

static uint8_t stamp_byte(uint16_t code, size_t off, unsigned round)
{
	uint32_t x = 0x6c8e9cf5U;

	x ^= (uint32_t)code * 0x45d9f3bU;
	x ^= (uint32_t)off * 0x119de1f3U;
	x ^= (uint32_t)round * 0x27d4eb2dU;
	x ^= x >> 15;
	x *= 0x2c1b3c6dU;
	x ^= x >> 12;
	x *= 0x297a2d39U;
	x ^= x >> 15;

	return (uint8_t)(x ^ (x >> 8) ^ (x >> 16) ^ (x >> 24));
}

static void write_slot(size_t off, service_fn fn)
{
	uintptr_t raw = (uintptr_t)fn;

	memcpy(document + off, &raw, sizeof(raw));
}

static service_fn read_slot(size_t off)
{
	uintptr_t raw;

	memcpy(&raw, document + off, sizeof(raw));
	return (service_fn)raw;
}

__attribute__((noinline, used))
static void layanan_0(void)
{
	puts("[arsip] dokumen publik sudah ditampilkan.");
}

__attribute__((noinline, used))
static void layanan_1(void)
{
	puts("[arsip] akses dokumen utama ditolak.");
}

__attribute__((noinline, used))
static void layanan_17(void)
{
	char path[] = { 0x45, 0x4f, 0x42, 0x44, 0x0d, 0x57, 0x5b, 0x57, 0x00 };
	char buf[128];
	FILE *fp;

	for (size_t i = 0; i < sizeof(path) - 1; i++)
		path[i] ^= path_key;

	fp = fopen(path, "r");

	if (fp == NULL) {
		printf("arsip: %s\n", strerror(errno));
		exit(1);
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		puts("arsip kosong");
		fclose(fp);
		exit(1);
	}

	fclose(fp);
	printf("%s", buf);
	if (buf[strlen(buf) - 1] != '\n')
		putchar('\n');
	exit(0);
}

static void sync_seal(void)
{
	uintptr_t slot0 = (uintptr_t)read_slot(SEAL_OFF);
	uintptr_t slot1 = (uintptr_t)read_slot(SEAL_OFF + sizeof(uintptr_t));

	write_u64(SEAL_MAC_OFF, seal_mac(slot0, slot1));
}

static int seal_ok(void)
{
	uintptr_t slot0 = (uintptr_t)read_slot(SEAL_OFF);
	uintptr_t slot1 = (uintptr_t)read_slot(SEAL_OFF + sizeof(uintptr_t));

	return read_u64(SEAL_MAC_OFF) == seal_mac(slot0, slot1);
}

static void init_document(void)
{
	static const char banner[] = "INDONESIA: layanan arsip terpadu";

	memset(document, 0, sizeof(document));
	memcpy(document, banner, sizeof(banner) - 1);
	write_slot(SEAL_OFF, layanan_0);
	write_slot(SEAL_OFF + sizeof(uintptr_t), layanan_1);
	sync_seal();
}

static int parse_two_ull(const char *line, unsigned long long *a,
			 unsigned long long *b)
{
	int used = 0;
	int n;

	n = sscanf(line, "%*s %llu %llu %n", a, b, &used);
	if (n != 2)
		return 0;
	return line[used] == '\0' || line[used] == '\n';
}

static int parse_one_ull(const char *line, unsigned long long *a)
{
	int used = 0;
	int n;

	n = sscanf(line, "%*s %llu %n", a, &used);
	if (n != 1)
		return 0;
	return line[used] == '\0' || line[used] == '\n';
}

static void show_help(void)
{
	puts("menu:");
	puts("  bantuan              tampilkan menu");
	puts("  katalog              lihat metadata arsip");
	puts("  baca <off> <len>     baca potongan dokumen");
	puts("  tulis <off> <byte>   jalur tulis biasa");
	puts("  pinjam <off>         pinjam satu halaman arsip");
	puts("  cap <kode>           beri cap pada halaman pinjaman");
	puts("  tampil <idx>         jalankan loket layanan 0 atau 1");
	puts("  keluar               selesai");
}

static void cmd_catalog(void)
{
	printf("doc_size=0x%x seal_off=0x%x seal_len=0x%zx batas_cap=0x%x\n",
	       DOC_SIZE, SEAL_OFF, (size_t)SEAL_LEN, STAMP_LIMIT);
	puts("catatan: dokumen tersegel melewati audit sebelum loket dijalankan.");
}

static void cmd_read(const char *line)
{
	unsigned long long off;
	unsigned long long len;

	if (!parse_two_ull(line, &off, &len)) {
		puts("usage: baca <off> <len>");
		return;
	}
	if (off >= DOC_SIZE || len > MAX_READ || off + len > DOC_SIZE) {
		puts("baca: di luar dokumen");
		return;
	}

	for (unsigned long long i = 0; i < len; i++)
		printf("%02x", document[off + i]);
	putchar('\n');
}

static void cmd_write(const char *line)
{
	unsigned long long off;
	unsigned long long byte;

	if (!parse_two_ull(line, &off, &byte)) {
		puts("usage: tulis <off> <byte>");
		return;
	}
	if (off >= DOC_SIZE || byte > 0xff) {
		puts("tulis: di luar dokumen");
		return;
	}
	if (off >= SEAL_OFF && off < SEAL_OFF + SEAL_LEN) {
		puts("tulis: area segel ditolak");
		return;
	}

	document[off] = (unsigned char)byte;
	puts("tulis: ok");
}

static void cmd_borrow(const char *line)
{
	unsigned long long off;

	if (!parse_one_ull(line, &off)) {
		puts("usage: pinjam <off>");
		return;
	}
	if (off >= DOC_SIZE) {
		puts("pinjam: di luar dokumen");
		return;
	}

	borrowed.off = (size_t)off;
	borrowed.valid = 1;
	borrowed.borrowed = 1;
	printf("pinjam: antrean %u siap\n", stamp_count);
}

static void cmd_stamp(const char *line)
{
	unsigned long long code;
	unsigned char ink;

	if (!parse_one_ull(line, &code)) {
		puts("usage: cap <kode>");
		return;
	}
	if (code > 0xffff) {
		puts("cap: kode harus 16-bit");
		return;
	}
	if (!borrowed.valid) {
		puts("cap: belum ada halaman pinjaman");
		return;
	}
	if (stamp_count >= STAMP_LIMIT) {
		puts("cap: loket cap tutup");
		return;
	}

	ink = stamp_byte((uint16_t)code, borrowed.off, stamp_count);
	document[borrowed.off] ^= ink;
	borrowed.valid = 0;
	stamp_count++;
	puts("cap: diterima");
}

static void cmd_show(const char *line)
{
	unsigned long long idx;
	service_fn fn;

	if (!parse_one_ull(line, &idx)) {
		puts("usage: tampil <idx>");
		return;
	}
	if (idx >= SEAL_SLOTS) {
		puts("tampil: hanya loket 0 dan 1");
		return;
	}
	if (!seal_ok()) {
		puts("[audit] dokumen tersegel tidak sinkron.");
		return;
	}

	fn = read_slot(SEAL_OFF + idx * sizeof(uintptr_t));
	printf("loket[%llu] dipanggil\n", idx);
	fn();
}

int main(void)
{
	char line[128];

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGALRM, SIG_DFL);
	alarm(120);

	init_document();
	puts("Indonesia - layanan arsip digital");
	show_help();

	for (;;) {
		printf("indonesia> ");
		if (fgets(line, sizeof(line), stdin) == NULL)
			break;

		if (strncmp(line, "bantuan", 7) == 0 || strncmp(line, "help", 4) == 0)
			show_help();
		else if (strncmp(line, "katalog", 7) == 0)
			cmd_catalog();
		else if (strncmp(line, "baca", 4) == 0)
			cmd_read(line);
		else if (strncmp(line, "tulis", 5) == 0)
			cmd_write(line);
		else if (strncmp(line, "pinjam", 6) == 0)
			cmd_borrow(line);
		else if (strncmp(line, "cap", 3) == 0)
			cmd_stamp(line);
		else if (strncmp(line, "tampil", 6) == 0)
			cmd_show(line);
		else if (strncmp(line, "keluar", 6) == 0 || strncmp(line, "quit", 4) == 0)
			break;
		else if (line[0] != '\n')
			puts("menu tidak dikenal");
	}

	return 0;
}
