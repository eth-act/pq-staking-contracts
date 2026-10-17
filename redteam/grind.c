// Grind rho for a leanXMSS-K WOTS+C message digest d = K(P || T || rho || M) such that the 58
// base-4 digits of d sum to 106 and each digit is >= min[k]. Used by the one-time-leaf reuse
// forgery PoC (redteam/forge_pop.py).
//
// usage: grind <P||T hex (32 bytes)> <M hex (32 bytes)> <58 min digits, e.g. 0120...> [threads]
//        grind --selftest <hex input>   (prints keccak256 of input)
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int ROTC[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                             27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const int PILN[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                             15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
#define ROTL(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static void keccakf(uint64_t st[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t bc[5], t;
        for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            uint64_t tmp = st[j];
            st[j] = ROTL(t, ROTC[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= RC[r];
    }
}

// Single-block keccak256 (len < 136), little-endian host.
static void keccak256(const uint8_t *in, size_t len, uint8_t out[32]) {
    uint64_t st[25] = {0};
    uint8_t block[136] = {0};
    memcpy(block, in, len);
    block[len] ^= 0x01;
    block[135] ^= 0x80;
    for (int i = 0; i < 17; i++) {
        uint64_t w;
        memcpy(&w, block + 8 * i, 8);
        st[i] ^= w;
    }
    keccakf(st);
    memcpy(out, st, 32);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t unhex(const char *s, uint8_t *out) {
    if (s[0] == '0' && s[1] == 'x') s += 2;
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(hexval(s[2 * i]) << 4 | hexval(s[2 * i + 1]));
    return n;
}

static uint8_t PREFIX[32], MSG[32], MIN[58];
static atomic_int found = 0;
static atomic_ullong total = 0;
static uint8_t RESULT[16];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    uint32_t tid = (uint32_t)(uintptr_t)arg;
    uint8_t buf[80], d[32];
    memcpy(buf, PREFIX, 32);
    memcpy(buf + 48, MSG, 32);
    memset(buf + 32, 0, 16);
    memcpy(buf + 32, &tid, 4);
    uint64_t ctr = 0, local = 0;
    while (!atomic_load_explicit(&found, memory_order_relaxed)) {
        memcpy(buf + 36, &ctr, 8);
        ctr++;
        local++;
        keccak256(buf, 80, d);
        int sum = 0, ok = 1;
        for (int k = 0; k < 58; k++) {
            int a = (d[k >> 2] >> (6 - 2 * (k & 3))) & 3;
            if (a < MIN[k]) { ok = 0; break; }
            sum += a;
        }
        if (ok && sum == 106) {
            pthread_mutex_lock(&lock);
            if (!found) {
                memcpy(RESULT, buf + 32, 16);
                atomic_store(&found, 1);
            }
            pthread_mutex_unlock(&lock);
        }
        if ((local & 0xfffff) == 0) atomic_fetch_add(&total, 0x100000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--selftest") == 0) {
        uint8_t in[136], out[32];
        size_t n = unhex(argv[2], in);
        keccak256(in, n, out);
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
        return 0;
    }
    if (argc < 4) return 2;
    unhex(argv[1], PREFIX);
    unhex(argv[2], MSG);
    for (int k = 0; k < 58; k++) MIN[k] = (uint8_t)(argv[3][k] - '0');
    int threads = argc > 4 ? atoi(argv[4]) : 32;
    pthread_t th[256];
    for (int t = 0; t < threads; t++) pthread_create(&th[t], NULL, worker, (void *)(uintptr_t)t);
    for (int t = 0; t < threads; t++) pthread_join(th[t], NULL);
    for (int i = 0; i < 16; i++) printf("%02x", RESULT[i]);
    printf(" %llu\n", (unsigned long long)atomic_load(&total));
    return 0;
}
