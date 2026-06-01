/*
 * csprng_stub.c — Demo CSPRNG for bare-metal RISC-V FPGA
 *
 * Entropy source : rdcycle (multiple samples) + CLINT mtime via MMIO
 *                  (base 0x02000000, mtime at +0xBFF8). The rdtime CSR
 *                  is NOT used — it traps on this board configuration.
 *
 * Whitening      : SHA-256 — 64 bytes of raw entropy → 32-byte key.
 *                  wolfCrypt (primary), TinyCrypt (legacy), Blake2b (Monocypher).
 *
 * Stream output  : HMAC-SHA-256 counter mode.
 *                  Each block: HMAC(key, counter_LE32) → 32 bytes.
 *
 * Board entropy  : Call csprng_add_entropy(data, len) after long-term keys
 *                  are derived to fold in board-specific material. This
 *                  guarantees different ephemeral keys on initiator vs.
 *                  responder even when mtime/rdcycle values match.
 *
 * Fallback       : splitmix64-CTR if no crypto library present.
 *
 * Limitation: entropy comes from execution timing. Main variation is CLINT
 *   mtime at seed time, which differs between FPGA programming sessions.
 *   For production security, replace with a real TRNG peripheral.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef WOLFCRYPT
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifdef TINYCRYPT
#include "tinycrypt/sha256.h"
#include "tinycrypt/hmac.h"
#endif

#if !defined(TINYCRYPT) && !defined(WOLFCRYPT) && defined(MONOCYPHER)
#include "monocypher.h"
#endif

#ifdef ASCON
/* Ascon-Hash256 (ascon-c crypto_hash, provided by the EDHOC lib). Used for
 * CSPRNG whitening on Suite-7 so the build does NOT link Monocypher Blake2b
 * (~17 KB). Monocypher is still included above (for ChaCha20 / crypto_wipe),
 * but its Blake2b stays dead-code-eliminated. */
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);
#endif

/* -------------------------------------------------------------------------
 * RV32 counter helpers
 * rdcycleh/rdcycle: atomically read 64-bit cycle counter (hi-lo-hi loop).
 * rv32_clint_mtime: direct MMIO read — rdtime CSR traps on this board.
 * ------------------------------------------------------------------------- */

static inline uint64_t rv32_rdcycle(void)
{
    uint32_t lo, hi1, hi2;
    do {
        __asm__ volatile ("rdcycleh %0" : "=r"(hi1));
        __asm__ volatile ("rdcycle  %0" : "=r"(lo));
        __asm__ volatile ("rdcycleh %0" : "=r"(hi2));
    } while (hi1 != hi2);
    return ((uint64_t)hi1 << 32) | lo;
}

/* CLINT mtime low 32 bits (Arty A7 SoC: CLINT base = 0x02000000).
 * mtime offset = 0xBFF8. Returns 0 if CLINT is not present. */
static inline uint32_t rv32_clint_mtime(void)
{
    return *(volatile uint32_t *)0x0200BFF8UL;
}

/* -------------------------------------------------------------------------
 * splitmix64 finalizer — avalanche mixer, no dependencies.
 * ------------------------------------------------------------------------- */
static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* -------------------------------------------------------------------------
 * CSPRNG state
 * ------------------------------------------------------------------------- */
#if defined(WOLFCRYPT) || defined(TINYCRYPT)
static uint8_t  g_key[32];
static uint32_t g_counter;
#elif defined(MONOCYPHER)
static uint8_t  g_key[32];
static uint8_t  g_nonce[8];
static uint64_t g_counter;
#else
static uint64_t g_seed;
static uint64_t g_counter;
#endif

static int g_ready = 0;

/* -------------------------------------------------------------------------
 * Volatile wipe — prevents compiler from eliding scrub of sensitive stack data.
 * ------------------------------------------------------------------------- */
static void csprng_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

/* -------------------------------------------------------------------------
 * Entropy collection and initial seeding
 * ------------------------------------------------------------------------- */
static void csprng_seed(void)
{
    /*
     * Collect 8 entropy words:
     *   raw[0..3]: rdcycle snapshots (64-bit, large value after sign_key_gen)
     *   raw[4]:    CLINT mtime low 32 bits (main inter-run entropy source)
     *   raw[5]:    second mtime sample + accumulated work word
     *   raw[6..7]: inter-sample cycle differences (timing jitter)
     *
     * Between samples, run volatile busy-loops of different lengths so
     * each successive reading lands at a different pipeline/memory offset.
     */
    uint64_t raw[8];
    volatile uint32_t work = 0;

    raw[0] = rv32_rdcycle();
    raw[4] = (uint64_t)rv32_clint_mtime();

    /* Delay 1 */
    for (volatile int i = 0; i < 500; i++) work ^= (uint32_t)(i * 0x9e3779b9u);
    raw[1] = rv32_rdcycle();

    /* Delay 2 — memory-touching */
    volatile uint8_t scratch[32];
    for (volatile int i = 0; i < 32; i++) scratch[i] = (uint8_t)(work >> i);
    for (volatile int i = 31; i >= 0; i--) work ^= scratch[i];
    raw[2] = rv32_rdcycle();
    raw[5] = (uint64_t)rv32_clint_mtime() | ((uint64_t)work << 32);

    /* Delay 3 — length depends on raw[1] to prevent compile-time folding */
    for (volatile uint32_t i = 0; i < (raw[1] & 0xFFF) + 200; i++) work += i;
    raw[3] = rv32_rdcycle();

    /* Capture cycle deltas — pure timing jitter */
    raw[6] = (raw[1] - raw[0]) ^ ((raw[2] - raw[1]) << 17);
    raw[7] = (raw[3] - raw[2]) ^ ((raw[3] - raw[0]) << 13) ^ (uint64_t)work;

    /* Pre-mix with splitmix64 before whitening */
    for (int i = 0; i < 8; i++)
        raw[i] = mix64(raw[i] ^ raw[(i + 5) % 8]);

    /* Pack 8×uint64 into 64-byte entropy buffer (little-endian) */
    uint8_t entropy[64];
    for (int i = 0; i < 8; i++) {
        uint64_t v = raw[i];
        for (int b = 0; b < 8; b++) {
            entropy[i * 8 + b] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }

#ifdef WOLFCRYPT
    /* Whiten with wc_Sha256Hash: 64 bytes of entropy → 32-byte key */
    wc_Sha256Hash(entropy, sizeof(entropy), g_key);
    g_counter = 0;

#elif defined(TINYCRYPT)
    /* Whiten with SHA-256: 64 bytes of entropy → 32-byte key */
    struct tc_sha256_state_struct sha_s;
    tc_sha256_init(&sha_s);
    tc_sha256_update(&sha_s, entropy, sizeof(entropy));
    tc_sha256_final(g_key, &sha_s);
    g_counter = 0;
    csprng_wipe(&sha_s, sizeof(sha_s));

#elif defined(ASCON)
    /* Whiten with Ascon-Hash256 (already linked) → 32-byte key + 8-byte nonce.
     * Avoids the ~17 KB Monocypher Blake2b the MONOCYPHER branch would pull in. */
    uint8_t digest[32], nd[32];
    crypto_hash(digest, entropy, sizeof(entropy));
    crypto_hash(nd, digest, 32);
    memcpy(g_key,   digest, 32);
    memcpy(g_nonce, nd,      8);
    g_counter = 0;
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(nd,     sizeof(nd));

#elif defined(MONOCYPHER)
    /* Whiten with Blake2b-512 → 32-byte key + 8-byte nonce */
    uint8_t digest[64];
    crypto_blake2b(digest, 64, entropy, sizeof(entropy));
    memcpy(g_key,   digest,      32);
    memcpy(g_nonce, digest + 32,  8);
    g_counter = 0;
    crypto_wipe(digest,  sizeof(digest));

#else
    /* Fallback: fold into 64-bit seed */
    g_seed = 0;
    for (int i = 0; i < 8; i++)
        g_seed = mix64(g_seed ^ raw[i]);
    g_counter = 0;
#endif

    csprng_wipe(entropy, sizeof(entropy));
    csprng_wipe(raw, sizeof(raw));
    g_ready = 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*
 * csprng_add_entropy — fold external data into the CSPRNG key.
 *
 * Call ONCE after deriving long-term keys from a board-specific seed.
 * Ensures different boards produce different ephemeral keys even when
 * rdcycle/mtime entropy values happen to collide.
 *
 *   TINYCRYPT path: new_key = SHA-256(current_key || data)
 *   MONOCYPHER path: new_key = Blake2b(current_key || data)[0..31]
 *   Fallback:       g_seed ^= mix64(data[0..7])
 */
void csprng_add_entropy(const uint8_t *data, uint32_t len)
{
    if (!data || len == 0) return;
    if (!g_ready) csprng_seed();

#ifdef WOLFCRYPT
    /* new_key = SHA-256(current_key || data) */
    {
        Hmac hmac;
        uint8_t new_key[32];
        wc_HmacSetKey(&hmac, WC_SHA256, g_key, 32);
        wc_HmacUpdate(&hmac, data, len);
        wc_HmacFinal(&hmac, new_key);
        wc_HmacFree(&hmac);
        memcpy(g_key, new_key, 32);
        csprng_wipe(new_key, 32);
    }
    g_counter = 0;

#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct sha_s;
    tc_sha256_init(&sha_s);
    tc_sha256_update(&sha_s, g_key, 32);
    tc_sha256_update(&sha_s, data, len);
    tc_sha256_final(g_key, &sha_s);
    g_counter = 0;
    csprng_wipe(&sha_s, sizeof(sha_s));

#elif defined(ASCON)
    {
    uint8_t buf[64];
    uint32_t use = len < 32 ? len : 32;
    memcpy(buf,      g_key, 32);
    memcpy(buf + 32, data,  use);
    uint8_t digest[32], nd[32];
    crypto_hash(digest, buf, 32 + use);
    crypto_hash(nd, digest, 32);
    memcpy(g_key,   digest, 32);
    memcpy(g_nonce, nd,      8);
    g_counter = 0;
    crypto_wipe(buf,    sizeof(buf));
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(nd,     sizeof(nd));
    }
#elif defined(MONOCYPHER)
    uint8_t buf[64];
    uint32_t use = len < 32 ? len : 32;
    memcpy(buf,        g_key, 32);
    memcpy(buf + 32,   data,  use);
    uint8_t digest[64];
    crypto_blake2b(digest, 64, buf, 32 + use);
    memcpy(g_key,   digest,     32);
    memcpy(g_nonce, digest + 32, 8);
    g_counter = 0;
    crypto_wipe(buf,    sizeof(buf));
    crypto_wipe(digest, sizeof(digest));

#else
    uint64_t v = 0;
    uint32_t copy = len < 8 ? len : 8;
    for (uint32_t i = 0; i < copy; i++)
        v |= ((uint64_t)data[i] << (8 * i));
    g_seed = mix64(g_seed ^ v);
    g_counter = 0;
#endif
}

/*
 * default_CSPRNG — fill dest with `size` pseudo-random bytes.
 * Returns 1 on success, 0 on bad arguments.
 */
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
    if (!dest || size == 0) return 0;
    if (!g_ready) csprng_seed();

#ifdef WOLFCRYPT
    unsigned int done = 0;
    while (done < size) {
        /* HMAC-SHA-256(key, counter_LE32) → 32-byte block */
        uint8_t ctr_buf[4] = {
            (uint8_t)(g_counter),
            (uint8_t)(g_counter >> 8),
            (uint8_t)(g_counter >> 16),
            (uint8_t)(g_counter >> 24)
        };
        Hmac hmac;
        uint8_t block[32];
        wc_HmacSetKey(&hmac, WC_SHA256, g_key, 32);
        wc_HmacUpdate(&hmac, ctr_buf, 4);
        wc_HmacFinal(&hmac, block);
        wc_HmacFree(&hmac);
        g_counter++;

        unsigned int chunk = size - done;
        if (chunk > 32) chunk = 32;
        memcpy(dest + done, block, chunk);
        done += chunk;

        csprng_wipe(block, sizeof(block));
    }

#elif defined(TINYCRYPT)
    unsigned int done = 0;
    while (done < size) {
        /* HMAC-SHA-256(key, counter_LE32) → 32-byte block */
        uint8_t ctr_buf[4] = {
            (uint8_t)(g_counter),
            (uint8_t)(g_counter >> 8),
            (uint8_t)(g_counter >> 16),
            (uint8_t)(g_counter >> 24)
        };
        struct tc_hmac_state_struct hmac_s;
        uint8_t block[TC_SHA256_DIGEST_SIZE];
        tc_hmac_set_key(&hmac_s, g_key, 32);
        tc_hmac_init(&hmac_s);
        tc_hmac_update(&hmac_s, ctr_buf, 4);
        tc_hmac_final(block, TC_SHA256_DIGEST_SIZE, &hmac_s);
        g_counter++;

        unsigned int chunk = size - done;
        if (chunk > TC_SHA256_DIGEST_SIZE) chunk = TC_SHA256_DIGEST_SIZE;
        memcpy(dest + done, block, chunk);
        done += chunk;

        csprng_wipe(&hmac_s, sizeof(hmac_s));
        csprng_wipe(block, sizeof(block));
    }

#elif defined(ASCON)
    /* Ascon-Hash256 counter mode: block = AsconHash(key || counter_LE32).
     * Reuses the already-linked Ascon hash so Suite 7 does NOT drag in a
     * separate stream cipher (Monocypher ChaCha20 ~1 KB). */
    {
    unsigned int done = 0;
    while (done < size) {
        uint8_t ctr_in[36];
        memcpy(ctr_in, g_key, 32);
        ctr_in[32] = (uint8_t)(g_counter);
        ctr_in[33] = (uint8_t)(g_counter >> 8);
        ctr_in[34] = (uint8_t)(g_counter >> 16);
        ctr_in[35] = (uint8_t)(g_counter >> 24);
        uint8_t block[32];
        crypto_hash(block, ctr_in, sizeof(ctr_in));
        g_counter++;
        unsigned int chunk = size - done;
        if (chunk > 32) chunk = 32;
        memcpy(dest + done, block, chunk);
        done += chunk;
        csprng_wipe(block, sizeof(block));
    }
    }

#elif defined(MONOCYPHER)
    g_counter = crypto_chacha20_djb(dest, NULL, size,
                                     g_key, g_nonce, g_counter);

#else
    unsigned int i = 0;
    while (i < size) {
        uint64_t block = mix64(g_seed ^ (++g_counter));
        unsigned int chunk = size - i;
        if (chunk > 8) chunk = 8;
        for (unsigned int b = 0; b < chunk; b++) {
            dest[i++] = (uint8_t)(block & 0xFF);
            block >>= 8;
        }
    }
#endif

    return 1;
}

/*
 * init_prng — mix in a 32-bit external seed value.
 * Legacy API; prefer csprng_add_entropy() for multi-byte input.
 */
void init_prng(uint32_t seed)
{
    uint8_t buf[4] = {
        (uint8_t)(seed),
        (uint8_t)(seed >> 8),
        (uint8_t)(seed >> 16),
        (uint8_t)(seed >> 24)
    };
    csprng_add_entropy(buf, 4);
}
