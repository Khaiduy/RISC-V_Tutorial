/*
 * OSCORE Standalone Benchmark
 *
 * Measures oscore_context_init(), coap2oscore(), oscore2coap() in isolation.
 * Methodology: offline emulation — pre-filled buffers, no network, rdcycle64.
 * Matches Hristozov et al. CODASPY 2021 measurement methodology.
 *
 * Key material: RFC 8613 Appendix C.1.1 test vectors (T1)
 *   Client: Sender ID=empty,  Recipient ID={0x01}   (used for coap2oscore)
 *   Server: Sender ID={0x01}, Recipient ID=empty    (used for oscore2coap)
 *   AEAD: AES-CCM-16-64-128  (RFC 8613 mandatory)
 *   HKDF: HMAC-SHA-256       (RFC 8613 mandatory)
 *
 * Reference results (Cortex-M33 @ 64 MHz, tinycrypt, Hristozov 2021):
 *   oscore_context_init : ~2,625 us
 *   coap2oscore         : ~946 us  (35-byte OSCORE frame)
 *   oscore2coap         : ~946 us  (35-byte OSCORE frame)
 *
 * NOTE on RFC C.4 vector: the RFC test vector uses SSN=20. A fresh context
 * starts at SSN=0, so our encryption produces a different ciphertext (different
 * nonce). Correctness is verified by round-trip: encrypt (client) → decrypt
 * (server) → compare against original.
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "oscore.h"

/* CPU frequency. Override at build time: make oscore_benchmark BENCHMARK_CPU_HZ=65000000UL */
#ifndef BENCHMARK_CPU_HZ
#define BENCHMARK_CPU_HZ 50000000UL   /* Arty 35T Rocket core: 50 MHz */
#endif

/* Number of iterations per measurement (crypto is deterministic; variance ≈ 0). */
#define N_ITER 100

/* Packet pool depth for decrypt measurements.
 * Each slot is MAX_OSCORE_LEN bytes; total BSS = N_POOL * MAX_OSCORE_LEN.
 * N_POOL=10 → 12 KB, fitting the 64 KB memory_mem region.
 * Fewer iterations are acceptable because crypto is deterministic. */
#define N_POOL 10

/* Buffer limits */
#define MAX_APP_PAYLOAD  1000
#define MAX_COAP_LEN     (23 + MAX_APP_PAYLOAD)
#define MAX_OSCORE_LEN   1200   /* generous: overhead ≤ ~30 bytes */

/* ---------------------------------------------------------------------------
 * RV32 atomic 64-bit cycle counter
 * Reads rdcycleh / rdcycle / rdcycleh and retries on 32-bit carry.
 * ---------------------------------------------------------------------------*/
static inline uint64_t rdcycle64(void)
{
    uint32_t lo, hi, hi2;
    do {
        asm volatile ("rdcycleh %0" : "=r"(hi));
        asm volatile ("rdcycle  %0" : "=r"(lo));
        asm volatile ("rdcycleh %0" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

/* ---------------------------------------------------------------------------
 * RFC 8613 Appendix C.1.1 — key derivation with Master Salt (T1 vectors)
 * ---------------------------------------------------------------------------*/
static const uint8_t T1_MASTER_SECRET[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};
static const uint8_t T1_MASTER_SALT[8] = {
    0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40
};

/* RFC 8613 C.1.1: Client Sender ID = empty, Server Sender ID = {0x01} */
static const uint8_t SERVER_SENDER_ID[1] = { 0x01 };

/* RFC 8613 C.4 — 22-byte CoAP GET request (no application payload) */
static const uint8_t T1_COAP_REQ[22] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
};

/* RFC 8613 C.4 — known OSCORE encoding of T1_COAP_REQ at SSN=20.
 * Used to verify the server can decrypt a well-known ciphertext. */
static const uint8_t T1_OSCORE_REQ_SSN20[35] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
};

/* Fixed 23-byte CoAP header for payload sweep:
 * 22 bytes header + 0xFF payload marker. Append N bytes of app payload. */
static const uint8_t COAP_HEADER_23[23] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31, 0xff
};

/* Application payload sizes for the sweep (bytes).
 * Matches the uoscore-uedhoc benchmarks.md test points. */
static const uint16_t SWEEP_SIZES[] = { 10, 20, 50, 100, 200, 500, 1000 };
#define NUM_SWEEPS ((int)(sizeof(SWEEP_SIZES) / sizeof(SWEEP_SIZES[0])))

/* ---------------------------------------------------------------------------
 * Static buffers — allocated in BSS, not on the stack
 * ---------------------------------------------------------------------------*/
static struct context client_ctx;   /* Sender=empty,  Recipient={0x01} */
static struct context server_ctx;   /* Sender={0x01}, Recipient=empty  */
static uint8_t coap_buf[MAX_COAP_LEN];
static uint8_t oscore_enc_buf[MAX_OSCORE_LEN];  /* scratch for encrypt timing */
static uint8_t coap_dec_buf[MAX_COAP_LEN];      /* decryption output */

/* Packet pool for Hristozov-compatible decrypt measurement:
 * N_ITER packets with consecutive SSNs pre-generated outside the timed window.
 * Server context is initialised once; the replay window accepts each new SSN
 * in order without requiring context reinitialisation. */
static uint8_t  pkt_pool[N_POOL][MAX_OSCORE_LEN];
static uint32_t pkt_len[N_POOL];

/* ---------------------------------------------------------------------------
 * Context helpers
 * ---------------------------------------------------------------------------*/

/* CLIENT context: Sender ID=empty (client sends), Recipient ID={0x01} (server) */
static enum err client_ctx_init(void)
{
    struct oscore_init_params p = {
        .master_secret         = { .len = sizeof(T1_MASTER_SECRET),
                                   .ptr = (uint8_t *)T1_MASTER_SECRET },
        .sender_id             = { .len = 0, .ptr = NULL },
        .recipient_id          = { .len = sizeof(SERVER_SENDER_ID),
                                   .ptr = (uint8_t *)SERVER_SENDER_ID },
        .id_context            = { .len = 0, .ptr = NULL },
        .master_salt           = { .len = sizeof(T1_MASTER_SALT),
                                   .ptr = (uint8_t *)T1_MASTER_SALT },
        .aead_alg              = OSCORE_AES_CCM_16_64_128,
        .hkdf                  = OSCORE_SHA_256,
        .fresh_master_secret_salt = true,
    };
    memset(&client_ctx, 0, sizeof(client_ctx));
    return oscore_context_init(&p, &client_ctx);
}

/* SERVER context: Sender ID={0x01} (server sends), Recipient ID=empty (client) */
static enum err server_ctx_init(void)
{
    struct oscore_init_params p = {
        .master_secret         = { .len = sizeof(T1_MASTER_SECRET),
                                   .ptr = (uint8_t *)T1_MASTER_SECRET },
        .sender_id             = { .len = sizeof(SERVER_SENDER_ID),
                                   .ptr = (uint8_t *)SERVER_SENDER_ID },
        .recipient_id          = { .len = 0, .ptr = NULL },
        .id_context            = { .len = 0, .ptr = NULL },
        .master_salt           = { .len = sizeof(T1_MASTER_SALT),
                                   .ptr = (uint8_t *)T1_MASTER_SALT },
        .aead_alg              = OSCORE_AES_CCM_16_64_128,
        .hkdf                  = OSCORE_SHA_256,
        .fresh_master_secret_salt = true,
    };
    memset(&server_ctx, 0, sizeof(server_ctx));
    return oscore_context_init(&p, &server_ctx);
}

/* ---------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------------*/
int main(void)
{
    REG32(uart, UART_REG_DIV)    = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;

    kprintf("\r\n=== OSCORE Benchmark (RFC 8613 Appendix C.1 vectors) ===\r\n");
    kprintf("CPU: %lu Hz,  N_ITER: %d\r\n\r\n",
            (unsigned long)BENCHMARK_CPU_HZ, N_ITER);

    uint64_t t0, t1, total;
    enum err rc;

    /* ===================================================================
     * 1. Correctness checks
     * ===================================================================*/
    kprintf("[CHECK] Correctness:\r\n");

    /* 1a. Decrypt the RFC C.4 known vector (SSN=20) using server context.
     *     This verifies the server can decrypt a well-known client request. */
    server_ctx_init();
    uint32_t coap_out_len = sizeof(coap_dec_buf);
    rc = oscore2coap((uint8_t *)T1_OSCORE_REQ_SSN20, sizeof(T1_OSCORE_REQ_SSN20),
                     coap_dec_buf, &coap_out_len, &server_ctx);
    if (rc == ok &&
        coap_out_len == sizeof(T1_COAP_REQ) &&
        memcmp(coap_dec_buf, T1_COAP_REQ, sizeof(T1_COAP_REQ)) == 0) {
        kprintf("  PASS RFC C.4: server decrypts SSN=20 vector -> matches T1_COAP_REQ\r\n");
    } else {
        kprintf("  FAIL RFC C.4 decrypt: rc=%d len=%lu\r\n",
                (int)rc, (unsigned long)coap_out_len);
    }

    /* 1b. Round-trip: client encrypts (SSN=0) -> server decrypts -> compare.
     *     This verifies the two derived key sets are consistent. */
    client_ctx_init();
    uint32_t enc_len = sizeof(oscore_enc_buf);
    rc = coap2oscore((uint8_t *)T1_COAP_REQ, sizeof(T1_COAP_REQ),
                     oscore_enc_buf, &enc_len, &client_ctx);
    if (rc != ok) {
        kprintf("  FAIL round-trip encrypt: rc=%d\r\n", (int)rc);
        while (1) {}
    }

    server_ctx_init();
    coap_out_len = sizeof(coap_dec_buf);
    rc = oscore2coap(oscore_enc_buf, enc_len,
                     coap_dec_buf, &coap_out_len, &server_ctx);
    if (rc == ok &&
        coap_out_len == sizeof(T1_COAP_REQ) &&
        memcmp(coap_dec_buf, T1_COAP_REQ, sizeof(T1_COAP_REQ)) == 0) {
        kprintf("  PASS round-trip: client(SSN=0) -> server -> original CoAP\r\n\r\n");
    } else {
        kprintf("  FAIL round-trip decrypt: rc=%d len=%lu\r\n\r\n",
                (int)rc, (unsigned long)coap_out_len);
    }

    /* ===================================================================
     * 2. oscore_context_init() timing — client context (representative)
     * ===================================================================*/
    total = 0;
    for (int i = 0; i < N_ITER; i++) {
        t0 = rdcycle64();
        client_ctx_init();
        t1 = rdcycle64();
        total += (t1 - t0);
    }
    {
        uint32_t avg = (uint32_t)(total / N_ITER);
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("[INIT] oscore_context_init (N=%d):\r\n", N_ITER);
        kprintf("  avg %lu cycles = %lu us\r\n",
                (unsigned long)avg, (unsigned long)us);
        kprintf("  ref: ~2625 us (Cortex-M33 @ 64 MHz, tinycrypt)\r\n\r\n");
    }

    /* ===================================================================
     * 3. Reference point: T1_COAP_REQ (22-byte, no app payload)
     *    This is the Hristozov et al. operating point — produces a 35-byte
     *    OSCORE frame. Report separately for direct paper comparison.
     * ===================================================================*/
    kprintf("[REF-35B] T1_COAP_REQ -> 35-byte OSCORE (N=%d):\r\n", N_ITER);

    /* coap2oscore: encrypt 22-byte CoAP GET -> ~35 bytes OSCORE */
    client_ctx_init();
    total = 0;
    for (int i = 0; i < N_ITER; i++) {
        uint32_t out = sizeof(oscore_enc_buf);
        t0 = rdcycle64();
        coap2oscore((uint8_t *)T1_COAP_REQ, sizeof(T1_COAP_REQ),
                    oscore_enc_buf, &out, &client_ctx);
        t1 = rdcycle64();
        total += (t1 - t0);
    }
    {
        uint32_t avg = (uint32_t)(total / N_ITER);
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("  coap2oscore: avg %lu cycles = %lu us  (ref: ~946 us)\r\n",
                (unsigned long)avg, (unsigned long)us);
    }

    /* oscore2coap: pre-generate N_POOL packets (SSN 0..N_POOL-1), then time
     * N_POOL consecutive server decryptions with a single server_ctx_init().
     * The replay window accepts each incrementing SSN without reinit.
     * N_POOL < N_ITER to fit the 64 KB memory region; variance is zero
     * for deterministic bare-metal crypto. */
    client_ctx_init();
    for (int i = 0; i < N_POOL; i++) {
        pkt_len[i] = sizeof(pkt_pool[i]);
        coap2oscore((uint8_t *)T1_COAP_REQ, sizeof(T1_COAP_REQ),
                    pkt_pool[i], &pkt_len[i], &client_ctx);
    }
    server_ctx_init();
    total = 0;
    for (int i = 0; i < N_POOL; i++) {
        uint32_t dec_len = sizeof(coap_dec_buf);
        t0 = rdcycle64();
        oscore2coap(pkt_pool[i], pkt_len[i],
                    coap_dec_buf, &dec_len, &server_ctx);
        t1 = rdcycle64();
        total += (t1 - t0);
    }
    {
        uint32_t avg = (uint32_t)(total / N_POOL);
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("  oscore2coap: avg %lu cycles = %lu us  (ref: ~946 us)\r\n\r\n",
                (unsigned long)avg, (unsigned long)us);
    }

    /* ===================================================================
     * 4. coap2oscore() — payload sweep (CLIENT encrypts)
     *    Fresh client context per sweep point (SSN=0).
     *    N_ITER encryptions; SSN increments 0..N_ITER-1 — crypto cost same.
     * ===================================================================*/
    kprintf("[ENCRYPT] coap2oscore (N=%d per size):\r\n", N_ITER);
    kprintf("Payload |   Avg Cycles |   Avg us\r\n");
    kprintf("--------|--------------|----------\r\n");

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint16_t plen     = SWEEP_SIZES[ps];
        uint32_t coap_len = 23 + plen;

        memcpy(coap_buf, COAP_HEADER_23, 23);
        for (uint16_t j = 0; j < plen; j++) {
            coap_buf[23 + j] = (uint8_t)(j & 0xFF);
        }

        client_ctx_init();
        total = 0;
        for (int i = 0; i < N_ITER; i++) {
            uint32_t out = sizeof(oscore_enc_buf);
            t0 = rdcycle64();
            coap2oscore(coap_buf, coap_len,
                        oscore_enc_buf, &out, &client_ctx);
            t1 = rdcycle64();
            total += (t1 - t0);
        }
        {
            uint32_t avg = (uint32_t)(total / N_ITER);
            uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
            kprintf("  %5u  |  %10lu  |  %lu\r\n",
                    plen, (unsigned long)avg, (unsigned long)us);
        }
    }

    /* ===================================================================
     * 4. oscore2coap() — payload sweep (SERVER decrypts)
     *    Pre-generate one client OSCORE packet per payload size (SSN=0).
     *    Time server decryption; reinit server context before each call
     *    (outside timed window) to reset the replay window.
     * ===================================================================*/
    kprintf("\r\n[DECRYPT] oscore2coap (N=%d per size):\r\n", N_POOL);
    kprintf("Payload |   Avg Cycles |   Avg us\r\n");
    kprintf("--------|--------------|----------\r\n");

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint16_t plen     = SWEEP_SIZES[ps];
        uint32_t coap_len = 23 + plen;

        memcpy(coap_buf, COAP_HEADER_23, 23);
        for (uint16_t j = 0; j < plen; j++) {
            coap_buf[23 + j] = (uint8_t)(j & 0xFF);
        }

        /* Pre-generate N_POOL packets with SSN 0..N-1 using client context. */
        client_ctx_init();
        int pre_gen_ok = 1;
        for (int i = 0; i < N_POOL; i++) {
            pkt_len[i] = sizeof(pkt_pool[i]);
            rc = coap2oscore(coap_buf, coap_len,
                             pkt_pool[i], &pkt_len[i], &client_ctx);
            if (rc != ok) {
                kprintf("  pre-gen FAIL rc=%d plen=%u i=%d\r\n",
                        (int)rc, plen, i);
                pre_gen_ok = 0;
                break;
            }
        }
        if (!pre_gen_ok) continue;

        /* Time N_POOL consecutive server decryptions — single server_ctx_init().
         * Incrementing SSNs are accepted by the replay window without reinit. */
        server_ctx_init();
        total = 0;
        for (int i = 0; i < N_POOL; i++) {
            uint32_t dec_len = sizeof(coap_dec_buf);
            t0 = rdcycle64();
            oscore2coap(pkt_pool[i], pkt_len[i],
                        coap_dec_buf, &dec_len, &server_ctx);
            t1 = rdcycle64();
            total += (t1 - t0);
        }
        {
            uint32_t avg = (uint32_t)(total / N_POOL);
            uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
            kprintf("  %5u  |  %10lu  |  %lu\r\n",
                    plen, (unsigned long)avg, (unsigned long)us);
        }
    }

    kprintf("\r\n=== Done ===\r\n");
    kprintf("ref: ~946 us encrypt/decrypt @ 35-byte OSCORE / Cortex-M33 @ 64 MHz\r\n");

    while (1) {}
    return 0;
}
