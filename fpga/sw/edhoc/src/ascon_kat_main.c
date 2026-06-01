/* On-target Ascon KAT self-test for RV32 verification.
 * Runs the same KAT vectors that PASS on host gcc; if these fail on the FPGA
 * the bug is RV32-build-specific (alignment / 32-bit / LTO interaction).
 * If they PASS, the bug is in the EDHOC integration (crypto_wrapper_legacy.c
 * AEAD splice or ascon_hmac/HKDF wiring). */
#include <stdint.h>
#include <string.h>
#include "kprintf.h"

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub, const unsigned char *k);
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);
int ascon_hmac(const unsigned char *key, unsigned long long key_len,
               const unsigned char *data, unsigned long long data_len,
               unsigned char *out);

static volatile uint32_t _delay_blackhole = 0;
static void uart_settle(void) {
    /* Crude busy-wait so UART FIFO drains between prints. */
    for (volatile uint32_t i = 0; i < 200000; i++) _delay_blackhole += i;
}
static void print_hex(const char *label, const uint8_t *b, int n) {
    kprintf("%s ", label);
    for (int i = 0; i < n; i++) kprintf("%02x", b[i]);
    kprintf("\r\n");
    uart_settle();
}

static int cmp(const uint8_t *got, const uint8_t *exp, int n) {
    for (int i = 0; i < n; i++) if (got[i] != exp[i]) return 0;
    return 1;
}

int main(void) {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    uint8_t nonce[16] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                         0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
    uint8_t out[64];
    unsigned long long olen;
    int fails = 0;

    kprintf("\r\n=== Ascon KAT self-test on RV32 ===\r\n");

    /* AEAD KAT#1 */
    uint8_t exp_aead1[16] = {0x4F,0x9C,0x27,0x82,0x11,0xBE,0xC9,0x31,
                             0x6B,0xF6,0x8F,0x46,0xEE,0x8B,0x2E,0xC6};
    olen = 0;
    crypto_aead_encrypt(out, &olen, NULL, 0, NULL, 0, NULL, nonce, key);
    print_hex("AEAD#1 got", out, (int)olen);
    if (olen == 16 && cmp(out, exp_aead1, 16)) kprintf("AEAD#1 PASS\r\n");
    else { kprintf("AEAD#1 FAIL\r\n"); fails++; }
    uart_settle();

    /* AEAD KAT#2: AD=30, PT=empty */
    uint8_t ad2[1] = {0x30};
    uint8_t exp_aead2[16] = {0xCC,0xCB,0x67,0x4F,0xE1,0x8A,0x09,0xA2,
                             0x85,0xD6,0xAB,0x11,0xB3,0x56,0x75,0xC0};
    olen = 0;
    crypto_aead_encrypt(out, &olen, NULL, 0, ad2, 1, NULL, nonce, key);
    print_hex("AEAD#2 got", out, (int)olen);
    if (olen == 16 && cmp(out, exp_aead2, 16)) kprintf("AEAD#2 PASS\r\n");
    else { kprintf("AEAD#2 FAIL\r\n"); fails++; }
    uart_settle();

    /* HASH KAT#1: Msg=empty */
    uint8_t exp_hash1[32] = {0x0B,0x3B,0xE5,0x85,0x0F,0x2F,0x6B,0x98,
                             0xCA,0xF2,0x9F,0x8F,0xDE,0xA8,0x9B,0x64,
                             0xA1,0xFA,0x70,0xAA,0x24,0x9B,0x8F,0x83,
                             0x9B,0xD5,0x3B,0xAA,0x30,0x4D,0x92,0xB2};
    crypto_hash(out, NULL, 0);
    print_hex("HASH#1 got", out, 32);
    if (cmp(out, exp_hash1, 32)) kprintf("HASH#1 PASS\r\n");
    else { kprintf("HASH#1 FAIL\r\n"); fails++; }
    uart_settle();

    /* HASH KAT#2: Msg=00 */
    uint8_t msg2[1] = {0x00};
    uint8_t exp_hash2[32] = {0x07,0x28,0x62,0x10,0x35,0xAF,0x3E,0xD2,
                             0xBC,0xA0,0x3B,0xF6,0xFD,0xE9,0x00,0xF9,
                             0x45,0x6F,0x53,0x30,0xE4,0xB5,0xEE,0x23,
                             0xE7,0xF6,0xA1,0xE7,0x02,0x91,0xBC,0x80};
    crypto_hash(out, msg2, 1);
    print_hex("HASH#2 got", out, 32);
    if (cmp(out, exp_hash2, 32)) kprintf("HASH#2 PASS\r\n");
    else { kprintf("HASH#2 FAIL\r\n"); fails++; }
    uart_settle();

    /* AEAD roundtrip: encrypt then decrypt arbitrary plaintext+AD */
    uint8_t pt[24] = {0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04,
                      0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,
                      0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14};
    uint8_t ad3[4] = {0xCA,0xFE,0xBA,0xBE};
    uint8_t ct[24 + 16];
    uint8_t pt_back[24];
    unsigned long long ctlen = 0, ptlen = 0;
    crypto_aead_encrypt(ct, &ctlen, pt, 24, ad3, 4, NULL, nonce, key);
    print_hex("ROUNDTRIP ct+tag", ct, (int)ctlen);
    int rr = crypto_aead_decrypt(pt_back, &ptlen, NULL, ct, ctlen, ad3, 4, nonce, key);
    if (rr == 0 && ptlen == 24 && cmp(pt_back, pt, 24)) kprintf("ROUNDTRIP PASS\r\n");
    else { kprintf("ROUNDTRIP FAIL (rr=%d ptlen=%lu)\r\n", rr, (unsigned long)ptlen); fails++; }

    /* ascon_hmac consistency test: known key + msg, hex of MAC output.
     * Compare against host-computed reference (printed in this same format). */
    uint8_t hk[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    uint8_t hm[12] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                      0x01,0x02,0x03,0x04};
    uint8_t mac[32];
    ascon_hmac(hk, 16, hm, 12, mac);
    print_hex("HMAC tgt", mac, 32);
    uart_settle();

    kprintf("=== TOTAL: %d failure(s) ===\r\n", fails);
    while (1) {}
    return 0;
}
