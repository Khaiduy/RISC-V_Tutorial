/*
 * ascon_hash256_rv32.c — Ascon-Hash256 (crypto_hash) over the shared asm
 * permutation. Algorithmically byte-identical to the ascon-c ref hash, except
 * the 12-round permutation P12() is replaced by ascon_p12() (ascon_p12_rv32.S),
 * which reuses the AEAD's ascon_permute(). One permutation serves both AEAD and
 * Hash — removes the ~618 B duplicate the ref C hash carried.
 *
 * Word convention matches asm_rv32i + ref: each 64-bit Ascon word is split
 * (hi32,lo32) with little-endian byte packing. Provides the same crypto_hash()
 * symbol the legacy crypto wrapper calls for ASCON_HASH_256.
 */
#include <stdint.h>

extern void ascon_p12(uint64_t x[5]);

/* ASCON_HASH_IV: VARIANT=2, PA=12, PB=12, HASH_SIZE*8=256, RATE=8
 * (identical expression to ascon-c ref constants.h). */
#define ASCON_HASH_IV (((uint64_t)2)        | ((uint64_t)12 << 16) | \
                       ((uint64_t)12 << 20) | ((uint64_t)256 << 24) | \
                       ((uint64_t)8 << 40))
#define ASCON_HASH_RATE 8
#define ASCON_HASH_OUTLEN 32

static uint64_t loadbytes(const uint8_t *b, int n)
{
	uint64_t x = 0;
	for (int i = 0; i < n; i++)
		x |= (uint64_t)b[i] << (8 * i);
	return x;
}

static void storebytes(uint8_t *b, uint64_t x, int n)
{
	for (int i = 0; i < n; i++)
		b[i] = (uint8_t)(x >> (8 * i));
}

int crypto_hash(unsigned char *out, const unsigned char *in,
		unsigned long long len)
{
	uint64_t x[5];

	/* initialize */
	x[0] = ASCON_HASH_IV;
	x[1] = 0;
	x[2] = 0;
	x[3] = 0;
	x[4] = 0;
	ascon_p12(x);

	/* absorb full message blocks */
	while (len >= ASCON_HASH_RATE) {
		x[0] ^= loadbytes(in, 8);
		ascon_p12(x);
		in += ASCON_HASH_RATE;
		len -= ASCON_HASH_RATE;
	}
	/* absorb final (partial) block + padding */
	x[0] ^= loadbytes(in, (int)len);
	x[0] ^= (uint64_t)0x01 << (8 * len);
	ascon_p12(x);

	/* squeeze 32-byte digest */
	int outlen = ASCON_HASH_OUTLEN;
	while (outlen > ASCON_HASH_RATE) {
		storebytes(out, x[0], 8);
		ascon_p12(x);
		out += ASCON_HASH_RATE;
		outlen -= ASCON_HASH_RATE;
	}
	storebytes(out, x[0], outlen);

	return 0;
}
