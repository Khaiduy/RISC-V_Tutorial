/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include <string.h>

#include "edhoc.h"

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

#include "common/debug.h"

#ifdef USE_HW_X25519
#define X25519_KEY_SIZE 32
#endif

#ifdef ASCON
/* Ascon-AEAD support (RV32I assembly implementation) */
#include "api.h"  /* Defines CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES */

/* Declare crypto_aead functions from opt32 implementation */
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k);

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k);

/* Wrapper to reduce parameter passing issues on bare-metal RV32I */
static int ascon_decrypt_wrapper(unsigned char* m, unsigned long long* mlen,
                                  const unsigned char* c, unsigned long long clen,
                                  const unsigned char* ad, unsigned long long adlen,
                                  const unsigned char* npub, const unsigned char* k) {
	return crypto_aead_decrypt(m, mlen, NULL, c, clen, ad, adlen, npub, k);
}

/* Ascon-Hash256 (bi32_lowsize) and Ascon-HMAC */
#include "crypto_hash.h"    /* bi32_lowsize crypto_hash() */
#include "ascon_hmac.h"     /* Ascon-HMAC for HKDF */
#endif

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
struct edhoc_mock_cb edhoc_crypto_mock_cb;
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

#ifdef MBEDTLS
/*
IMPORTANT!!!!
make sure MBEDTLS_PSA_CRYPTO_CONFIG is defined in include/mbedtls/mbedtls_config.h


modify setting in include/psa/crypto_config.h 
*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <psa/crypto.h>

#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

#endif

#ifdef COMPACT25519
#include <c25519.h>
#include <edsign.h>
//#include <compact_x25519.h>
#endif

#if defined(MONOCYPHER)
#include <monocypher.h>
#include "optional/monocypher-ed25519.h"
#endif

#ifdef COMPACT25519
#ifdef CURVE25519_DONNA
extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
#endif

#ifdef CURVE25519_DONNA
extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
#endif

#endif

#ifdef TINYCRYPT
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/hmac.h>
// MODIFIED: P-256 ECC removed for Suite 0
// #include <tinycrypt/ecc_dsa.h>
// #include <tinycrypt/ecc_dh.h>
#endif

// MODIFIED: Hardware X25519 accelerator support
#ifdef USE_HW_X25519
// Use existing driver functions
extern void hwx25519_init(void* x25519ctrl, uint64_t scalar[4], uint64_t point_in[4]);
extern void hwx25519_results(void* x25519ctrl, uint64_t* result);

#define X25519_CTRL_ADDR 0x64004000UL

static inline void hw_x25519_compute(const uint8_t *scalar_bytes, 
                                      const uint8_t *point_bytes,
                                      uint8_t *result_bytes)
{
	uint64_t scalar[4], point_in[4], result[4];
	
	// Convert byte arrays to uint64_t arrays (little-endian)
	// X25519 uses little-endian format
	for(int i = 0; i < 4; i++) {
		scalar[i] = 0;
		point_in[i] = 0;
		for(int j = 0; j < 8; j++) {
			scalar[i] |= ((uint64_t)scalar_bytes[i*8 + j]) << (j*8);
			point_in[i] |= ((uint64_t)point_bytes[i*8 + j]) << (j*8);
		}
	}
	
	// Use the driver functions
	hwx25519_init((void*)X25519_CTRL_ADDR, scalar, point_in);
	hwx25519_results((void*)X25519_CTRL_ADDR, result);
	
	// Convert result back to byte array (little-endian)
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 8; j++) {
			result_bytes[i*8 + j] = (uint8_t)(result[i] >> (j*8));
		}
	}
}
#endif // USE_HW_X25519

#ifdef MBEDTLS
#define TRY_EXPECT_PSA(x, expected_result, key_id, err_code)                   \
	do {                                                                   \
		int retval = (int)(x);                                         \
		if ((expected_result) != retval) {                             \
			if (PSA_KEY_HANDLE_INIT != (key_id)) {                 \
				psa_destroy_key(key_id);                       \
			}                                                      \
			handle_external_runtime_error(retval, __FILE__,        \
						      __LINE__);               \
			return err_code;                                       \
		}                                                              \
	} while (0)

/**
 * @brief Decompresses an elliptic curve point. 
 * 
 * 
 * @param grp elliptic curve group point
 * @param input the compressed key
 * @param ilen the lenhgt if the compressed key
 * @param output the uncopressed key
 * @param olen the lenhgt of the output
 * @param osize the actual available size of the out buffer
 * @return 0 on success
 */
static inline int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
					 const unsigned char *input,
					 size_t ilen, unsigned char *output,
					 size_t *olen, size_t osize)
{
	int ret;
	size_t plen;
	mbedtls_mpi r;
	mbedtls_mpi x;
	mbedtls_mpi n;

	plen = mbedtls_mpi_size(&grp->P);

	*olen = 2 * plen + 1;

	if (osize < *olen)
		return (MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

	// output will consist of 0x04|X|Y
	memcpy(output + 1, input, ilen);
	output[0] = 0x04;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&n);

	// x <= input
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input, plen));

	// r = x^2
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

	// r = x^2 + a
	if (grp->A.p == NULL) {
		// Special case where a is -3
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
	} else {
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
	}

	// r = x^3 + ax
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

	// r = x^3 + ax + b
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

	// Calculate square root of r over finite field P:
	//   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

	// n = P + 1
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

	// n = (P + 1) / 4
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

	// r ^ ((P + 1) / 4) (mod p)
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

	// Select solution that has the correct "sign" (equals odd/even solution in finite group)
	if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
		// r = p - r
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
	}

	// y => output
	ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&n);

	return (ret);
}

#endif

#if 0 // DISABLED - P-256 support removed for Suite 0
#ifdef TINYCRYPT
/* Declaration of function from TinyCrypt ecc.c */
uECC_word_t cond_set(uECC_word_t p_true, uECC_word_t p_false,
		     unsigned int cond);

/* From uECC project embedded in TinyCrypt - ecc.c
   BSD-2-Clause license */
static uECC_word_t uECC_vli_add(uECC_word_t *result, const uECC_word_t *left,
				const uECC_word_t *right, wordcount_t num_words)
{
	uECC_word_t carry = 0U;
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		uECC_word_t sum = left[i] + right[i] + carry;
		uECC_word_t val = (sum < left[i]);
		carry = cond_set(val, carry, (sum != left[i]));
		result[i] = sum;
	}
	return carry;
}

/* From uECC project; curve-specific.inc */
/* Calculates EC square root of bignum (Very Large Integer) based on curve */
static void mod_sqrt_default(uECC_word_t *a, uECC_Curve curve)
{
	bitcount_t i;
	uECC_word_t p1[NUM_ECC_WORDS] = { 1 };
	uECC_word_t l_result[NUM_ECC_WORDS] = { 1 };
	wordcount_t num_words = curve->num_words;

	/* When curve->p == 3 (mod 4), we can compute
       sqrt(a) = a^((curve->p + 1) / 4) (mod curve->p). */
	uECC_vli_add(p1, curve->p, p1, num_words); /* p1 = curve_p + 1 */
	for (i = uECC_vli_numBits(p1, num_words) - 1; i > 1; --i) {
		uECC_vli_modMult_fast(l_result, l_result, l_result, curve);
		if (uECC_vli_testBit(p1, i)) {
			uECC_vli_modMult_fast(l_result, l_result, a, curve);
		}
	}
	uECC_vli_set(a, l_result, num_words);
}

/**
 * @brief Decompresses an elliptic curve point. 
 * 
 * 
 * @param compressed the compressed key
 * @param public_key the uncopressed key
 * @param curve elliptic curve group point
 */
/* From uECC project 
   BSD-2-Clause license */
static inline void uECC_decompress(const uint8_t *compressed,
				   uint8_t *public_key, uECC_Curve curve)
{
	uECC_word_t point[NUM_ECC_WORDS * 2];

	uECC_word_t *y = point + curve->num_words;

	uECC_vli_bytesToNative(point, compressed, curve->num_bytes);

	curve->x_side(y, point, curve);
	mod_sqrt_default(y, curve);

	if ((y[0] & 0x01) != (compressed[0] == 0x03)) {
		uECC_vli_sub(y, curve->p, y, curve->num_words);
	}

	uECC_vli_nativeToBytes(public_key, curve->num_bytes, point);
	uECC_vli_nativeToBytes(public_key + curve->num_bytes, curve->num_bytes,
			       y);
}
#endif
#endif // End DISABLED - P-256 support removed

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
static bool
aead_mock_args_match_predefined(struct edhoc_mock_aead_in_out *predefined,
				const uint8_t *key, const uint16_t key_len,
				uint8_t *nonce, const uint16_t nonce_len,
				const uint8_t *aad, const uint16_t aad_len,
				uint8_t *tag, const uint16_t tag_len)
{
	return array_equals(&predefined->key,
			    &(struct byte_array){ .ptr = (void *)key,
						  .len = key_len }) &&
	       array_equals(&predefined->nonce,
			    &(struct byte_array){ .ptr = nonce,
						  .len = nonce_len }) &&
	       array_equals(&predefined->aad,
			    &(struct byte_array){ .ptr = (void *)aad,
						  .len = aad_len }) &&
	       array_equals(&predefined->tag,
			    &(struct byte_array){ .ptr = tag, .len = tag_len });
}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
	for (uint32_t i = 0; i < edhoc_crypto_mock_cb.aead_in_out_count; i++) {
		struct edhoc_mock_aead_in_out *predefined_in_out =
			edhoc_crypto_mock_cb.aead_in_out + i;
		if (aead_mock_args_match_predefined(
			    predefined_in_out, key->ptr, key->len, nonce->ptr,
			    nonce->len, aad->ptr, aad->len, tag->ptr,
			    tag->len)) {
			memcpy(out->ptr, predefined_in_out->out.ptr,
			       predefined_in_out->out.len);
			return ok;
		}
	}
	// if no mocked data has been found - continue with normal aead
#endif

#if defined(ASCON)
	/* Ascon-AEAD-128 backend (opt32 C implementation for debugging) */
#ifdef DEBUG_PRINT
	kprintf("\r\n[CRYPTO] Using ASCON-AEAD-128 (opt32 C)\r\n");
	PRINT_ARRAY("[ASCON] Key", key->ptr, key->len);
	PRINT_ARRAY("[ASCON] Nonce", nonce->ptr, nonce->len);
#endif
	
	if (key->len != 16) {
		kprintf("[ASCON] ERROR: Key must be 16 bytes, got %d\r\n", key->len);
		return unexpected_result_from_ext_lib;
	}
	if (nonce->len != 16) {
		kprintf("[ASCON] ERROR: Nonce must be 16 bytes, got %d\r\n", nonce->len);
		return unexpected_result_from_ext_lib;
	}
	if (tag->len != 16) {
		kprintf("[ASCON] ERROR: Tag must be 16 bytes, got %d\r\n", tag->len);
		return unexpected_result_from_ext_lib;
	}

	if (op == DECRYPT) {
#ifdef DEBUG_PRINT
		kprintf("[ASCON] DECRYPT: ciphertext+tag_len=%d, aad_len=%d\r\n",
		        in->len, aad->len);
		PRINT_ARRAY("[ASCON-DEC] Ciphertext+Tag", in->ptr, in->len);
		PRINT_ARRAY("[ASCON-DEC] AAD", aad->ptr, aad->len);
		kprintf("[ASCON] About to call crypto_aead_decrypt()...\r\n");
#endif
		/* crypto_aead_decrypt expects ciphertext+tag concatenated */
		unsigned long long mlen;
		int result = ascon_decrypt_wrapper(out->ptr, &mlen,
		                                    in->ptr, in->len,
		                                    aad->ptr, aad->len,
		                                    nonce->ptr, key->ptr);
#ifdef DEBUG_PRINT
		kprintf("[ASCON] crypto_aead_decrypt returned: %d (0=success), mlen=%llu\r\n", result, mlen);
		if (result == 0 && mlen > 0) {
			PRINT_ARRAY("[ASCON-DEC] Decrypted plaintext", out->ptr, (uint32_t)mlen);
		}
#endif
		TRY_EXPECT(result, 0);  /* Ascon returns 0 on success */

	} else {
#ifdef DEBUG_PRINT
		kprintf("[ASCON] ENCRYPT: plaintext_len=%d, aad_len=%d\r\n",
		        in->len, aad->len);
		PRINT_ARRAY("[ASCON-ENC] Plaintext", in->ptr, in->len);
		PRINT_ARRAY("[ASCON-ENC] AAD", aad->ptr, aad->len);
#endif
		/* crypto_aead_encrypt writes ciphertext+tag concatenated */
		unsigned long long clen;
		int result = crypto_aead_encrypt(out->ptr, &clen, in->ptr, in->len,
		                                 aad->ptr, aad->len, NULL,
		                                 nonce->ptr, key->ptr);
#ifdef DEBUG_PRINT
		kprintf("[ASCON] crypto_aead_encrypt returned: %d (0=success), clen=%llu\r\n", result, clen);
		if (result == 0) {
			PRINT_ARRAY("[ASCON-ENC] Ciphertext+Tag", out->ptr, (uint32_t)clen);
		}
#endif
		TRY_EXPECT(result, 0);  /* Ascon returns 0 on success */
	}
	return ok;

#elif defined(TINYCRYPT)
	struct tc_ccm_mode_struct c;
	struct tc_aes_key_sched_struct sched;
	
#ifdef DEBUG_PRINT
	kprintf("\r\n[CRYPTO] Using AES-CCM (TinyCrypt)\r\n");
	PRINT_ARRAY("[CRYPTO] Key", key->ptr, key->len);
#endif
	TRY_EXPECT(tc_aes128_set_encrypt_key(&sched, key->ptr), 1);
	TRY_EXPECT(tc_ccm_config(&c, &sched, nonce->ptr, nonce->len, tag->len),
		   1);

	if (op == DECRYPT) {
#ifdef DEBUG_PRINT
		kprintf("[CRYPTO] DECRYPT: out_len=%d, aad_len=%d, in_len=%d, tag_len=%d\r\n",
		        out->len, aad->len, in->len, tag->len);
		PRINT_ARRAY("[CRYPTO-DEC] Nonce", nonce->ptr, nonce->len);
		PRINT_ARRAY("[CRYPTO-DEC] Ciphertext+Tag", in->ptr, in->len);
		PRINT_ARRAY("[CRYPTO-DEC] AAD", aad->ptr, aad->len);
		kprintf("[CRYPTO] TinyCrypt will decrypt %d bytes, verify tag from in[%d...%d]\r\n",
		        in->len - tag->len, in->len - tag->len, in->len);
#endif
		int result = tc_ccm_decryption_verification(out->ptr, out->len,
							  aad->ptr, aad->len,
							  in->ptr, in->len, &c);
#ifdef DEBUG_PRINT
		kprintf("[CRYPTO] tc_ccm_decryption_verification returned: %d (1=success)\r\n", result);
		if (result == 1 && out->len > 0) {
			PRINT_ARRAY("[CRYPTO-DEC] Decrypted plaintext", out->ptr, out->len);
		}
#endif
		TRY_EXPECT(result, 1);

	} else {
#ifdef DEBUG_PRINT
		kprintf("[CRYPTO] ENCRYPT: in_len=%d, aad_len=%d, tag_len=%d\r\n",
		        in->len, aad->len, tag->len);
		PRINT_ARRAY("[CRYPTO-ENC] Nonce", nonce->ptr, nonce->len);
		PRINT_ARRAY("[CRYPTO-ENC] Plaintext", in->ptr, in->len);
		PRINT_ARRAY("[CRYPTO-ENC] AAD", aad->ptr, aad->len);
		kprintf("[CRYPTO] Output buffer size: %d (should be >= %d)\r\n",
		        (out->len + tag->len), (in->len + tag->len));
#endif
		int result = tc_ccm_generation_encryption(
				   out->ptr, (out->len + tag->len), aad->ptr,
				   aad->len, in->ptr, in->len, &c);
#ifdef DEBUG_PRINT
		kprintf("[CRYPTO] tc_ccm_generation_encryption returned: %d (1=success)\r\n", result);
		if (result == 1) {
			PRINT_ARRAY("[CRYPTO-ENC] Ciphertext+Tag", out->ptr, in->len + tag->len);
		}
#endif
		TRY_EXPECT(result, 1);
		memcpy(tag->ptr, out->ptr + out->len, tag->len);
#ifdef DEBUG_PRINT
		kprintf("[CRYPTO] Tag extracted from out[%d...%d]\r\n", out->len, out->len + tag->len);
#endif
	}
#elif defined(MBEDTLS)
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(
		PSA_ALG_CCM, (uint32_t)tag->len);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attr,
				PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, ((size_t)key->len << 3));
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	TRY_EXPECT_PSA(psa_import_key(&attr, key->ptr, key->len, &key_id),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	if (op == DECRYPT) {
		size_t out_len_re = 0;
		TRY_EXPECT_PSA(
			psa_aead_decrypt(key_id, alg, nonce->ptr, nonce->len,
					 aad->ptr, aad->len, in->ptr, in->len,
					 out->ptr, out->len, &out_len_re),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
	} else {
		size_t out_len_re;
		TRY_EXPECT_PSA(
			psa_aead_encrypt(key_id, alg, nonce->ptr, nonce->len,
					 aad->ptr, aad->len, in->ptr, in->len,
					 out->ptr, (size_t)(in->len + tag->len),
					 &out_len_re),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
		memcpy(tag->ptr, out->ptr + out_len_re - tag->len, tag->len);
	}
	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);

#endif
	return ok;
}

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
static bool
sign_mock_args_match_predefined(struct edhoc_mock_sign_in_out *predefined,
				const uint8_t *sk, const size_t sk_len,
				const uint8_t *pk, const size_t pk_len,
				const uint8_t *msg, const size_t msg_len)
{
	return array_equals(&predefined->sk,
			    &(struct byte_array){ .len = sk_len,
						  .ptr = (void *)sk }) &&
	       array_equals(&predefined->pk,
			    &(struct byte_array){ .len = pk_len,
						  .ptr = (void *)pk }) &&
	       array_equals(&predefined->msg,
			    &(struct byte_array){ .len = msg_len,
						  .ptr = (void *)msg });
}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

enum err WEAK sign(enum sign_alg alg, const struct byte_array *sk,
		   const struct byte_array *pk, const struct byte_array *msg,
		   uint8_t *out)
{
	// MODIFIED: Method 3 doesn't use signatures - STUBBED OUT
	(void)alg;
	(void)sk;
	(void)pk;
	(void)msg;
	(void)out;
	return crypto_operation_not_implemented;
	
#if 0 // DISABLED - No signatures in Method 3
#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
	for (uint32_t i = 0; i < edhoc_crypto_mock_cb.sign_in_out_count; i++) {
		struct edhoc_mock_sign_in_out *predefined_in_out =
			edhoc_crypto_mock_cb.sign_in_out + i;
		if (sign_mock_args_match_predefined(predefined_in_out, sk->ptr,
						    sk->len, pk->ptr, PK_SIZE,
						    msg->ptr, msg->len)) {
			memcpy(out, predefined_in_out->out.ptr,
			       predefined_in_out->out.len);
			return ok;
		}
	}
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

	if (alg == EdDSA) {
#if defined(MONOCYPHER)
                crypto_eddsa_sign(out, sk->ptr, msg->ptr, msg->len);
                return ok;
#elif defined(COMPACT25519)
                edsign_sign(out, pk->ptr, sk->ptr, msg->ptr, msg->len);
                return ok;
#endif
        } else if (alg == ES256) {
#if defined(TINYCRYPT)

		uECC_Curve p256 = uECC_secp256r1();
		struct tc_sha256_state_struct ctx_sha256;
		uint8_t hash[NUM_ECC_BYTES];

		TRY_EXPECT(tc_sha256_init(&ctx_sha256), 1);
		TRY_EXPECT(tc_sha256_update(&ctx_sha256, msg->ptr, msg->len),
			   1);
		TRY_EXPECT(tc_sha256_final(hash, &ctx_sha256), 1);

		TRY_EXPECT(uECC_sign(sk->ptr, hash, NUM_ECC_BYTES, out, p256),
			   TC_CRYPTO_SUCCESS);

		return ok;

#elif defined(MBEDTLS)
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

		psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
		bits = PSA_BYTES_TO_BITS((size_t)sk->len);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_VERIFY_MESSAGE |
						PSA_KEY_USAGE_VERIFY_HASH |
						PSA_KEY_USAGE_SIGN_MESSAGE |
						PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

		TRY_EXPECT_PSA(
			psa_import_key(&attributes, sk->ptr, sk->len, &key_id),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

		size_t signature_length;
		TRY_EXPECT_PSA(psa_sign_message(key_id, psa_alg, msg->ptr,
						msg->len, out, SIGNATURE_SIZE,
						&signature_length),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		TRY_EXPECT_PSA(signature_length, SIGNATURE_SIZE, key_id,
			       sign_failed);
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		return ok;
#endif
	}
	return unsupported_ecdh_curve;
#endif // End DISABLED - No signatures in Method 3
}

enum err WEAK verify(enum sign_alg alg, const struct byte_array *pk,
		     struct const_byte_array *msg, struct const_byte_array *sgn,
		     bool *result)
{
	// MODIFIED: Method 3 doesn't use signatures - STUBBED OUT
	(void)alg;
	(void)pk;
	(void)msg;
	(void)sgn;
	*result = false;
	return crypto_operation_not_implemented;
	
#if 0 // DISABLED - No signatures in Method 3
	if (alg == EdDSA) {
#ifdef COMPACT25519
		int verified =
			edsign_verify(sgn->ptr, pk->ptr, msg->ptr, msg->len);
		if (verified) {
			*result = true;
		} else {
			*result = false;
		}
		return ok;
#endif
	}
	if (alg == ES256) {
#if defined(MBEDTLS)
		psa_status_t status;
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

		psa_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
		bits = PSA_BYTES_TO_BITS(P_256_PRIV_KEY_SIZE);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_VERIFY_MESSAGE |
						PSA_KEY_USAGE_VERIFY_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(
						      PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);
		TRY_EXPECT_PSA(
			psa_import_key(&attributes, pk->ptr, pk->len, &key_id),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

		status = psa_verify_message(key_id, psa_alg, msg->ptr, msg->len,
					    sgn->ptr, sgn->len);
		if (PSA_SUCCESS == status) {
			*result = true;
		} else {
			*result = false;
		}
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		return ok;
#elif defined(TINYCRYPT)
		uECC_Curve p256 = uECC_secp256r1();
		struct tc_sha256_state_struct ctx_sha256;
		uint8_t hash[NUM_ECC_BYTES];
		TRY_EXPECT(tc_sha256_init(&ctx_sha256), 1);
		TRY_EXPECT(tc_sha256_update(&ctx_sha256, msg->ptr, msg->len),
			   1);
		TRY_EXPECT(tc_sha256_final(hash, &ctx_sha256), 1);
		uint8_t *pk_ptr = pk->ptr;
		if ((P_256_PUB_KEY_UNCOMPRESSED_SIZE == pk->len) &&
		    (0x04 == *pk->ptr)) {
			pk_ptr++;
		}
		TRY_EXPECT(uECC_verify(pk_ptr, hash, NUM_ECC_BYTES, sgn->ptr,
				       p256),
			   1);
		*result = true;
		return ok;
#endif
	}
	return crypto_operation_not_implemented;
#endif // End DISABLED - No signatures in Method 3
}

enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	/*"Note that [RFC5869] specifies that if the salt is not provided, 
	it is set to a string of zeros.  For implementation purposes, 
	not providing the salt is the same as setting the salt to the empty byte 
	string. OSCORE sets the salt default value to empty byte string, which 
	is converted to a string of zeroes (see Section 2.2 of [RFC5869])".*/

#ifdef ASCON
	/* Ascon-HMAC for Suite 2 (Ascon-Hash256) */
	if (alg == ASCON_HASH_256) {
		// PRINTF("[HKDF_EXTRACT] Using Ascon-HMAC\r\n");
		uint8_t zero_salt[32] = { 0 };
		const uint8_t *key;
		unsigned long long key_len;
		
		if (salt->ptr == NULL || salt->len == 0) {
			key = zero_salt;
			key_len = 32;
		} else {
			key = salt->ptr;
			key_len = salt->len;
		}
		// PRINTF("[HKDF_EXTRACT] Calling ascon_hmac...\r\n");
		if (ascon_hmac(key, key_len, ikm->ptr, ikm->len, out) != 0) {
			// PRINTF("[HKDF_EXTRACT] ascon_hmac FAILED!\r\n");
			return hkdf_failed;
		}
		// PRINTF("[HKDF_EXTRACT] ascon_hmac OK\r\n");
		return ok;
	}
#endif

	/* SHA-256 HMAC for Suite 0/1 */
	if (alg != SHA_256) {
		return crypto_operation_not_implemented;
	}
#ifdef TINYCRYPT
	struct tc_hmac_state_struct h;
	memset(&h, 0x00, sizeof(h));
	if (salt->ptr == NULL || salt->len == 0) {
		uint8_t zero_salt[32] = { 0 };
		TRY_EXPECT(tc_hmac_set_key(&h, zero_salt, 32), 1);
	} else {
		TRY_EXPECT(tc_hmac_set_key(&h, salt->ptr, salt->len), 1);
	}
	TRY_EXPECT(tc_hmac_init(&h), 1);
	TRY_EXPECT(tc_hmac_update(&h, ikm->ptr, ikm->len), 1);
	TRY_EXPECT(tc_hmac_final(out, TC_SHA256_DIGEST_SIZE, &h), 1);
#endif
#ifdef MBEDTLS
	psa_algorithm_t psa_alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);

	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, psa_alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

	if (salt->ptr && salt->len) {
		TRY_EXPECT_PSA(
			psa_import_key(&attr, salt->ptr, salt->len, &key_id),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
	} else {
		uint8_t zero_salt[32] = { 0 };

		TRY_EXPECT_PSA(psa_import_key(&attr, zero_salt, 32, &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
	}
	size_t out_len;
	TRY_EXPECT_PSA(psa_mac_compute(key_id, psa_alg, ikm->ptr, ikm->len, out,
				       32, &out_len),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
#endif
	return ok;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
	/* "N = ceil(L/HashLen)" */
	uint32_t iterations = (out->len + 31) / 32;
	/* "L length of output keying material in octets (<= 255*HashLen)"*/
	if (iterations > 255) {
		return hkdf_failed;
	}

#ifdef ASCON
	/* Ascon-HMAC for Suite 2 (Ascon-Hash256) */
	if (alg == ASCON_HASH_256) {
		// PRINTF("[HKDF_EXPAND] Using Ascon-HMAC, iterations=%d\r\n", (int)iterations);
		uint8_t t[32] = { 0 };
		ascon_hmac_state_t h;
		
		for (uint8_t i = 1; i <= iterations; i++) {
			// PRINTF("[HKDF_EXPAND] iter %d: init...\r\n", i);
			if (ascon_hmac_init(&h, prk->ptr, prk->len) != 0) {
				// PRINTF("[HKDF_EXPAND] init FAILED\r\n");
				return hkdf_failed;
			}
			if (i > 1) {
				if (ascon_hmac_update(&h, t, 32) != 0) {
					return hkdf_failed;
				}
			}
			// PRINTF("[HKDF_EXPAND] iter %d: update info...\r\n", i);
			if (ascon_hmac_update(&h, info->ptr, info->len) != 0) {
				return hkdf_failed;
			}
			if (ascon_hmac_update(&h, &i, 1) != 0) {
				return hkdf_failed;
			}
			// PRINTF("[HKDF_EXPAND] iter %d: final...\r\n", i);
			if (ascon_hmac_final(&h, t) != 0) {
				return hkdf_failed;
			}
			if (out->len < i * 32) {
				memcpy(&out->ptr[(i - 1) * 32], t, out->len % 32);
			} else {
				memcpy(&out->ptr[(i - 1) * 32], t, 32);
			}
		}
		// PRINTF("[HKDF_EXPAND] Complete\r\n");
		return ok;
	}
#endif

	/* SHA-256 HMAC for Suite 0/1 */
	if (alg != SHA_256) {
		return crypto_operation_not_implemented;
	}

#ifdef TINYCRYPT
	uint8_t t[32] = { 0 };
	struct tc_hmac_state_struct h;
	for (uint8_t i = 1; i <= iterations; i++) {
		memset(&h, 0x00, sizeof(h));
		TRY_EXPECT(tc_hmac_set_key(&h, prk->ptr, prk->len), 1);
		tc_hmac_init(&h);
		if (i > 1) {
			TRY_EXPECT(tc_hmac_update(&h, t, 32), 1);
		}
		TRY_EXPECT(tc_hmac_update(&h, info->ptr, info->len), 1);
		TRY_EXPECT(tc_hmac_update(&h, &i, 1), 1);
		TRY_EXPECT(tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &h), 1);
		if (out->len < i * 32) {
			memcpy(&out->ptr[(i - 1) * 32], t, out->len % 32);
		} else {
			memcpy(&out->ptr[(i - 1) * 32], t, 32);
		}
	}
#endif
#ifdef MBEDTLS
	psa_status_t status;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
#ifdef DEBUG_PRINT
	// PRINTF("key_id: %d\r\n", key_id);
#endif

	TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
		       unexpected_result_from_ext_lib);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

	// PRINT_ARRAY("PRK:", prk->ptr, prk->len);
	TRY_EXPECT_PSA(psa_import_key(&attr, prk->ptr, prk->len, &key_id),
		       PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);

	size_t combo_len = (32 + (size_t)info->len + 1);

	TRY_EXPECT_PSA(check_buffer_size(INFO_MAX_SIZE + 32 + 1,
					 (uint32_t)combo_len),
		       ok, key_id, unexpected_result_from_ext_lib);

	uint8_t combo[INFO_MAX_SIZE + 32 + 1];
	uint8_t tmp_out[32];
	memset(tmp_out, 0, 32);
	memcpy(combo + 32, info->ptr, info->len);
	size_t offset = 32;
	for (uint32_t i = 1; i <= iterations; i++) {
		memcpy(combo, tmp_out, 32);
		combo[combo_len - 1] = (uint8_t)i;
		size_t tmp_out_len;
		status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
					 combo + offset, combo_len - offset,
					 tmp_out, 32, &tmp_out_len);
		TRY_EXPECT_PSA(status, PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		offset = 0;
		uint8_t *dest = out->ptr + ((i - 1) << 5);
		if (out->len < (uint32_t)(i << 5)) {
			memcpy(dest, tmp_out, out->len & 31);
		} else {
			memcpy(dest, tmp_out, 32);
		}
	}
	TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
#endif
	return ok;
}

enum err WEAK hkdf_sha_256(struct byte_array *master_secret,
			   struct byte_array *master_salt,
			   struct byte_array *info, struct byte_array *out)
{
	BYTE_ARRAY_NEW(prk, HASH_SIZE, HASH_SIZE);
	TRY(hkdf_extract(SHA_256, master_salt, master_secret, prk.ptr));
	TRY(hkdf_expand(SHA_256, &prk, info, out));
	return ok;
}

#ifdef ASCON
enum err WEAK hkdf_ascon(struct byte_array *master_secret,
			 struct byte_array *master_salt,
			 struct byte_array *info, struct byte_array *out)
{
	// PRINTF("[HKDF_ASCON] Starting...\r\n");
	BYTE_ARRAY_NEW(prk, HASH_SIZE, HASH_SIZE);
	// PRINTF("[HKDF_ASCON] Calling hkdf_extract...\r\n");
	TRY(hkdf_extract(ASCON_HASH_256, master_salt, master_secret, prk.ptr));
	// PRINTF("[HKDF_ASCON] hkdf_extract done, calling hkdf_expand...\r\n");
	TRY(hkdf_expand(ASCON_HASH_256, &prk, info, out));
	// PRINTF("[HKDF_ASCON] Complete\r\n");
	return ok;
}
#endif

enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
	// kprintf("[CRYPTO] shared_secret_derive called, alg=%d (X25519=%d)\r\n", alg, X25519);
	if (alg == X25519) {
		// kprintf("[CRYPTO] Algorithm is X25519\r\n");
#ifdef USE_HW_X25519
		// MODIFIED: Use hardware X25519 accelerator
		// kprintf("[CRYPTO] Using HW X25519\r\n");
		hw_x25519_compute(sk->ptr, pk->ptr, shared_secret);
		// kprintf("[CRYPTO] X25519 complete\r\n");
		return ok;
#elif defined(MONOCYPHER)
		crypto_x25519(shared_secret, sk->ptr, pk->ptr);
		return ok;
#elif defined(MONOCYPHER)
		crypto_x25519(shared_secret, sk->ptr, pk->ptr);
		return ok;
#elif defined(COMPACT25519)
		// Software fallback
		// kprintf("[CRYPTO] Using SW X25519 (COMPACT25519)\r\n");
		uint8_t e[F25519_SIZE];
		f25519_copy(e, sk->ptr);
#ifdef CURVE25519_DONNA
e[0] &= 0xf8;
e[31] &= 0x7f;
e[31] |= 0x40;
curve25519_donna(shared_secret, e, pk->ptr);
#else
c25519_prepare(e);
#endif
#ifndef CURVE25519_DONNA
c25519_smult(shared_secret, pk->ptr, e);
#endif
		// kprintf("[CRYPTO] X25519 shared secret computed\r\n");
		return ok;
#else
		// kprintf("[CRYPTO] ERROR: No X25519 implementation available!\r\n");
		return crypto_operation_not_implemented;
#endif
	}
	// kprintf("[CRYPTO] Algorithm is NOT X25519, returning error\r\n");
	// MODIFIED: Suite 0 only uses X25519 - P-256 removed
	if (alg == P256) {
		(void)sk;
		(void)pk;
		(void)shared_secret;
		return crypto_operation_not_implemented;
	}
#if 0 // DISABLED - Suite 0 uses X25519 only
	if (alg == P256) {
#if defined(TINYCRYPT)
		uECC_Curve p256 = uECC_secp256r1();
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		uECC_decompress(pk->ptr, pk_decompressed, p256);

		// PRINT_ARRAY("pk_decompressed", pk_decompressed,
			    2 * P_256_PUB_KEY_X_CORD_SIZE);

		TRY_EXPECT(uECC_shared_secret(pk_decompressed, sk->ptr,
					      shared_secret, p256),
			   1);

		return ok;
#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
		psa_algorithm_t psa_alg;
		size_t bits;
		psa_status_t result = ok;

		psa_alg = PSA_ALG_ECDH;
		bits = PSA_BYTES_TO_BITS(sk->len);

		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, psa_alg);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
						PSA_ECC_FAMILY_SECP_R1));

		TRY_EXPECT_PSA(psa_import_key(&attr, sk->ptr, (size_t)sk->len,
					      &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		psa_key_type_t type = psa_get_key_type(&attr);
		size_t shared_size =
			PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits);

		size_t shared_secret_len = 0;

		size_t pk_decompressed_len;
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		mbedtls_pk_context ctx_verify = { 0 };
		mbedtls_pk_init(&ctx_verify);
		if (PSA_SUCCESS !=
		    mbedtls_pk_setup(&ctx_verify, mbedtls_pk_info_from_type(
							  MBEDTLS_PK_ECKEY))) {
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
		if (PSA_SUCCESS !=
		    mbedtls_ecp_group_load(&mbedtls_pk_ec(ctx_verify)->grp,
					   MBEDTLS_ECP_DP_SECP256R1)) {
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
		if (PSA_SUCCESS !=
		    mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp,
					   pk->ptr, pk->len, pk_decompressed,
					   &pk_decompressed_len,
					   sizeof(pk_decompressed))) {
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}

		// PRINT_ARRAY("pk_decompressed", pk_decompressed,
			    (uint32_t)pk_decompressed_len);

		if (PSA_SUCCESS !=
		    psa_raw_key_agreement(PSA_ALG_ECDH, key_id, pk_decompressed,
					  pk_decompressed_len, shared_secret,
					  shared_size, &shared_secret_len)) {
			result = unexpected_result_from_ext_lib;
			goto cleanup;
		}
	cleanup:
		if (PSA_KEY_HANDLE_INIT != key_id) {
			TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		}
		mbedtls_pk_free(&ctx_verify);
		return result;
#endif
	}
	return crypto_operation_not_implemented;
#endif // End DISABLED - Suite 0 uses X25519 only
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	if (alg == X25519) {
		uint8_t extended_seed[32];
#if defined(TINYCRYPT)
		struct tc_sha256_state_struct s;
		TRY_EXPECT(tc_sha256_init(&s), 1);
		TRY_EXPECT(tc_sha256_update(&s, (uint8_t *)&seed, sizeof(seed)),
			   1);
		TRY_EXPECT(tc_sha256_final(extended_seed, &s),
			   TC_CRYPTO_SUCCESS);
#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */
		size_t length;
		TRY_EXPECT(psa_hash_compute(PSA_ALG_SHA_256, (uint8_t *)&seed,
					    sizeof(seed), extended_seed, HASH_SIZE,
					    &length),
			   0);
		if (length != 32) {
			return sha_failed;
		}
#endif
		
#ifdef USE_HW_X25519
		// MODIFIED: Use hardware X25519 accelerator for key generation
		// X25519 base point
		static const uint8_t base_point[32] = {
			9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};
		
		// kprintf("[CRYPTO] Generating ephemeral X25519 keypair...\r\n");
		// Copy private key (hardware handles clamping)
		memcpy(sk->ptr, extended_seed, 32);
		sk->len = X25519_KEY_SIZE;
		
		// Compute public key with hardware
		hw_x25519_compute(sk->ptr, base_point, pk->ptr);
		pk->len = X25519_KEY_SIZE;
		// kprintf("[CRYPTO] Ephemeral keypair generated\r\n");
#elif defined(MONOCYPHER)
                // Software fallback - Monocypher
                memcpy(sk->ptr, extended_seed, 32);
                sk->ptr[0] &= 0xf8;
                sk->ptr[31] &= 0x7f;
                sk->ptr[31] |= 0x40;
                crypto_x25519_public_key(pk->ptr, sk->ptr);

#elif defined(COMPACT25519)
                // Software fallback
#ifdef CURVE25519_DONNA
const uint8_t basepoint[32] = {9};
memcpy(sk->ptr, extended_seed, 32);
sk->ptr[0] &= 0xf8;
sk->ptr[31] &= 0x7f;
sk->ptr[31] |= 0x40;
curve25519_donna(pk->ptr, sk->ptr, basepoint);
#else
compact_x25519_keygen(sk->ptr, pk->ptr, extended_seed);
#endif
		pk->len = X25519_KEY_SIZE;
		sk->len = X25519_KEY_SIZE;
#else
		return crypto_operation_not_implemented;
#endif
	// MODIFIED: Suite 0 only uses X25519 - P-256 removed  
	} else if (alg == P256) {
		(void)seed;
		(void)sk;
		(void)pk;
		return crypto_operation_not_implemented;
	}
#if 0 // DISABLED - Suite 0 uses X25519 only
	} else if (alg == P256) {
#if defined(TINYCRYPT)
		if (P_256_PUB_KEY_X_CORD_SIZE > pk->len) {
			return buffer_to_small;
		}
		uECC_Curve p256 = uECC_secp256r1();
		uint8_t pk_decompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];
		TRY_EXPECT(uECC_make_key(pk_decompressed, sk->ptr, p256),
			   TC_CRYPTO_SUCCESS);
		TRY(_memcpy_s(pk->ptr, P_256_PUB_KEY_X_CORD_SIZE,
			      pk_decompressed, P_256_PUB_KEY_X_CORD_SIZE));
		pk->len = P_256_PUB_KEY_X_CORD_SIZE;
		return ok;
#elif defined(MBEDTLS) /* TINYCRYPT / MBEDTLS */
		psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_algorithm_t psa_alg = PSA_ALG_ECDH;
		uint8_t priv_key_size = P_256_PRIV_KEY_SIZE;
		size_t bits = PSA_BYTES_TO_BITS((size_t)priv_key_size);
		size_t pub_key_uncompressed_size =
			P_256_PUB_KEY_UNCOMPRESSED_SIZE;
		uint8_t pub_key_uncompressed[P_256_PUB_KEY_UNCOMPRESSED_SIZE];

		if (P_256_PUB_KEY_X_CORD_SIZE > pk->len) {
			return buffer_to_small;
		}
		TRY_EXPECT_PSA(psa_crypto_init(), PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_EXPORT |
						PSA_KEY_USAGE_DERIVE |
						PSA_KEY_USAGE_SIGN_MESSAGE |
						PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes, psa_alg);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);

		TRY_EXPECT_PSA(psa_generate_key(&attributes, &key_id),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);

		size_t key_len = 0;
		size_t public_key_len = 0;

		TRY_EXPECT_PSA(psa_export_key(key_id, sk->ptr, priv_key_size,
					      &key_len),
			       PSA_SUCCESS, key_id,
			       unexpected_result_from_ext_lib);
		TRY_EXPECT_PSA(
			psa_export_public_key(key_id, pub_key_uncompressed,
					      pub_key_uncompressed_size,
					      &public_key_len),
			PSA_SUCCESS, key_id, unexpected_result_from_ext_lib);
		TRY_EXPECT_PSA(public_key_len, P_256_PUB_KEY_UNCOMPRESSED_SIZE,
			       key_id, unexpected_result_from_ext_lib);
		/* Prepare output format - only x parameter */
		memcpy(pk->ptr, (pub_key_uncompressed + 1),
		       P_256_PUB_KEY_X_CORD_SIZE);
		TRY_EXPECT(psa_destroy_key(key_id), PSA_SUCCESS);
		pk->len = P_256_PUB_KEY_X_CORD_SIZE;
#endif
	} else {
		return unsupported_ecdh_curve;
	}
	return ok;
#endif // End DISABLED - Suite 0 uses X25519 only
	return unsupported_ecdh_curve;
}

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
#ifdef ASCON
	/* Ascon-Hash256 for Suite 2 */
	if (alg == ASCON_HASH_256) {
		PRINT_ARRAY("[HASH-IN] Input data", in->ptr, in->len);
		if (crypto_hash(out->ptr, in->ptr, in->len) != 0) {
			return sha_failed;
		}
		out->len = HASH_SIZE;
		PRINT_ARRAY("[HASH-OUT] Output hash", out->ptr, out->len);
		return ok;
	}
#endif

	if (alg == SHA_256) {
#ifdef TINYCRYPT
		struct tc_sha256_state_struct s;
		TRY_EXPECT(tc_sha256_init(&s), 1);
		TRY_EXPECT(tc_sha256_update(&s, in->ptr, in->len), 1);
		TRY_EXPECT(tc_sha256_final(out->ptr, &s), 1);
		out->len = HASH_SIZE;
		return ok;
#endif
#ifdef MBEDTLS
		size_t length;
		TRY_EXPECT(psa_hash_compute(PSA_ALG_SHA_256, in->ptr, in->len,
					    out->ptr, HASH_SIZE, &length),
			   PSA_SUCCESS);
		if (length != HASH_SIZE) {
			return sha_failed;
		}
		out->len = HASH_SIZE;
		// PRINT_ARRAY("hash", out->ptr, out->len);
		return ok;
#endif
	}

	return crypto_operation_not_implemented;
}

