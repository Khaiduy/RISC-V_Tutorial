/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
/* This file is the wolfSSL-backed crypto wrapper. A parallel file
 * crypto_wrapper_legacy.c provides the Monocypher + TinyCrypt + Ascon-c
 * backends for Suites 0/1/4/5/7 + PSK. The Makefile picks one backend per
 * build via -DWOLFCRYPT or -DMONOCYPHER -DTINYCRYPT. The outer guard below
 * leaves this file empty when the legacy backend is selected so symbols
 * don't collide at link time. */
#ifdef WOLFCRYPT

#include <string.h>

#include "edhoc.h"

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
struct edhoc_mock_cb edhoc_crypto_mock_cb;
#endif

#ifdef COMPACT25519
#include <c25519.h>
#include <edsign.h>
#endif

#ifdef WOLFCRYPT
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#if EDHOC_CRYPTO_SUITE == 25
#include <wolfssl/wolfcrypt/kmac.h>
#endif
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve448.h>
/* wolfssl/wolfcrypt/ed448.h defines enum { Ed448=0, Ed448ph=1 } which
 * conflicts with our sign_alg.Ed448=-49.  Rename it during include. */
#define Ed448 wc_Ed448HashType
#include <wolfssl/wolfcrypt/ed448.h>
#undef Ed448
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#endif
#endif /* WOLFCRYPT */

#ifdef WOLFCRYPT
/* Compile-time suite classification — mirrors edhoc_suite_defs.h.
 * Guards below prevent dead ECC/Ed448/hash branches from being compiled,
 * allowing --gc-sections to remove unreferenced wolfCrypt code. */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || EDHOC_CRYPTO_SUITE == 5
#  define _SUITE_USES_P256 1   /* P-256 for ECDH */
#else
#  define _SUITE_USES_P256 0
#endif
#if EDHOC_CRYPTO_SUITE == 24
#  define _SUITE_USES_P384 1
#else
#  define _SUITE_USES_P384 0
#endif
#if EDHOC_CRYPTO_SUITE == 25
#  define _SUITE_USES_X448 1
#else
#  define _SUITE_USES_X448 0
#endif
/* ES256 for signing — Suites 2/3/5 (with P-256 ECDH) and Suite 6 (with X25519 ECDH).
 * Per RFC 9528 Table 6, Suite 6 is the mixed case. */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6
#  define _SUITE_USES_ES256 1
#else
#  define _SUITE_USES_ES256 0
#endif
#define _SUITE_USES_ECC (_SUITE_USES_P256 || _SUITE_USES_P384 || _SUITE_USES_ES256)
#endif /* WOLFCRYPT */

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
#endif /* EDHOC_MOCK_CRYPTO_WRAPPER */

#if defined(WOLFCRYPT) && defined(HAVE_ASCON)
/* HMAC using Ascon-Hash256: H(k XOR opad || H(k XOR ipad || data1 || data2)) */
static void ascon_hmac(const uint8_t *key, word32 key_len,
		       const uint8_t *data1, word32 data1_len,
		       const uint8_t *data2, word32 data2_len,
		       uint8_t *out)
{
	wc_AsconHash256 h;
	uint8_t k_pad[32];
	uint8_t i_key_pad[32];
	uint8_t o_key_pad[32];
	uint8_t inner[32];
	word32 i;

	memset(k_pad, 0, 32);
	if (key_len > 32) {
		wc_AsconHash256_Init(&h);
		wc_AsconHash256_Update(&h, key, key_len);
		wc_AsconHash256_Final(&h, k_pad);
	} else {
		memcpy(k_pad, key, key_len);
	}

	for (i = 0; i < 32; i++) {
		i_key_pad[i] = k_pad[i] ^ 0x36;
		o_key_pad[i] = k_pad[i] ^ 0x5c;
	}

	wc_AsconHash256_Init(&h);
	wc_AsconHash256_Update(&h, i_key_pad, 32);
	if (data1 && data1_len)
		wc_AsconHash256_Update(&h, data1, data1_len);
	if (data2 && data2_len)
		wc_AsconHash256_Update(&h, data2, data2_len);
	wc_AsconHash256_Final(&h, inner);

	wc_AsconHash256_Init(&h);
	wc_AsconHash256_Update(&h, o_key_pad, 32);
	wc_AsconHash256_Update(&h, inner, 32);
	wc_AsconHash256_Final(&h, out);
}
#endif /* WOLFCRYPT && HAVE_ASCON */

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
#endif

#ifdef WOLFCRYPT
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3
	{
		/* AES-CCM: key=16, nonce=13, tag=8 (suite 0/2) or 16 (suite 1/3) */
		Aes aes;
		int r = wc_AesInit(&aes, NULL, INVALID_DEVID);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		r = wc_AesCcmSetKey(&aes, key->ptr, key->len);
		if (r != 0) {
			wc_AesFree(&aes);
			return unexpected_result_from_ext_lib;
		}
		if (op == DECRYPT) {
			uint32_t ct_len = in->len - tag->len;
			r = wc_AesCcmDecrypt(&aes, out->ptr, in->ptr,
					    ct_len, nonce->ptr, nonce->len,
					    in->ptr + ct_len, tag->len,
					    aad->ptr, aad->len);
			wc_AesFree(&aes);
			if (r != 0)
				return mac_authentication_failed;
		} else {
			r = wc_AesCcmEncrypt(&aes, out->ptr, in->ptr, in->len,
					    nonce->ptr, nonce->len,
					    tag->ptr, tag->len,
					    aad->ptr, aad->len);
			wc_AesFree(&aes);
			if (r != 0)
				return unexpected_result_from_ext_lib;
		}
		return ok;
	}
#elif EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 5 || \
      EDHOC_CRYPTO_SUITE == 25
	{
		/* ChaCha20/Poly1305: key=32, nonce=12, tag=16 */
		if (op == DECRYPT) {
			uint32_t ct_len =
				in->len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
			if (wc_ChaCha20Poly1305_Decrypt(
				    key->ptr, nonce->ptr,
				    aad->ptr, aad->len,
				    in->ptr, ct_len,
				    in->ptr + ct_len, out->ptr) != 0)
				return mac_authentication_failed;
		} else {
			if (wc_ChaCha20Poly1305_Encrypt(
				    key->ptr, nonce->ptr, aad->ptr, aad->len,
				    in->ptr, in->len, out->ptr, tag->ptr) != 0)
				return unexpected_result_from_ext_lib;
		}
		return ok;
	}
#elif EDHOC_CRYPTO_SUITE == 6 || EDHOC_CRYPTO_SUITE == 24
	{
		/* AES-GCM: key=16 (suite 6) or 32 (suite 24), nonce=12, tag=16 */
		Aes aes;
		int r = wc_AesInit(&aes, NULL, INVALID_DEVID);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		r = wc_AesGcmSetKey(&aes, key->ptr, key->len);
		if (r != 0) {
			wc_AesFree(&aes);
			return unexpected_result_from_ext_lib;
		}
		if (op == DECRYPT) {
			uint32_t ct_len = in->len - tag->len;
			r = wc_AesGcmDecrypt(&aes, out->ptr, in->ptr, ct_len,
					     nonce->ptr, nonce->len,
					     in->ptr + ct_len, tag->len,
					     aad->ptr, aad->len);
			wc_AesFree(&aes);
			if (r != 0)
				return mac_authentication_failed;
		} else {
			r = wc_AesGcmEncrypt(&aes, out->ptr, in->ptr, in->len,
					     nonce->ptr, nonce->len,
					     tag->ptr, tag->len,
					     aad->ptr, aad->len);
			wc_AesFree(&aes);
			if (r != 0)
				return unexpected_result_from_ext_lib;
		}
		return ok;
	}
#elif EDHOC_CRYPTO_SUITE == 7 && defined(HAVE_ASCON)
	{
		/* Ascon-AEAD-128: key=16, nonce=16, tag=16 */
		wc_AsconAEAD128 ascon;
		int r = wc_AsconAEAD128_Init(&ascon);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		r = wc_AsconAEAD128_SetKey(&ascon, key->ptr);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		r = wc_AsconAEAD128_SetNonce(&ascon, nonce->ptr);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		r = wc_AsconAEAD128_SetAD(&ascon, aad->ptr, aad->len);
		if (r != 0)
			return unexpected_result_from_ext_lib;

		if (op == DECRYPT) {
			uint32_t ct_len = in->len - tag->len;
			r = wc_AsconAEAD128_DecryptUpdate(&ascon, out->ptr,
							 in->ptr, ct_len);
			if (r != 0)
				return unexpected_result_from_ext_lib;

			if (wc_AsconAEAD128_DecryptFinal(&ascon,
							 in->ptr + ct_len) != 0)
				return mac_authentication_failed;
		} else {
			r = wc_AsconAEAD128_EncryptUpdate(&ascon, out->ptr,
							 in->ptr, in->len);
			if (r != 0)
				return unexpected_result_from_ext_lib;

			r = wc_AsconAEAD128_EncryptFinal(&ascon, tag->ptr);
			if (r != 0)
				return unexpected_result_from_ext_lib;
		}
		return ok;
	}
#endif
#endif /* WOLFCRYPT */
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
#endif /* EDHOC_MOCK_CRYPTO_WRAPPER */

enum err WEAK sign(enum sign_alg alg, const struct byte_array *sk,
		   const struct byte_array *pk, const struct byte_array *msg,
		   uint8_t *out)
{
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
#endif

#ifdef COMPACT25519
	if (alg == EdDSA) {
		edsign_sign(out, pk->ptr, sk->ptr, msg->ptr, msg->len);
		return ok;
	}
#endif

#ifdef WOLFCRYPT
#ifdef HAVE_ED25519_SIGN
	if (alg == EdDSA) {
		/* sk->ptr[0..31] = 32-byte seed; pk->ptr = 32-byte public key */
		ed25519_key key;
		word32 sig_len = 64;
		wc_ed25519_init(&key);
		wc_ed25519_import_private_key(sk->ptr, 32, pk->ptr, pk->len,
					      &key);
		wc_ed25519_sign_msg(msg->ptr, msg->len, out, &sig_len, &key);
		wc_ed25519_free(&key);
		return ok;
	}
#endif /* HAVE_ED25519_SIGN */
#if _SUITE_USES_ES256 && defined(HAVE_ECC_SIGN)
	if (alg == ES256) {
		/* sp_ecc_sign_256 is LTO-eliminated when called indirectly through
		 * wc_ecc_sign_hash_ex.  Declare and call it directly so the linker
		 * sees a live reference and keeps the symbol (and its callees). */
		extern int sp_ecc_sign_256(const byte* hash, word32 hashLen,
		    WC_RNG* rng, const mp_int* priv, mp_int* rm, mp_int* sm,
		    mp_int* km, void* heap);

		ecc_key wc_key;
		mp_int r, s;
		WC_RNG rng;
		byte hash[32];
		wc_ecc_init(&wc_key);
		wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
					     &wc_key, ECC_SECP256R1);
		wc_Sha256Hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		wc_InitRng(&rng);
		sp_ecc_sign_256(hash, 32, &rng, wc_key.k, &r, &s, NULL, wc_key.heap);
		wc_FreeRng(&rng);
		mp_to_unsigned_bin_len(&r, out, 32);
		mp_to_unsigned_bin_len(&s, out + 32, 32);
		mp_clear(&r);
		mp_clear(&s);
		wc_ecc_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_ES256 && HAVE_ECC_SIGN */
#if _SUITE_USES_P384 && defined(HAVE_ECC_SIGN)
	if (alg == ES384) {
		ecc_key wc_key;
		mp_int r, s;
		WC_RNG rng;
		byte hash[48];
		wc_ecc_init(&wc_key);
		wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
					     &wc_key, ECC_SECP384R1);
		wc_Sha384Hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		wc_InitRng(&rng);
		wc_ecc_sign_hash_ex(hash, 48, &rng, &wc_key, &r, &s);
		wc_FreeRng(&rng);
		mp_to_unsigned_bin_len(&r, out, 48);
		mp_to_unsigned_bin_len(&s, out + 48, 48);
		mp_clear(&r);
		mp_clear(&s);
		wc_ecc_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_P384 && HAVE_ECC_SIGN */
#if _SUITE_USES_X448 && defined(HAVE_ED448) && !defined(NO_ED448_SIGN)
	if (alg == Ed448) {
		ed448_key wc_key;
		word32 sig_len = 114;
		wc_ed448_init(&wc_key);
		wc_ed448_import_private_key(sk->ptr, sk->len,
					    pk->ptr, pk->len, &wc_key);
		wc_ed448_sign_msg(msg->ptr, msg->len, out, &sig_len,
				  &wc_key, NULL, 0);
		wc_ed448_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 && !NO_ED448_SIGN */
#endif /* WOLFCRYPT */
	return unsupported_ecdh_curve;
}

enum err WEAK verify(enum sign_alg alg, const struct byte_array *pk,
		     struct const_byte_array *msg, struct const_byte_array *sgn,
		     bool *result)
{
#ifdef COMPACT25519
	if (alg == EdDSA) {
		int verified =
			edsign_verify(sgn->ptr, pk->ptr, msg->ptr, msg->len);
		*result = (verified != 0);
		return ok;
	}
#endif

#ifdef WOLFCRYPT
#if defined(HAVE_ED25519) && !defined(NO_ED25519_VERIFY)
	if (alg == EdDSA) {
		ed25519_key key;
		int verified = 0;
		wc_ed25519_init(&key);
		wc_ed25519_import_public(pk->ptr, pk->len, &key);
		wc_ed25519_verify_msg(sgn->ptr, sgn->len, msg->ptr, msg->len,
				      &verified, &key);
		*result = (verified == 1);
		wc_ed25519_free(&key);
		return ok;
	}
#endif /* HAVE_ED25519 && !NO_ED25519_VERIFY */
#if _SUITE_USES_ES256 && defined(HAVE_ECC_VERIFY)
	if (alg == ES256) {
		/* CCS credentials store only X — try Y=even (0x02), fall back to Y=odd (0x03). */
		ecc_key wc_key;
		mp_int r, s;
		byte hash[32];
		byte compressed[33];
		int stat = 0;
		wc_Sha256Hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		mp_read_unsigned_bin(&r, sgn->ptr, 32);
		mp_read_unsigned_bin(&s, sgn->ptr + 32, 32);
		memcpy(compressed + 1, pk->ptr, 32);
		for (int parity = 0; parity < 2 && stat != 1; parity++) {
			compressed[0] = (parity == 0) ? 0x02 : 0x03;
			wc_ecc_init(&wc_key);
			if (wc_ecc_import_x963_ex(compressed, 33, &wc_key,
						  ECC_SECP256R1) == 0) {
				wc_ecc_verify_hash_ex(&r, &s, hash, 32, &stat,
						      &wc_key);
			}
			wc_ecc_free(&wc_key);
		}
		*result = (stat == 1);
		mp_clear(&r);
		mp_clear(&s);
		return ok;
	}
#endif /* _SUITE_USES_ES256 && HAVE_ECC_VERIFY */
#if _SUITE_USES_P384 && defined(HAVE_ECC_VERIFY)
	if (alg == ES384) {
		/* CCS credentials store only X — try Y=even (0x02), fall back to Y=odd (0x03). */
		ecc_key wc_key;
		mp_int r, s;
		byte hash[48];
		byte compressed[49];
		int stat = 0;
		wc_Sha384Hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		mp_read_unsigned_bin(&r, sgn->ptr, 48);
		mp_read_unsigned_bin(&s, sgn->ptr + 48, 48);
		memcpy(compressed + 1, pk->ptr, 48);
		for (int parity = 0; parity < 2 && stat != 1; parity++) {
			compressed[0] = (parity == 0) ? 0x02 : 0x03;
			wc_ecc_init(&wc_key);
			if (wc_ecc_import_x963_ex(compressed, 49, &wc_key,
						  ECC_SECP384R1) == 0) {
				wc_ecc_verify_hash_ex(&r, &s, hash, 48, &stat,
						      &wc_key);
			}
			wc_ecc_free(&wc_key);
		}
		*result = (stat == 1);
		mp_clear(&r);
		mp_clear(&s);
		return ok;
	}
#endif /* _SUITE_USES_P384 && HAVE_ECC_VERIFY */
#if _SUITE_USES_X448 && defined(HAVE_ED448) && !defined(NO_ED448_VERIFY)
	if (alg == Ed448) {
		ed448_key wc_key;
		int verified = 0;
		wc_ed448_init(&wc_key);
		wc_ed448_import_public(pk->ptr, pk->len, &wc_key);
		wc_ed448_verify_msg(sgn->ptr, sgn->len,
				    msg->ptr, msg->len,
				    &verified, &wc_key, NULL, 0);
		*result = (verified == 1);
		wc_ed448_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 && !NO_ED448_VERIFY */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	/*"Note that [RFC5869] specifies that if the salt is not provided,
	it is set to a string of zeros.  For implementation purposes,
	not providing the salt is the same as setting the salt to the empty byte
	string. OSCORE sets the salt default value to empty byte string, which
	is converted to a string of zeroes (see Section 2.2 of [RFC5869])".*/

#ifdef WOLFCRYPT
	if (alg == SHA_256) {
		uint8_t zero_salt[32] = { 0 };
		const uint8_t *s =
			(salt->ptr && salt->len) ? salt->ptr : zero_salt;
		word32 s_len = (salt->ptr && salt->len) ?
				       (word32)salt->len : 32;
		if (wc_HKDF_Extract(WC_SHA256, s, s_len,
				    ikm->ptr, ikm->len, out) != 0)
			return hkdf_failed;
		return ok;
	}
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384) {
		uint8_t zero_salt[48] = { 0 };
		const uint8_t *s =
			(salt->ptr && salt->len) ? salt->ptr : zero_salt;
		word32 s_len = (salt->ptr && salt->len) ?
				       (word32)salt->len : 48;
		if (wc_HKDF_Extract(WC_SHA384, s, s_len,
				    ikm->ptr, ikm->len, out) != 0)
			return hkdf_failed;
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 24 */
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		/* RFC 9528 §4.1.1: EDHOC_Extract(salt, IKM) = KMAC256(salt, IKM, 512, "")
		 * Output length = 64 bytes (512 bits). */
		Kmac kmac;
		uint8_t zero_salt[64] = { 0 };
		const uint8_t *s =
			(salt->ptr && salt->len) ? salt->ptr : zero_salt;
		word32 s_len = (salt->ptr && salt->len) ?
				       (word32)salt->len : 64;
		if (wc_InitKmac(&kmac, WC_KMAC_256, s, s_len,
				NULL, 0, NULL, INVALID_DEVID) != 0)
			return hkdf_failed;
		if (wc_KmacUpdate(&kmac, ikm->ptr, ikm->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		if (wc_KmacFinal(&kmac, out, 64) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		wc_KmacFree(&kmac);
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH256) {
		/* HKDF-Extract: PRK = HMAC-Ascon(salt, IKM) */
		uint8_t zero_salt[32] = { 0 };
		const uint8_t *s =
			(salt->ptr && salt->len) ? salt->ptr : zero_salt;
		word32 s_len = (salt->ptr && salt->len) ?
				       (word32)salt->len : 32;
		ascon_hmac(s, s_len, ikm->ptr, ikm->len, NULL, 0, out);
		return ok;
	}
#endif /* HAVE_ASCON */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
#ifdef WOLFCRYPT
	if (alg == SHA_256) {
		if (wc_HKDF_Expand(WC_SHA256, prk->ptr, prk->len,
				   info->ptr, info->len,
				   out->ptr, out->len) != 0)
			return hkdf_failed;
		return ok;
	}
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384) {
		if (wc_HKDF_Expand(WC_SHA384, prk->ptr, prk->len,
				   info->ptr, info->len,
				   out->ptr, out->len) != 0)
			return hkdf_failed;
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 24 */
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		/* RFC 9528 §4.1.2: EDHOC_Expand(PRK, info, length) = KMAC256(PRK, info, 8*length, "")
		 * KMAC supplies the exact requested output length directly — no expand loop. */
		Kmac kmac;
		if (wc_InitKmac(&kmac, WC_KMAC_256, prk->ptr, prk->len,
				NULL, 0, NULL, INVALID_DEVID) != 0)
			return hkdf_failed;
		if (wc_KmacUpdate(&kmac, info->ptr, info->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		if (wc_KmacFinal(&kmac, out->ptr, out->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		wc_KmacFree(&kmac);
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH256) {
		/* Manual HKDF-Expand with HMAC-Ascon (hash_len=32) */
		uint32_t hash_len = 32;
		uint32_t iterations = (out->len + hash_len - 1) / hash_len;
		if (iterations > 255)
			return hkdf_failed;
		uint8_t t[32] = { 0 };
		/* concat buffer: T(i-1)[32] + info[?] + counter[1] — max 288 bytes */
		uint8_t concat[32 + 256 + 1];
		for (uint8_t i = 1; i <= iterations; i++) {
			word32 concat_len = 0;
			if (i > 1) {
				memcpy(concat, t, 32);
				concat_len += 32;
			}
			if (info->len <= 256) {
				memcpy(concat + concat_len, info->ptr, info->len);
				concat_len += info->len;
			}
			concat[concat_len++] = i;
			ascon_hmac(prk->ptr, prk->len,
				   concat, concat_len, NULL, 0, t);
			uint32_t copy = (out->len < (uint32_t)i * hash_len) ?
					(out->len % hash_len) : hash_len;
			if (copy == 0)
				copy = hash_len;
			memcpy(&out->ptr[(i - 1) * hash_len], t, copy);
		}
		return ok;
	}
#endif /* HAVE_ASCON */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
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

enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
#ifdef COMPACT25519
	if (alg == X25519) {
		uint8_t e[F25519_SIZE];
		f25519_copy(e, sk->ptr);
		c25519_prepare(e);
		c25519_smult(shared_secret, pk->ptr, e);
		return ok;
	}
#endif

#ifdef WOLFCRYPT
#ifdef HAVE_CURVE25519
	if (alg == X25519) {
		curve25519_key priv_key, pub_key;
		word32 secret_len = 32;
		wc_curve25519_init(&priv_key);
		wc_curve25519_init(&pub_key);
		wc_curve25519_import_private_ex(sk->ptr, sk->len, &priv_key,
						EC25519_LITTLE_ENDIAN);
		wc_curve25519_import_public_ex(pk->ptr, pk->len, &pub_key,
					       EC25519_LITTLE_ENDIAN);
		wc_curve25519_shared_secret_ex(&priv_key, &pub_key,
					       shared_secret, &secret_len,
					       EC25519_LITTLE_ENDIAN);
		wc_curve25519_free(&priv_key);
		wc_curve25519_free(&pub_key);
		return ok;
	}
#endif /* HAVE_CURVE25519 */
#if _SUITE_USES_P256
	if (alg == P256) {
		ecc_key priv_key, pub_key;
		byte compressed[33];
		word32 secret_len = 32;
		WC_RNG rng;
		compressed[0] = 0x02;
		memcpy(compressed + 1, pk->ptr, 32);
		wc_ecc_init(&priv_key);
		wc_ecc_init(&pub_key);
		wc_InitRng(&rng);
		wc_ecc_set_rng(&priv_key, &rng);
		wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
					     &priv_key, ECC_SECP256R1);
		wc_ecc_import_x963_ex(compressed, 33, &pub_key, ECC_SECP256R1);
		wc_ecc_shared_secret(&priv_key, &pub_key,
				     shared_secret, &secret_len);
		wc_FreeRng(&rng);
		wc_ecc_free(&priv_key);
		wc_ecc_free(&pub_key);
		return ok;
	}
#endif /* _SUITE_USES_P256 */
#if _SUITE_USES_P384
	if (alg == P384) {
		ecc_key priv_key, pub_key;
		byte compressed[49];
		word32 secret_len = 48;
		WC_RNG rng;
		int r384;
		compressed[0] = 0x02;
		memcpy(compressed + 1, pk->ptr, 48);
		wc_ecc_init(&priv_key);
		wc_ecc_init(&pub_key);
		wc_InitRng(&rng);
		wc_ecc_set_rng(&priv_key, &rng);
		r384 = wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
						    &priv_key, ECC_SECP384R1);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_import_sk)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_import_x963_ex(compressed, 49, &pub_key, ECC_SECP384R1);
		if (r384 != 0) {
			/* Try odd-Y prefix — shared secret X-coord is the same either way */
			compressed[0] = 0x03;
			r384 = wc_ecc_import_x963_ex(compressed, 49, &pub_key, ECC_SECP384R1);
		}
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_import_pk)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_shared_secret(&priv_key, &pub_key,
					    shared_secret, &secret_len);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_ecdh)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		wc_FreeRng(&rng);
		wc_ecc_free(&priv_key);
		wc_ecc_free(&pub_key);
		return ok;
	}
#endif /* _SUITE_USES_P384 */
#if _SUITE_USES_X448
	if (alg == X448) {
		curve448_key priv_key, pub_key;
		word32 secret_len = 56;
		wc_curve448_init(&priv_key);
		wc_curve448_init(&pub_key);
		wc_curve448_import_private_ex(sk->ptr, sk->len, &priv_key,
					      EC448_LITTLE_ENDIAN);
		wc_curve448_import_public_ex(pk->ptr, pk->len, &pub_key,
					     EC448_LITTLE_ENDIAN);
		wc_curve448_shared_secret_ex(&priv_key, &pub_key,
					     shared_secret, &secret_len,
					     EC448_LITTLE_ENDIAN);
		wc_curve448_free(&priv_key);
		wc_curve448_free(&pub_key);
		return ok;
	}
#endif /* _SUITE_USES_X448 */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	(void)seed; /* seed no longer used — callers pre-fill sk->ptr */

	if (alg == X25519) {
		/* sk->ptr pre-filled with 32 bytes of CSPRNG output; apply clamping */
		sk->ptr[0] &= 0xf8;
		sk->ptr[31] &= 0x7f;
		sk->ptr[31] |= 0x40;
#ifdef COMPACT25519
		c25519_smult(pk->ptr, c25519_base_x, sk->ptr);
		pk->len = 32;
		sk->len = 32;
		return ok;
#elif defined(WOLFCRYPT) && defined(HAVE_CURVE25519)
		{
			curve25519_key key;
			word32 pk_len = 32;
			wc_curve25519_init(&key);
			wc_curve25519_import_private_ex(sk->ptr, 32, &key,
							EC25519_LITTLE_ENDIAN);
			wc_curve25519_export_public_ex(&key, pk->ptr, &pk_len,
						       EC25519_LITTLE_ENDIAN);
			pk->len = (uint32_t)pk_len;
			sk->len = 32;
			wc_curve25519_free(&key);
			return ok;
		}
#else
		return unsupported_ecdh_curve;
#endif
	}

#if defined(WOLFCRYPT) && _SUITE_USES_P256
	if (alg == P256) {
		ecc_key key;
		byte pub33[33];
		word32 pub_len = sizeof(pub33);
		word32 sk_len = 32;
		/* sk->ptr is pre-filled with 32 bytes of CSPRNG output by the caller.
		 * wc_ecc_make_key_ex is avoided: sp_ecc_make_key_256 is dead-code-
		 * eliminated by LTO, falling back to the heap-alloc generic path which
		 * fails on bare-metal.  Instead, import the private key and derive the
		 * public key via wc_ecc_make_pub, which uses sp_ecc_mulmod_base_256. */
		wc_ecc_init(&key);
		wc_ecc_import_private_key_ex(sk->ptr, 32, NULL, 0, &key, ECC_SECP256R1);
		wc_ecc_make_pub(&key, NULL);
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		wc_ecc_export_x963_ex(&key, pub33, &pub_len, 1);
		memcpy(pk->ptr, pub33 + 1, 32);
		pk->len = 32;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* WOLFCRYPT && _SUITE_USES_P256 */
#if defined(WOLFCRYPT) && _SUITE_USES_P384
	if (alg == P384) {
		/* sk->ptr pre-filled with 48 bytes of CSPRNG output by caller. */
		ecc_key key;
		byte pub97[97];
		word32 pub_len = sizeof(pub97);
		word32 sk_len = 48;
		int r384;
		wc_ecc_init(&key);
		r384 = wc_ecc_import_private_key_ex(sk->ptr, 48, NULL, 0,
						    &key, ECC_SECP384R1);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_keygen_import)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_make_pub(&key, NULL);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_make_pub)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		r384 = wc_ecc_export_x963(&key, pub97, &pub_len);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_export_pub)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		memcpy(pk->ptr, pub97 + 1, 48);
		pk->len = 48;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* WOLFCRYPT && _SUITE_USES_P384 */
#if defined(WOLFCRYPT) && _SUITE_USES_X448
	if (alg == X448) {
		/* sk->ptr pre-filled with 56 bytes of CSPRNG output by caller.
		 * Apply RFC 7748 §5 clamping so the keygen result matches what
		 * wc_curve448_import_private_ex produces during shared-secret derive. */
		sk->ptr[0]  &= 0xfc;
		sk->ptr[55] |= 0x80;
		curve448_key key;
		word32 pk_len = 56;
		wc_curve448_init(&key);
		wc_curve448_import_private_ex(sk->ptr, 56, &key,
					      EC448_LITTLE_ENDIAN);
		wc_curve448_export_public_ex(&key, pk->ptr, &pk_len,
					     EC448_LITTLE_ENDIAN);
		sk->len = 56;
		pk->len = (uint32_t)pk_len;
		wc_curve448_free(&key);
		return ok;
	}
#endif /* WOLFCRYPT && _SUITE_USES_X448 */
	return unsupported_ecdh_curve;
}

enum err WEAK sign_key_gen(enum sign_alg alg, const uint8_t *seed,
			   struct byte_array *sk, struct byte_array *pk)
{
#ifdef COMPACT25519
	if (alg == EdDSA) {
		edsign_seckey_expand(sk->ptr, seed);
		edsign_public_key(pk->ptr, sk->ptr);
		sk->len = 64;
		pk->len = 32;
		return ok;
	}
#endif

#ifdef WOLFCRYPT
#ifdef HAVE_ED25519
	if (alg == EdDSA) {
		/* Store seed in sk[0..31], public key in sk[32..63] (64-byte buf) */
		ed25519_key key;
		word32 pk_len = 32;
		int ret;
		wc_ed25519_init(&key);
		ret = wc_ed25519_import_private_only(seed, 32, &key);
		if (ret != 0) {
			wc_ed25519_free(&key);
			return sign_failed;
		}
		ret = wc_ed25519_make_public(&key, pk->ptr, pk_len);
		if (ret != 0) {
			wc_ed25519_free(&key);
			return sign_failed;
		}
		memcpy(sk->ptr, seed, 32);
		memcpy(sk->ptr + 32, pk->ptr, 32);
		sk->len = 64;
		pk->len = 32;
		wc_ed25519_free(&key);
		return ok;
	}
#endif /* HAVE_ED25519 */
#if _SUITE_USES_ES256
	if (alg == ES256) {
		ecc_key key;
		byte pub33[33];
		word32 pub_len = sizeof(pub33);
		word32 sk_len = 32;
		wc_ecc_init(&key);
		wc_ecc_import_private_key_ex(seed, 32, NULL, 0,
					     &key, ECC_SECP256R1);
		wc_ecc_make_pub(&key, NULL);
		wc_ecc_export_x963_ex(&key, pub33, &pub_len, 1);
		/* RFC 9528 §3.7: CRED uses y=false (even Y, prefix 0x02).
		 * If Y is odd (prefix 0x03), negate the private scalar: new_sk = n - sk.
		 * The negated key has the same X but even Y, keeping y=false valid. */
		if (pub33[0] == 0x03) {
			/* P-256 order n */
			static const byte p256n[32] = {
				0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
				0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
			};
			mp_int order, neg;
			mp_init(&order);
			mp_init(&neg);
			mp_read_unsigned_bin(&order, p256n, 32);
			mp_sub(&order, &key.k[0], &neg);
			mp_copy(&neg, &key.k[0]);
			mp_clear(&order);
			mp_clear(&neg);
			/* Recompute public key from negated private key */
			wc_ecc_make_pub(&key, NULL);
			pub_len = sizeof(pub33);
			wc_ecc_export_x963_ex(&key, pub33, &pub_len, 1);
		}
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		memcpy(pk->ptr, pub33 + 1, 32);
		pk->len = 32;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_ES256 */
#if _SUITE_USES_P384
	if (alg == ES384) {
		ecc_key key;
		byte pub97[97];
		word32 pub_len = sizeof(pub97);
		word32 sk_len = 48;
		wc_ecc_init(&key);
		wc_ecc_import_private_key_ex(seed, 48, NULL, 0,
					     &key, ECC_SECP384R1);
		wc_ecc_make_pub(&key, NULL);
		/* Use SECG compressed form so pub97[0] tells us Y parity. */
		pub_len = sizeof(pub97);
		wc_ecc_export_x963_ex(&key, pub97, &pub_len, 1);
		/* RFC 9528 §3.7: CRED uses y=false (even Y, prefix 0x02).
		 * If Y is odd (prefix 0x03), negate the private scalar: new_sk = n - sk.
		 * The negated key has the same X but even Y, keeping y=false valid. */
		if (pub97[0] == 0x03) {
			/* P-384 order n (NIST FIPS 186-4) */
			static const byte p384n[48] = {
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,
				0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
				0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
			};
			mp_int order, neg;
			mp_init(&order);
			mp_init(&neg);
			mp_read_unsigned_bin(&order, p384n, 48);
			mp_sub(&order, &key.k[0], &neg);
			mp_copy(&neg, &key.k[0]);
			mp_clear(&order);
			mp_clear(&neg);
			/* Recompute public key from negated private key */
			wc_ecc_make_pub(&key, NULL);
			pub_len = sizeof(pub97);
			wc_ecc_export_x963_ex(&key, pub97, &pub_len, 1);
		}
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		memcpy(pk->ptr, pub97 + 1, 48);
		pk->len = 48;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_P384 */
#if _SUITE_USES_X448 && defined(HAVE_ED448)
	if (alg == Ed448) {
		ed448_key key;
		word32 pk_len = 57;
		wc_ed448_init(&key);
		wc_ed448_import_private_only(seed, 57, &key);
		wc_ed448_make_public(&key, pk->ptr, pk_len);
		memcpy(sk->ptr, seed, 57);
		sk->len = 57;
		pk->len = (uint32_t)pk_len;
		wc_ed448_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
}

enum err WEAK x25519_public_from_private(const struct byte_array *sk,
					  struct byte_array *pk)
{
#ifdef COMPACT25519
	uint8_t e[32];
	f25519_copy(e, sk->ptr);
	c25519_prepare(e);
	c25519_smult(pk->ptr, c25519_base_x, e);
	pk->len = 32;
	return ok;
#elif defined(WOLFCRYPT) && defined(HAVE_CURVE25519)
	{
		curve25519_key key;
		word32 pk_len = 32;
		wc_curve25519_init(&key);
		wc_curve25519_import_private_ex(sk->ptr, sk->len, &key,
						EC25519_LITTLE_ENDIAN);
		wc_curve25519_export_public_ex(&key, pk->ptr, &pk_len,
					       EC25519_LITTLE_ENDIAN);
		pk->len = (uint32_t)pk_len;
		wc_curve25519_free(&key);
		return ok;
	}
#else
	return crypto_operation_not_implemented;
#endif
}

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
#ifdef WOLFCRYPT
	if (alg == SHA_256) {
		wc_Sha256Hash(in->ptr, in->len, out->ptr);
		out->len = 32;
		return ok;
	}
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384) {
		wc_Sha384Hash(in->ptr, in->len, out->ptr);
		out->len = 48;
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 24 */
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		wc_Shake256Hash(in->ptr, in->len, out->ptr, 64);
		out->len = 64;
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH256) {
		wc_AsconHash256 h;
		wc_AsconHash256_Init(&h);
		wc_AsconHash256_Update(&h, in->ptr, in->len);
		wc_AsconHash256_Final(&h, out->ptr);
		out->len = 32;
		return ok;
	}
#endif /* HAVE_ASCON */
#endif /* WOLFCRYPT */
	return crypto_operation_not_implemented;
}

#ifdef WOLFCRYPT
#ifdef WOLFSSL_HAVE_MLKEM
#warning "ML-KEM: protocol integration pending"

static int kyber_type(enum kem_alg alg)
{
	switch (alg) {
	case ML_KEM_512:  return WC_ML_KEM_512;
	case ML_KEM_768:  return WC_ML_KEM_768;
	case ML_KEM_1024: return WC_ML_KEM_1024;
	default:          return -1;
	}
}

enum err kem_keygen(enum kem_alg alg, struct byte_array *ek,
		    struct byte_array *dk)
{
	int type = kyber_type(alg);
	if (type < 0)
		return crypto_operation_not_implemented;

	MlKemKey *key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
	if (!key)
		return crypto_operation_not_implemented;

	WC_RNG rng;
	wc_InitRng(&rng);
	wc_MlKemKey_MakeKey(key, &rng);
	wc_FreeRng(&rng);

	wc_MlKemKey_EncodePublicKey(key, ek->ptr, (word32)ek->len);
	wc_MlKemKey_EncodePrivateKey(key, dk->ptr, (word32)dk->len);

	wc_MlKemKey_Delete(key, NULL);
	return ok;
}

enum err kem_encap(enum kem_alg alg, const struct byte_array *ek,
		   struct byte_array *ct, struct byte_array *ss)
{
	int type = kyber_type(alg);
	if (type < 0)
		return crypto_operation_not_implemented;

	MlKemKey *key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
	if (!key)
		return crypto_operation_not_implemented;

	wc_MlKemKey_DecodePublicKey(key, ek->ptr, (word32)ek->len);

	WC_RNG rng;
	wc_InitRng(&rng);
	wc_MlKemKey_Encapsulate(key, ct->ptr, ss->ptr, &rng);
	wc_FreeRng(&rng);

	wc_MlKemKey_Delete(key, NULL);
	return ok;
}

enum err kem_decap(enum kem_alg alg, const struct byte_array *dk,
		   const struct byte_array *ct, struct byte_array *ss)
{
	int type = kyber_type(alg);
	if (type < 0)
		return crypto_operation_not_implemented;

	MlKemKey *key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
	if (!key)
		return crypto_operation_not_implemented;

	wc_MlKemKey_DecodePrivateKey(key, dk->ptr, (word32)dk->len);
	wc_MlKemKey_Decapsulate(key, ss->ptr, ct->ptr, (word32)ct->len);

	wc_MlKemKey_Delete(key, NULL);
	return ok;
}
#endif /* WOLFSSL_HAVE_MLKEM */
#endif /* WOLFCRYPT (inner block) */

#endif /* WOLFCRYPT — outer guard, mirror at top of file */
