/*
 * crypto_wrapper_legacy.c — Monocypher + TinyCrypt + Ascon-c backend for the
 * PSK library (EDHOC Method 4).
 *
 * Backend selection by compile-time defines (mutually exclusive with the
 * wolfcrypt crypto_wrapper.c — only one wrapper is linked per build):
 *   Suite 0/1 : X25519 (Monocypher) + AES-CCM-16 (TinyCrypt) + SHA-256/HMAC (TinyCrypt)
 *   Suite 7   : X25519 (Monocypher) + Ascon-AEAD-128 + Ascon-Hash256 (ascon-c)
 *
 * Public API matches uoscore-uedhoc-psk/inc/common/crypto_wrapper.h
 * (aead takes 7 args — algorithm/tag-length implicit via EDHOC_CRYPTO_SUITE).
 */
#if defined(MONOCYPHER) || defined(TINYCRYPT)

#include <string.h>

#include "edhoc.h"
#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "edhoc/suites.h"

#include <monocypher.h>

#ifdef TINYCRYPT
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#endif

#ifdef ASCON
/* Ascon-c NIST API: crypto_aead_encrypt/decrypt produce ciphertext||tag in a
 * single buffer; crypto_hash gives 32-byte Ascon-Hash256. ascon_hmac is the
 * vendored RFC 2104 HMAC over Ascon-Hash256 (64-byte block). */
#include "crypto_aead.h"
#include "crypto_hash.h"
#include "common/ascon_hmac.h"
#endif

#if !defined(EDHOC_CRYPTO_SUITE)
#  error "EDHOC_CRYPTO_SUITE must be defined by the Makefile"
#endif

/* ===== AEAD =====
 * DECRYPT: in = ct+tag combined; out = plaintext (out->len already pt length);
 *          tag points INTO in (redundant).
 * ENCRYPT: in = plaintext; out = ciphertext; tag = separate fresh buffer. */
enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
#if EDHOC_CRYPTO_SUITE == 7
#  ifdef ASCON
	if (op == DECRYPT) {
		unsigned long long mlen = 0;
		int r = crypto_aead_decrypt(out->ptr, &mlen, NULL,
					    in->ptr, in->len,
					    aad->ptr, aad->len,
					    nonce->ptr, key->ptr);
		if (r != 0) return mac_authentication_failed;
		return ok;
	} else {
		uint8_t ct_tag[256 + 16];
		if (in->len + tag->len > sizeof(ct_tag)) return buffer_to_small;
		unsigned long long clen = 0;
		int r = crypto_aead_encrypt(ct_tag, &clen,
					    in->ptr, in->len,
					    aad->ptr, aad->len,
					    NULL, nonce->ptr, key->ptr);
		if (r != 0) return unexpected_result_from_ext_lib;
		memcpy(out->ptr, ct_tag, in->len);
		memcpy(tag->ptr, ct_tag + in->len, tag->len);
		return ok;
	}
#  else
	return crypto_operation_not_implemented;
#  endif
#elif defined(TINYCRYPT)
	/* Suite 0/1: AES-CCM-16. Key=16, nonce=13, tag=8 (S0) / 16 (S1). */
	struct tc_ccm_mode_struct c;
	struct tc_aes_key_sched_struct sched;
	if (tc_aes128_set_encrypt_key(&sched, key->ptr) != TC_CRYPTO_SUCCESS)
		return unexpected_result_from_ext_lib;
	if (tc_ccm_config(&c, &sched, nonce->ptr, nonce->len, tag->len) !=
	    TC_CRYPTO_SUCCESS)
		return unexpected_result_from_ext_lib;
	if (op == DECRYPT) {
		if (tc_ccm_decryption_verification(out->ptr, out->len,
						   aad->ptr, aad->len,
						   in->ptr, in->len, &c) !=
		    TC_CRYPTO_SUCCESS)
			return mac_authentication_failed;
	} else {
		if (tc_ccm_generation_encryption(out->ptr, out->len + tag->len,
						 aad->ptr, aad->len,
						 in->ptr, in->len, &c) !=
		    TC_CRYPTO_SUCCESS)
			return unexpected_result_from_ext_lib;
		memcpy(tag->ptr, out->ptr + out->len, tag->len);
	}
	return ok;
#else
	return crypto_operation_not_implemented;
#endif
}

/* ===== HASH ===== */
enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
#ifdef ASCON
	if (alg == ASCON_HASH_256) {
		if (crypto_hash(out->ptr, in->ptr, in->len) != 0)
			return sha_failed;
		out->len = 32;
		return ok;
	}
#endif
#ifdef TINYCRYPT
	if (alg == SHA_256) {
		struct tc_sha256_state_struct s;
		if (tc_sha256_init(&s) != TC_CRYPTO_SUCCESS) return sha_failed;
		if (tc_sha256_update(&s, in->ptr, in->len) != TC_CRYPTO_SUCCESS)
			return sha_failed;
		if (tc_sha256_final(out->ptr, &s) != TC_CRYPTO_SUCCESS)
			return sha_failed;
		out->len = 32;
		return ok;
	}
#endif
	return crypto_operation_not_implemented;
}

/* ===== HKDF (Extract + Expand) ===== */
enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
#ifdef ASCON
	if (alg == ASCON_HASH_256) {
		uint8_t zero[32] = { 0 };
		const uint8_t *s = (salt && salt->ptr && salt->len) ? salt->ptr : zero;
		uint32_t s_len = (salt && salt->ptr && salt->len) ? salt->len : 32;
		if (ascon_hmac(s, s_len, ikm->ptr, ikm->len, out) != 0)
			return hkdf_failed;
		return ok;
	}
#endif
#ifdef TINYCRYPT
	if (alg == SHA_256) {
		struct tc_hmac_state_struct h;
		uint8_t zero[32] = { 0 };
		const uint8_t *s = (salt && salt->ptr && salt->len) ? salt->ptr : zero;
		uint32_t s_len = (salt && salt->ptr && salt->len) ? salt->len : 32;
		memset(&h, 0, sizeof(h));
		if (tc_hmac_set_key(&h, s, s_len) != TC_CRYPTO_SUCCESS) return hkdf_failed;
		if (tc_hmac_init(&h) != TC_CRYPTO_SUCCESS) return hkdf_failed;
		if (tc_hmac_update(&h, ikm->ptr, ikm->len) != TC_CRYPTO_SUCCESS) return hkdf_failed;
		if (tc_hmac_final(out, TC_SHA256_DIGEST_SIZE, &h) != TC_CRYPTO_SUCCESS) return hkdf_failed;
		return ok;
	}
#endif
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
	uint32_t iterations = (out->len + 31) / 32;
	if (iterations > 255) return hkdf_failed;

#ifdef ASCON
	if (alg == ASCON_HASH_256) {
		uint8_t t[32] = { 0 };
		uint8_t buf[256 + 32 + 1];
		for (uint8_t i = 1; i <= iterations; i++) {
			uint32_t pos = 0;
			if (i > 1) { memcpy(buf, t, 32); pos = 32; }
			if (pos + info->len + 1 > sizeof(buf)) return hkdf_failed;
			memcpy(buf + pos, info->ptr, info->len); pos += info->len;
			buf[pos++] = i;
			if (ascon_hmac(prk->ptr, prk->len, buf, pos, t) != 0)
				return hkdf_failed;
			uint32_t take = (out->len < (uint32_t)(i * 32)) ?
					(out->len - (uint32_t)((i - 1) * 32)) : 32;
			memcpy(out->ptr + (i - 1) * 32, t, take);
		}
		return ok;
	}
#endif
#ifdef TINYCRYPT
	if (alg == SHA_256) {
		uint8_t t[32] = { 0 };
		struct tc_hmac_state_struct h;
		for (uint8_t i = 1; i <= iterations; i++) {
			memset(&h, 0, sizeof(h));
			if (tc_hmac_set_key(&h, prk->ptr, prk->len) != TC_CRYPTO_SUCCESS) return hkdf_failed;
			tc_hmac_init(&h);
			if (i > 1) {
				if (tc_hmac_update(&h, t, 32) != TC_CRYPTO_SUCCESS) return hkdf_failed;
			}
			if (tc_hmac_update(&h, info->ptr, info->len) != TC_CRYPTO_SUCCESS) return hkdf_failed;
			if (tc_hmac_update(&h, &i, 1) != TC_CRYPTO_SUCCESS) return hkdf_failed;
			if (tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &h) != TC_CRYPTO_SUCCESS) return hkdf_failed;
			if (out->len < (uint32_t)(i * 32))
				memcpy(&out->ptr[(i - 1) * 32], t, out->len % 32);
			else
				memcpy(&out->ptr[(i - 1) * 32], t, 32);
		}
		return ok;
	}
#endif
	return crypto_operation_not_implemented;
}

/* PSK lib's header declares these unused helpers — provide stubs. */
enum err WEAK hkdf_sha_256(struct byte_array *master_secret,
			   struct byte_array *master_salt, struct byte_array *info,
			   struct byte_array *out)
{
	(void)master_secret; (void)master_salt; (void)info; (void)out;
	return crypto_operation_not_implemented;
}
#ifdef ASCON
enum err WEAK hkdf_ascon(struct byte_array *master_secret,
			 struct byte_array *master_salt, struct byte_array *info,
			 struct byte_array *out)
{
	(void)master_secret; (void)master_salt; (void)info; (void)out;
	return crypto_operation_not_implemented;
}
#endif

/* ===== ECDH (X25519 via Monocypher) ===== */
enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
	if (alg == X25519) {
		crypto_x25519(shared_secret, sk->ptr, pk->ptr);
		return ok;
	}
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	(void)seed;
	if (alg == X25519) {
		/* sk is pre-filled with random bytes by the caller. Clamp per
		 * RFC 7748, then derive the public key (Monocypher re-clamps
		 * internally — harmless). */
		sk->ptr[0]  &= 0xF8;
		sk->ptr[31] &= 0x7F;
		sk->ptr[31] |= 0x40;
		crypto_x25519_public_key(pk->ptr, sk->ptr);
		sk->len = 32;
		pk->len = 32;
		return ok;
	}
	return crypto_operation_not_implemented;
}

/* ===== Sign / Verify (stubs — PSK Method 4 has no signatures) ===== */
enum err WEAK sign(enum sign_alg alg, const struct byte_array *sk,
		   const struct byte_array *pk, const struct byte_array *msg,
		   uint8_t *out)
{
	(void)alg; (void)sk; (void)pk; (void)msg; (void)out;
	return crypto_operation_not_implemented;
}

enum err WEAK verify(enum sign_alg alg, const struct byte_array *pk,
		     struct const_byte_array *msg, struct const_byte_array *sgn,
		     bool *result)
{
	(void)alg; (void)pk; (void)msg; (void)sgn;
	if (result) *result = false;
	return crypto_operation_not_implemented;
}

#endif /* MONOCYPHER || TINYCRYPT */
