/*
 * crypto_wrapper.c — wolfcrypt-backed implementation for the PSK library.
 *
 * Backend: wolfcrypt (shared with the standard library's wolfssl/).
 * Suite selection by EDHOC_CRYPTO_SUITE compile-time macro.
 * Supports Suites 0, 1 (AES-CCM + SHA-256 + X25519) and Suite 7
 * (Ascon-AEAD-128 + Ascon-Hash-256 + X25519).
 *
 * Public API matches uoscore-uedhoc-psk/inc/common/crypto_wrapper.h
 * (note: aead takes 7 args — algorithm is implicit via CRYPTO_SUITE).
 */
/* Outer guard: emit symbols only under the wolfcrypt backend. The legacy
 * backend (Monocypher + TinyCrypt + Ascon-c) lives in crypto_wrapper_legacy.c
 * and is selected by -DMONOCYPHER/-DTINYCRYPT/-DASCON. Exactly one wrapper
 * emits per build, avoiding duplicate symbols (both match src/common/*.c). */
#ifdef WOLFCRYPT

#include <string.h>

#include "edhoc.h"
#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "edhoc/suites.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#endif

#if !defined(EDHOC_CRYPTO_SUITE)
#  error "EDHOC_CRYPTO_SUITE must be defined by the Makefile"
#endif

/* ===== AEAD =====
 * 7-arg signature per PSK lib's crypto_wrapper.h: AEAD alg + tag length are
 * determined at compile time from EDHOC_CRYPTO_SUITE. */

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || EDHOC_CRYPTO_SUITE == 2
	Aes aes;
	int r = wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (r != 0) return unexpected_result_from_ext_lib;
	r = wc_AesCcmSetKey(&aes, key->ptr, key->len);
	if (r != 0) { wc_AesFree(&aes); return unexpected_result_from_ext_lib; }
	if (op == DECRYPT) {
		uint32_t ct_len = in->len - tag->len;
		r = wc_AesCcmDecrypt(&aes, out->ptr, in->ptr, ct_len,
				     nonce->ptr, nonce->len,
				     in->ptr + ct_len, tag->len,
				     aad->ptr, aad->len);
		wc_AesFree(&aes);
		if (r != 0) return mac_authentication_failed;
	} else {
		r = wc_AesCcmEncrypt(&aes, out->ptr, in->ptr, in->len,
				     nonce->ptr, nonce->len,
				     tag->ptr, tag->len,
				     aad->ptr, aad->len);
		wc_AesFree(&aes);
		if (r != 0) return unexpected_result_from_ext_lib;
	}
	return ok;
#elif EDHOC_CRYPTO_SUITE == 7
#  ifdef HAVE_ASCON
	wc_AsconAEAD128 a;
	if (wc_AsconAEAD128_Init(&a) != 0) return unexpected_result_from_ext_lib;
	if (wc_AsconAEAD128_SetKey(&a, key->ptr) != 0) {
		wc_AsconAEAD128_Free(&a); return unexpected_result_from_ext_lib; }
	if (wc_AsconAEAD128_SetNonce(&a, nonce->ptr) != 0) {
		wc_AsconAEAD128_Free(&a); return unexpected_result_from_ext_lib; }
	if (aad->len)
		wc_AsconAEAD128_SetAD(&a, aad->ptr, aad->len);
	if (op == DECRYPT) {
		uint32_t ct_len = in->len - tag->len;
		if (wc_AsconAEAD128_DecryptUpdate(&a, out->ptr, in->ptr, ct_len) != 0) {
			wc_AsconAEAD128_Free(&a); return mac_authentication_failed; }
		if (wc_AsconAEAD128_DecryptFinal(&a, in->ptr + ct_len) != 0) {
			wc_AsconAEAD128_Free(&a); return mac_authentication_failed; }
		wc_AsconAEAD128_Free(&a);
		return ok;
	} else {
		if (wc_AsconAEAD128_EncryptUpdate(&a, out->ptr, in->ptr, in->len) != 0) {
			wc_AsconAEAD128_Free(&a); return unexpected_result_from_ext_lib; }
		if (wc_AsconAEAD128_EncryptFinal(&a, tag->ptr) != 0) {
			wc_AsconAEAD128_Free(&a); return unexpected_result_from_ext_lib; }
		wc_AsconAEAD128_Free(&a);
		return ok;
	}
#  else
	return crypto_operation_not_implemented;
#  endif
#else
	return crypto_operation_not_implemented;
#endif
}

/* ===== HASH ===== */

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
	if (alg == SHA_256) {
		if (wc_Sha256Hash(in->ptr, in->len, out->ptr) != 0)
			return sha_failed;
		out->len = 32;
		return ok;
	}
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH_256) {
		wc_AsconHash256 h;
		if (wc_AsconHash256_Init(&h) != 0) return sha_failed;
		if (wc_AsconHash256_Update(&h, in->ptr, in->len) != 0) {
			wc_AsconHash256_Free(&h); return sha_failed; }
		if (wc_AsconHash256_Final(&h, out->ptr) != 0) {
			wc_AsconHash256_Free(&h); return sha_failed; }
		wc_AsconHash256_Free(&h);
		out->len = 32;
		return ok;
	}
#endif
	return crypto_operation_not_implemented;
}

/* ===== HKDF (Extract + Expand) ===== */

#ifdef HAVE_ASCON
static enum err ascon_hmac(const uint8_t *key, uint32_t key_len,
			   const uint8_t *m, uint32_t m_len,
			   uint8_t *out)
{
	uint8_t k_pad[64] = {0};
	uint8_t i_pad[64], o_pad[64], inner[32];
	wc_AsconHash256 h;
	if (key_len > 64) {
		if (wc_AsconHash256_Init(&h) != 0) return sha_failed;
		wc_AsconHash256_Update(&h, key, key_len);
		wc_AsconHash256_Final(&h, k_pad);
		wc_AsconHash256_Free(&h);
	} else {
		memcpy(k_pad, key, key_len);
	}
	for (int i = 0; i < 64; i++) { i_pad[i] = k_pad[i] ^ 0x36; o_pad[i] = k_pad[i] ^ 0x5c; }
	if (wc_AsconHash256_Init(&h) != 0) return sha_failed;
	wc_AsconHash256_Update(&h, i_pad, 64);
	if (m && m_len) wc_AsconHash256_Update(&h, m, m_len);
	wc_AsconHash256_Final(&h, inner);
	wc_AsconHash256_Free(&h);
	if (wc_AsconHash256_Init(&h) != 0) return sha_failed;
	wc_AsconHash256_Update(&h, o_pad, 64);
	wc_AsconHash256_Update(&h, inner, 32);
	wc_AsconHash256_Final(&h, out);
	wc_AsconHash256_Free(&h);
	return ok;
}
#endif

enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	const uint8_t zero[32] = {0};
	const uint8_t *s = (salt && salt->ptr && salt->len) ? salt->ptr : zero;
	uint32_t s_len = (salt && salt->ptr && salt->len) ? salt->len : 32;

	if (alg == SHA_256) {
		if (wc_HKDF_Extract(WC_SHA256, s, s_len, ikm->ptr, ikm->len, out) != 0)
			return hkdf_failed;
		return ok;
	}
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH_256) {
		return ascon_hmac(s, s_len, ikm->ptr, ikm->len, out);
	}
#endif
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
	if (alg == SHA_256) {
		if (wc_HKDF_Expand(WC_SHA256, prk->ptr, prk->len,
				   info->ptr, info->len, out->ptr, out->len) != 0)
			return hkdf_failed;
		return ok;
	}
#ifdef HAVE_ASCON
	if (alg == ASCON_HASH_256) {
		uint32_t hash_len = 32;
		uint32_t iter = (out->len + hash_len - 1) / hash_len;
		if (iter > 255) return hkdf_failed;
		uint8_t T[32] = {0};
		uint32_t T_len = 0;
		uint8_t cat[32 + 512 + 1];
		for (uint8_t ctr = 1; ctr <= iter; ctr++) {
			uint32_t catlen = 0;
			if (T_len) { memcpy(cat, T, T_len); catlen += T_len; }
			if (info->len) { memcpy(cat + catlen, info->ptr, info->len); catlen += info->len; }
			cat[catlen++] = ctr;
			enum err r = ascon_hmac(prk->ptr, prk->len, cat, catlen, T);
			if (r != ok) return r;
			uint32_t off = (ctr - 1) * hash_len;
			uint32_t copy = (out->len - off > hash_len) ? hash_len : (out->len - off);
			memcpy(&out->ptr[off], T, copy);
			T_len = hash_len;
		}
		return ok;
	}
#endif
	return crypto_operation_not_implemented;
}

/* PSK lib's header also declares these unused helpers — provide stubs. */
enum err WEAK hkdf_sha_256(struct byte_array *master_secret,
			   struct byte_array *master_salt, struct byte_array *info,
			   struct byte_array *out)
{
	(void)master_secret; (void)master_salt; (void)info; (void)out;
	return crypto_operation_not_implemented;
}
#ifdef HAVE_ASCON
enum err WEAK hkdf_ascon(struct byte_array *master_secret,
			 struct byte_array *master_salt, struct byte_array *info,
			 struct byte_array *out)
{
	(void)master_secret; (void)master_salt; (void)info; (void)out;
	return crypto_operation_not_implemented;
}
#endif

/* ===== ECDH ===== */

enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
	if (alg == X25519) {
		curve25519_key priv, pub;
		word32 secret_len = 32;
		wc_curve25519_init(&priv);
		wc_curve25519_init(&pub);
		if (wc_curve25519_import_private_ex(sk->ptr, 32, &priv,
						    EC25519_LITTLE_ENDIAN) != 0) {
			wc_curve25519_free(&priv); wc_curve25519_free(&pub);
			return unexpected_result_from_ext_lib; }
		if (wc_curve25519_import_public_ex(pk->ptr, 32, &pub,
						   EC25519_LITTLE_ENDIAN) != 0) {
			wc_curve25519_free(&priv); wc_curve25519_free(&pub);
			return unexpected_result_from_ext_lib; }
		if (wc_curve25519_shared_secret_ex(&priv, &pub, shared_secret, &secret_len,
						   EC25519_LITTLE_ENDIAN) != 0) {
			wc_curve25519_free(&priv); wc_curve25519_free(&pub);
			return unexpected_result_from_ext_lib; }
		wc_curve25519_free(&priv);
		wc_curve25519_free(&pub);
		return ok;
	}
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	(void)seed;
	if (alg == X25519) {
		sk->ptr[0]  &= 0xF8;
		sk->ptr[31] &= 0x7F;
		sk->ptr[31] |= 0x40;
		curve25519_key key;
		word32 pk_len = 32;
		wc_curve25519_init(&key);
		if (wc_curve25519_import_private_ex(sk->ptr, 32, &key,
						    EC25519_LITTLE_ENDIAN) != 0) {
			wc_curve25519_free(&key);
			return unexpected_result_from_ext_lib; }
		if (wc_curve25519_export_public_ex(&key, pk->ptr, &pk_len,
						   EC25519_LITTLE_ENDIAN) != 0) {
			wc_curve25519_free(&key);
			return unexpected_result_from_ext_lib; }
		sk->len = 32;
		pk->len = (uint32_t)pk_len;
		wc_curve25519_free(&key);
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

#endif /* WOLFCRYPT */
