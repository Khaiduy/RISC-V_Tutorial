/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/suites.h"

#include "common/oscore_edhoc_error.h"

enum err get_suite(enum suite_label label, struct suite *suite)
{
	switch (label) {
	case SUITE_0:
		suite->suite_label = SUITE_0;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_1:
		suite->suite_label = SUITE_1;
		suite->edhoc_aead = AES_CCM_16_128_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_2:
		suite->suite_label = SUITE_2;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = P256;
		suite->edhoc_sign = ES256;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_3:
		suite->suite_label = SUITE_3;
		suite->edhoc_aead = AES_CCM_16_128_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = P256;
		suite->edhoc_sign = ES256;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_4:
		suite->suite_label = SUITE_4;
		suite->edhoc_aead = CHACHA20_POLY1305;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16; /* RFC 9528 Table 6: 16 */
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = CHACHA20_POLY1305;
		suite->app_hash = SHA_256;
		break;
	case SUITE_5:
		suite->suite_label = SUITE_5;
		suite->edhoc_aead = CHACHA20_POLY1305;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = P256;
		suite->edhoc_sign = ES256;
		suite->app_aead = CHACHA20_POLY1305;
		suite->app_hash = SHA_256;
		break;
	case SUITE_6:
		suite->suite_label = SUITE_6;
		suite->edhoc_aead = AES_GCM_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = ES256;  /* RFC 9528 Table 6: Suite 6 signs with ES256 */
		suite->app_aead = AES_GCM_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_7:
		suite->suite_label = SUITE_7;
		suite->edhoc_aead = ASCON_AEAD128;
		suite->edhoc_hash = ASCON_HASH256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = ASCON_AEAD128;
		suite->app_hash = ASCON_HASH256;
		break;
	case SUITE_24:
		suite->suite_label = SUITE_24;
		suite->edhoc_aead = AES_GCM_256;
		suite->edhoc_hash = SHA_384;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = P384;
		suite->edhoc_sign = ES384;
		suite->app_aead = AES_GCM_256; /* RFC 9528 Table 6: A256GCM */
		suite->app_hash = SHA_384;     /* RFC 9528 Table 6: SHA-384 */
		break;
	case SUITE_25:
		suite->suite_label = SUITE_25;
		suite->edhoc_aead = CHACHA20_POLY1305;
		suite->edhoc_hash = SHAKE_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = X448;
		suite->edhoc_sign = Ed448;
		suite->app_aead = CHACHA20_POLY1305;
		suite->app_hash = SHAKE_256;
		break;
	default:
		return unsupported_cipher_suite;
		break;
	}
	return ok;
}

uint32_t get_hash_len(enum hash_alg alg)
{
	switch (alg) {
	case SHA_256:
	case ASCON_HASH256:
		return 32;
		break;
	case SHA_384:
		return 48;
		break;
	case SHAKE_256:
		return 64;
		break;
	}
	return 0;
}

uint32_t get_aead_mac_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case CHACHA20_POLY1305:
	case AES_GCM_128:
	case AES_GCM_256:
	case ASCON_AEAD128:
		return 16;
		break;
	case AES_CCM_16_64_128:
		return 8;
		break;
	}
	return 0;
}

uint32_t get_aead_key_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
	case AES_GCM_128:
	case ASCON_AEAD128:
		return 16;
		break;
	case CHACHA20_POLY1305:
	case AES_GCM_256:
		return 32;
		break;
	}
	return 0;
}

uint32_t get_aead_iv_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
		return 13;
		break;
	case CHACHA20_POLY1305:
	case AES_GCM_128:
	case AES_GCM_256:
		return 12;
		break;
	case ASCON_AEAD128:
		return 16;
		break;
	}
	return 0;
}

uint32_t get_signature_len(enum sign_alg alg)
{
	switch (alg) {
	case ES256:
	case EdDSA:
		return 64;
		break;
	case ES384:
		return 96;
		break;
	case Ed448:
		return 114;
		break;
	}
	return 0;
}

uint32_t get_ecdh_pk_len(enum ecdh_alg alg)
{
	switch (alg) {
	case P256:
	case X25519:
		return 32;
		break;
	case P384:
		return 48;
		break;
	case X448:
		return 56;
		break;
	}
	return 0;
}
