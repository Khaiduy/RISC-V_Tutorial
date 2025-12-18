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
	if (label == SUITE_0) {
		suite->suite_label = SUITE_0;
		suite->edhoc_aead = AES_CCM_16_64_128;  // Tag=8, Nonce=13
		suite->edhoc_hash = SHA_256;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
#ifdef DEBUG_PRINT
		kprintf("\r\n*** SUITE 0 SELECTED: AES-CCM-16-64-128 (8-byte tag) ***\r\n\r\n");
#endif
		return ok;
	} else if (label == SUITE_1) {
		suite->suite_label = SUITE_1;
		suite->edhoc_aead = AES_CCM_16_128_128;  // Tag=16, Nonce=13
		suite->edhoc_hash = SHA_256;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_128_128;
		suite->app_hash = SHA_256;
#ifdef DEBUG_PRINT
		kprintf("\r\n*** SUITE 1 SELECTED: AES-CCM-16-128-128 (16-byte tag) ***\r\n\r\n");
#endif
		return ok;
	} else if (label == SUITE_2) {
		suite->suite_label = SUITE_2;
		suite->edhoc_aead = ASCON_AEAD_128;  // Tag=16, Nonce=16, Key=16
		suite->edhoc_hash = SHA_256;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = ASCON_AEAD_128;
		suite->app_hash = SHA_256;
#ifdef DEBUG_PRINT
		kprintf("\r\n*** SUITE 2 SELECTED: ASCON-AEAD-128 (16-byte nonce) ***\r\n\r\n");
#endif
		return ok;
	}
	
	return unsupported_cipher_suite;
}

uint32_t get_hash_len(enum hash_alg alg)
{
	// MODIFIED: Only SHA-256 supported (Suite 0)
	(void)alg;
	return 32;
}

uint32_t get_aead_mac_len(enum aead_alg alg)
{
	if (alg == AES_CCM_16_128_128 || alg == ASCON_AEAD_128) {
		return 16;  // Suite 1 and Ascon: 16-byte tag
	}
	return 8;  // Suite 0: 8-byte tag
}

uint32_t get_aead_key_len(enum aead_alg alg)
{
	// MODIFIED: Only AES_CCM_16_64_128 supported (Suite 0)
	(void)alg;
	return 16;
}

uint32_t get_aead_iv_len(enum aead_alg alg)
{
	if (alg == ASCON_AEAD_128) {
		return 16;  /* Ascon-AEAD-128 requires 16-byte nonce */
	} else if (alg == AES_CCM_16_128_128) {
		return 13;  /* AES-CCM-16-128-128 uses 13-byte nonce */
	}
	/* AES-CCM-16-64-128 (Suite 0) uses 13-byte nonce */
	return 13;
}

uint32_t get_signature_len(enum sign_alg alg)
{
	// MODIFIED: Only EdDSA supported (Suite 0)
	(void)alg;
	return 64;
}

uint32_t get_ecdh_pk_len(enum ecdh_alg alg)
{
	// MODIFIED: Only X25519 supported (Suite 0)
	(void)alg;
	return 32;
}
