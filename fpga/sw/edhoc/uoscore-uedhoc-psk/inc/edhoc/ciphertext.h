/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "edhoc/retrieve_cred.h"

enum ciphertext { CIPHERTEXT2, CIPHERTEXT3, CIPHERTEXT4 };

/* ===== PSK-ONLY FUNCTIONS (NO id_cred/sig_or_mac PARAMETERS) ===== */

/**
 * @brief PSK-only encryption for Message 2 and Message 4.
 *        These messages contain NO id_cred or sig_or_mac.
 */
enum err ciphertext_gen_psk(
	enum ciphertext ctxt, struct suite *suite,
	const struct byte_array *c_r,
	const struct byte_array *ead,
	struct byte_array *prk,
	struct byte_array *th,
	struct byte_array *ciphertext,
	struct byte_array *plaintext);

/**
 * @brief PSK-only decryption for Message 2 and Message 4.
 *        These messages contain NO id_cred or sig_or_mac.
 */
enum err ciphertext_decrypt_split_psk(
	enum ciphertext ctxt, struct suite *suite,
	struct byte_array *c_r,
	struct byte_array *ead,
	struct byte_array *prk,
	struct byte_array *th,
	struct byte_array *ciphertext,
	struct byte_array *plaintext);

/**
 * @brief PSK-only encryption for Message 3.
 *        Uses ID_CRED_PSK (not id_cred), NO sig_or_mac.
 *        Two-layer: KEYSTREAM_3A XOR (ID_CRED_PSK || AEAD(PLAINTEXT_3B)).
 */
enum err ciphertext_gen_psk_msg3(
	struct suite *suite,
	const struct byte_array *id_cred_psk,
	const struct byte_array *ead,
	struct byte_array *prk_3e2m,
	struct byte_array *th3,
	struct byte_array *prk_4e3m,
	const struct byte_array *cred_i,
	const struct byte_array *cred_r,
	struct byte_array *ciphertext,
	struct byte_array *plaintext);

/**
 * @brief PSK-only decryption for Message 3.
 *        Extracts ID_CRED_PSK from PLAINTEXT_3A, NO sig_or_mac.
 *        Two-layer: XOR KEYSTREAM_3A, then AEAD decrypt with external AAD.
 */
enum err ciphertext_decrypt_split_psk_msg3(
	struct suite *suite,
	struct byte_array *id_cred_psk,
	struct byte_array *ead,
	struct byte_array *prk_3e2m,
	struct byte_array *th3,
	struct byte_array *prk_4e3m,
	struct cred_array *cred_i_array,
	const struct byte_array *cred_r,
	struct byte_array *ciphertext,
	struct byte_array *plaintext);

#endif
