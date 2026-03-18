/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>

#include "oscore.h"

#include "oscore/oscore_cose.h"
#include "oscore/security_context.h"
#include "oscore/supported_algorithm.h"

#include "common/crypto_wrapper.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/print_util.h"

#include "cbor/oscore_enc_structure.h"

/*the additional bytes in the enc_structure are constant*/
#define ENCRYPT0_ENCODING_OVERHEAD 16

/**
 * @brief Encode the input AAD to defined COSE structure
 * @param external_aad: input aad to form COSE structure
 * @param out: output encoded COSE byte string
 * @return err
 */
static enum err create_enc_structure(struct byte_array *external_aad,
				     struct byte_array *out)
{
	// PRINTF("[CREATE_ENC_STRUCT] Start\r\n");
	struct oscore_enc_structure enc_structure;

	uint8_t context[] = { 'E', 'n', 'c', 'r', 'y', 'p', 't', '0', '\0' };
	enc_structure.oscore_enc_structure_context.value = context;
	enc_structure.oscore_enc_structure_context.len = 8;  /* "Encrypt0" length without null */
	// PRINTF("[CREATE_ENC_STRUCT] Context set\r\n");
	
	enc_structure.oscore_enc_structure_protected.value = NULL;
	enc_structure.oscore_enc_structure_protected.len = 0;
	enc_structure.oscore_enc_structure_external_aad.value =
		external_aad->ptr;
	enc_structure.oscore_enc_structure_external_aad.len =
		external_aad->len;
	// PRINTF("[CREATE_ENC_STRUCT] AAD len=%d\r\n", external_aad->len);

	size_t payload_len_out = 0;

	// PRINTF("[CREATE_ENC_STRUCT] Calling cbor_encode...\r\n");
	TRY_EXPECT(cbor_encode_oscore_enc_structure(out->ptr, out->len,
						    &enc_structure,
						    &payload_len_out),
		   0);
	// PRINTF("[CREATE_ENC_STRUCT] CBOR encode done, len=%d\r\n", (int)payload_len_out);

	out->len = (uint32_t)payload_len_out;
	// PRINTF("[CREATE_ENC_STRUCT] Complete\r\n");
	return ok;
}

enum err oscore_cose_decrypt(struct byte_array *in_ciphertext,
			     struct byte_array *out_plaintext,
			     struct byte_array *nonce,
			     struct byte_array *recipient_aad,
			     struct byte_array *key)
{
	/* get enc_structure */
	uint32_t aad_len = recipient_aad->len + ENCRYPT0_ENCODING_OVERHEAD;
	BYTE_ARRAY_NEW(aad, MAX_AAD_LEN, aad_len);
	TRY(create_enc_structure(recipient_aad, &aad));
	PRINT_ARRAY("AAD encoded", aad.ptr, aad.len);
	struct byte_array tag = BYTE_ARRAY_INIT(
		(in_ciphertext->ptr + in_ciphertext->len - AUTH_TAG_LEN), AUTH_TAG_LEN);

	PRINT_ARRAY("Ciphertext", in_ciphertext->ptr, in_ciphertext->len);

	TRY(aead(DECRYPT, in_ciphertext, key, nonce, &aad, out_plaintext,
		 &tag));

	PRINT_ARRAY("Decrypted plaintext", out_plaintext->ptr,
		    out_plaintext->len);
	return ok;
}

enum err oscore_cose_encrypt(struct byte_array *in_plaintext,
			     struct byte_array *out_ciphertext,
			     struct byte_array *nonce,
			     struct byte_array *sender_aad,
			     struct byte_array *key)
{
	// PRINTF("[OSCORE_COSE_ENC] Start, plaintext_len=%d\r\n", in_plaintext->len);
	/* get enc_structure  */
	uint32_t aad_len = sender_aad->len + ENCRYPT0_ENCODING_OVERHEAD;
	BYTE_ARRAY_NEW(aad, MAX_AAD_LEN, aad_len);

	// PRINTF("[OSCORE_COSE_ENC] Creating enc_structure...\r\n");
	TRY(create_enc_structure(sender_aad, &aad));
	PRINT_ARRAY("aad enc structure", aad.ptr, aad.len);

	struct byte_array tag =
		BYTE_ARRAY_INIT(out_ciphertext->ptr + in_plaintext->len, AUTH_TAG_LEN);

	out_ciphertext->len -= tag.len;
	// PRINTF("[OSCORE_COSE_ENC] Calling aead() with nonce_len=%d, aad_len=%d...\r\n", nonce->len, aad.len);
	TRY(aead(ENCRYPT, in_plaintext, key, nonce, &aad, out_ciphertext,
		 &tag));
	// PRINTF("[OSCORE_COSE_ENC] aead() returned\r\n");
	PRINT_ARRAY("tag", tag.ptr, tag.len);
	PRINT_ARRAY("Ciphertext", out_ciphertext->ptr, out_ciphertext->len);
	out_ciphertext->len += tag.len;
	PRINT_ARRAY("Ciphertext + tag", out_ciphertext->ptr,
		    out_ciphertext->len);

	// PRINTF("[OSCORE_COSE_ENC] Complete\r\n");
	return ok;
}
