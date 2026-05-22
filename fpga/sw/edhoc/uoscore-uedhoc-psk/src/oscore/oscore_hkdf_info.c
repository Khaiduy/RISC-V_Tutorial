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

#include "oscore/aad.h"
#include "oscore/oscore_hkdf_info.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

#include "cbor/oscore_info.h"

/*
HKDF = composition of HKDF-Extract and HKDF-Expand (RFC5869)
output = HKDF(salt, IKM, info, L
* salt = Master Salt
* IKM = Master Secret
* info = CBOR-array [
     id: bstr,
     alg_aead: int / tstr,
     type: tstr,
     L: uint,
  ]
     + id: SenderID / RecipientID for keys; empty string for CommonIV
     + alg_aead: AEAD Algorithm
     + type: "Key" / "IV", ascii string without nul-terminator
     + L: size of key/iv for AEAD alg
         - in bytes
* https://www.iana.org/assignments/cose/cose.xhtml
*/

enum err oscore_create_hkdf_info(struct byte_array *id,
				 struct byte_array *id_context,
				 enum AEAD_algorithm aead_alg,
				 enum derive_type type, struct byte_array *out)
{
	// PRINTF("[HKDF_INFO] Start: type=%d, aead_alg=%d\r\n", type, aead_alg);
	struct oscore_info info_struct;

	char type_enc[10] = {0};  /* Initialize to zeros */
	uint8_t len = 0;
	uint8_t type_len = 0;
	switch (type) {
	case KEY:
		type_enc[0] = 'K';
		type_enc[1] = 'e';
		type_enc[2] = 'y';
		type_enc[3] = '\0';
		type_len = 3;
		len = 16;
		break;
	case IV:
		type_enc[0] = 'I';
		type_enc[1] = 'V';
		type_enc[2] = '\0';
		type_len = 2;
#ifdef ASCON
		len = 16;  /* Ascon uses 16-byte IV */
#else
		len = 13;  /* AES-CCM uses 13-byte IV */
#endif
		break;
	}
	// PRINTF("[HKDF_INFO] Type=%s, len=%d\r\n", type_enc, len);

	info_struct.oscore_info_id.value = id->ptr;
	info_struct.oscore_info_id.len = id->len;
	// PRINTF("[HKDF_INFO] ID len=%d\r\n", id->len);

	if (id_context->len == 0) {
		info_struct.oscore_info_id_context_choice =
			oscore_info_id_context_nil_c;
		// PRINTF("[HKDF_INFO] ID context: nil\r\n");
	} else {
		info_struct.oscore_info_id_context_choice =
			oscore_info_id_context_bstr_c;
		info_struct.oscore_info_id_context_bstr.value =
			id_context->ptr;
		info_struct.oscore_info_id_context_bstr.len = id_context->len;
		// PRINTF("[HKDF_INFO] ID context len=%d\r\n", id_context->len);
	}
	info_struct.oscore_info_alg_aead_choice = oscore_info_alg_aead_int_c;
	info_struct.oscore_info_alg_aead_int = (int32_t)aead_alg;
	// PRINTF("[HKDF_INFO] AEAD alg=%d\r\n", aead_alg);

	info_struct.oscore_info_type.value = (uint8_t *)type_enc;
	info_struct.oscore_info_type.len = type_len;  /* Use known length, not strlen */
	// PRINTF("[HKDF_INFO] Type string len=%d\r\n", type_len);

	info_struct.oscore_info_L = len;
	// PRINTF("[HKDF_INFO] L=%d\r\n", len);

	size_t payload_len_out;

	// PRINTF("[HKDF_INFO] Calling cbor_encode_oscore_info...\r\n");
	TRY_EXPECT(cbor_encode_oscore_info(out->ptr, out->len, &info_struct,
					   &payload_len_out),
		   0);
	// PRINTF("[HKDF_INFO] CBOR encode done, len=%d\r\n", (int)payload_len_out);

	out->len = (uint32_t)payload_len_out;
	// PRINTF("[HKDF_INFO] Complete\r\n");
	return ok;
}
