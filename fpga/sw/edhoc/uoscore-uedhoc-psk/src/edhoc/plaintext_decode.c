/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <stdbool.h>

#include "edhoc/retrieve_cred.h"
#include "edhoc/plaintext.h"
#include "edhoc/int_encode_decode.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_plaintext2.h"
#include "cbor/edhoc_decode_plaintext3.h"
#include "cbor/edhoc_encode_id_cred_x.h"
#include "cbor/edhoc_decode_bstr_type.h"
#include "edhoc/bstr_encode_decode.h"

/**
 * @brief			Decodes PSK mode PLAINTEXT_2A = (C_R, ?EAD_2).
 * 				In PSK mode, there is no ID_CRED_R or MAC_2.
 * @param ptxt			The plaintext buffer.
 * @param c_r			Output for C_R.
 * @param ead			Output for optional EAD_2.
 * @retval			Ok or error.
 */
static enum err plaintext2_split_psk(struct byte_array *ptxt,
				     struct byte_array *c_r,
				     struct byte_array *ead)
{
	uint32_t offset = 0;
	
#ifdef DEBUG_PRINT
	PRINT_MSG("[PSK_P2A] Decoding PLAINTEXT_2A (PSK mode)\r\n");
	PRINT_ARRAY("PLAINTEXT_2A", ptxt->ptr, ptxt->len);
#endif
	
	/* Decode C_R (first element) - can be int or bstr */
	/* Check the first byte to determine type */
	if (ptxt->len == 0) {
		PRINT_MSG("[PSK_P2A] ERROR: Empty plaintext\r\n");
		return cbor_decoding_error;
	}
	
	uint8_t first_byte = ptxt->ptr[0];
#ifdef DEBUG_PRINT
	PRINTF("[PSK_P2A] first_byte=0x%02x\r\n", first_byte);
#endif
	
	/* CBOR major type is in bits 7-5 */
	uint8_t major_type = (first_byte >> 5) & 0x07;
#ifdef DEBUG_PRINT
	PRINTF("[PSK_P2A] major_type=%d\r\n", major_type);
#endif
	
	if (major_type == 0 || major_type == 1) {
		/* Major type 0 = unsigned int, type 1 = negative int */
		/* C_R is an integer */
		int32_t c_r_int;
		struct byte_array int_buf = {.ptr = ptxt->ptr, .len = ptxt->len};
		TRY(decode_int(&int_buf, &c_r_int));
#ifdef DEBUG_PRINT
		PRINTF("[PSK_P2A] C_R decoded as int: %d\r\n", c_r_int);
#endif
		TRY(encode_int(&c_r_int, 1, c_r));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("C_R (encoded)", c_r->ptr, c_r->len);
#endif
		/* CBOR integer encoding: 
		 * - Values 0-23 (and -1 to -24): 1 byte (0x00-0x17, 0x20-0x37)
		 * - Values 24-255 (and -25 to -256): 2 bytes (0x18/0x38 + value byte)
		 * - Values 256-65535: 3 bytes (0x19/0x39 + 2 value bytes)
		 * - etc.
		 */
		uint8_t additional_info = first_byte & 0x1F;
		if (additional_info < 24) {
			/* Values 0-23 (positive) or -1 to -24 (negative) */
			offset = 1;
		} else if (additional_info == 24) {
			/* 1-byte value follows */
			offset = 2;
		} else if (additional_info == 25) {
			/* 2-byte value follows */
			offset = 3;
		} else if (additional_info == 26) {
			/* 4-byte value follows */
			offset = 5;
		} else if (additional_info == 27) {
			/* 8-byte value follows */
			offset = 9;
		} else {
			PRINTF("[PSK_P2A] ERROR: Invalid CBOR integer encoding (additional_info=%d)\r\n", additional_info);
			return cbor_decoding_error;
		}
#ifdef DEBUG_PRINT
		PRINTF("[PSK_P2A] C_R consumed %d bytes (additional_info=%d)\r\n", offset, additional_info);
#endif
	} else if (major_type == 2) {
		/* Major type 2 = byte string */
		/* C_R is a bstr */
		struct byte_array bstr_buf = {.ptr = ptxt->ptr, .len = ptxt->len};
		
		/* Decode the bstr to get C_R */
		struct zcbor_string str;
		size_t decode_len = 0;
		TRY_EXPECT(cbor_decode_bstr_type_b_str(bstr_buf.ptr, bstr_buf.len,
						       &str, &decode_len), 0);
		TRY(_memcpy_s(c_r->ptr, c_r->len, str.value, (uint32_t)str.len));
		c_r->len = (uint32_t)str.len;
		offset = (uint32_t)decode_len;
#ifdef DEBUG_PRINT
		PRINTF("[PSK_P2A] C_R decoded as bstr, len=%u, consumed %u bytes\r\n", 
		        c_r->len, offset);
		PRINT_ARRAY("C_R (bstr)", c_r->ptr, c_r->len);
#endif
	} else {
		PRINTF("[PSK_P2A] ERROR: Unexpected CBOR major type: %d\r\n", major_type);
		return cbor_decoding_error; /* Unexpected type */
	}
	
	/* Decode ?EAD_2 (optional second element) */
#ifdef DEBUG_PRINT
	PRINTF("[PSK_P2A] Checking for EAD_2: offset=%u, ptxt->len=%u\r\n", 
	        offset, ptxt->len);
#endif
	if (offset < ptxt->len) {
		struct byte_array ead_buf = {
			.ptr = ptxt->ptr + offset,
			.len = ptxt->len - offset
		};
#ifdef DEBUG_PRINT
		PRINTF("[PSK_P2A] Decoding EAD_2, len=%u\r\n", ead_buf.len);
		PRINT_ARRAY("EAD_2 buffer", ead_buf.ptr, ead_buf.len);
#endif
		TRY(decode_bstr(&ead_buf, ead));
#ifdef DEBUG_PRINT
		PRINTF("[PSK_P2A] EAD_2 decoded, len=%u\r\n", ead->len);
		PRINT_ARRAY("EAD_2", ead->ptr, ead->len);
#endif
	} else {
		ead->len = 0;
		ead->ptr = NULL;
#ifdef DEBUG_PRINT
		PRINT_MSG("[PSK_P2A] No EAD_2 in PLAINTEXT_2A\r\n");
#endif
	}
	
#ifdef DEBUG_PRINT
	PRINT_MSG("[PSK_P2A] Decoding complete\r\n");
#endif
	return ok;
}

enum err plaintext_split_psk_msg2(struct byte_array *ptxt,
				  struct byte_array *c_r,
				  struct byte_array *ead)
{
	return plaintext2_split_psk(ptxt, c_r, ead);
}
