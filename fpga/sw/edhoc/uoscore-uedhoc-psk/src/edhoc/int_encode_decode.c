/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"

#include "cbor/edhoc_encode_int_type.h"
#include "cbor/edhoc_decode_int_type.h"

bool c_x_is_encoded_int(const struct byte_array *c_i)
{
	if (c_i->len == 0) {
		return false;
	}
	
	uint8_t first_byte = c_i->ptr[0];
	uint8_t major_type = (first_byte >> 5) & 0x07;
	
	/* CBOR major type 0 = unsigned int, type 1 = negative int */
	if (major_type == 0 || major_type == 1) {
		uint8_t additional_info = first_byte & 0x1F;
		
		/* Check if length matches the encoding:
		 * - additional_info 0-23: 1 byte total
		 * - additional_info 24: 2 bytes total (0x18/0x38 + 1 value byte)
		 * - additional_info 25: 3 bytes total (0x19/0x39 + 2 value bytes)
		 * - etc.
		 */
		if (additional_info < 24 && c_i->len == 1) {
			return true;
		} else if (additional_info == 24 && c_i->len == 2) {
			return true;
		} else if (additional_info == 25 && c_i->len == 3) {
			return true;
		} else if (additional_info == 26 && c_i->len == 5) {
			return true;
		} else if (additional_info == 27 && c_i->len == 9) {
			return true;
		}
	}
	
	return false;
}


bool c_r_is_raw_int(const struct byte_array *c_r)
{
	if (c_r->len == 1 && c_r->ptr[0] >= -24 && c_r->ptr[0] <= 23) {
		return true;
	} else {
		return false;
	}
}


enum err encode_int(const int32_t *in, uint32_t in_len, struct byte_array *out)
{
	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_int_type_i(out->ptr, out->len, in,
					  &payload_len_out),
		   0);
	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err decode_int(const struct byte_array *in, int32_t *out)
{
	size_t decode_len = 0;
	TRY_EXPECT(cbor_decode_int_type_i(in->ptr, in->len, out, &decode_len),
		   0);
	if (decode_len != 1) {
		return cbor_decoding_error;
	}
	return ok;
}