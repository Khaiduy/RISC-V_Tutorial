/*
 * edhoc_error_msg.c - RFC 9528 §6 wire-format error messages
 *                     + EDHOC-PSK draft -07 §9 uniform-error helper.
 *
 * PSK-library copy. Do NOT cross-link with the standard library's
 * uoscore-uedhoc/src/edhoc/edhoc_error_msg.c — they are independent files
 * for two separately-deployed libraries.
 */
#include "edhoc/edhoc_error_msg.h"
#include <string.h>

/* CBOR helpers ----------------------------------------------------------- */

/* Encode a signed int as CBOR. Returns bytes written. */
static uint32_t cbor_enc_int(uint8_t *buf, uint32_t cap, int val)
{
	if (val >= 0) {
		uint32_t u = (uint32_t)val;
		if (u <= 23) {
			if (cap < 1) return 0;
			buf[0] = (uint8_t)u;
			return 1;
		}
		if (u <= 0xFF) {
			if (cap < 2) return 0;
			buf[0] = 0x18;
			buf[1] = (uint8_t)u;
			return 2;
		}
		if (u <= 0xFFFF) {
			if (cap < 3) return 0;
			buf[0] = 0x19;
			buf[1] = (uint8_t)(u >> 8);
			buf[2] = (uint8_t)u;
			return 3;
		}
		if (cap < 5) return 0;
		buf[0] = 0x1A;
		buf[1] = (uint8_t)(u >> 24);
		buf[2] = (uint8_t)(u >> 16);
		buf[3] = (uint8_t)(u >> 8);
		buf[4] = (uint8_t)u;
		return 5;
	} else {
		uint32_t u = (uint32_t)(-(val + 1));
		if (u <= 23) {
			if (cap < 1) return 0;
			buf[0] = 0x20 | (uint8_t)u;
			return 1;
		}
		if (u <= 0xFF) {
			if (cap < 2) return 0;
			buf[0] = 0x38;
			buf[1] = (uint8_t)u;
			return 2;
		}
		if (u <= 0xFFFF) {
			if (cap < 3) return 0;
			buf[0] = 0x39;
			buf[1] = (uint8_t)(u >> 8);
			buf[2] = (uint8_t)u;
			return 3;
		}
		if (cap < 5) return 0;
		buf[0] = 0x3A;
		buf[1] = (uint8_t)(u >> 24);
		buf[2] = (uint8_t)(u >> 16);
		buf[3] = (uint8_t)(u >> 8);
		buf[4] = (uint8_t)u;
		return 5;
	}
}

/* Encode a text string. */
static uint32_t cbor_enc_tstr(uint8_t *buf, uint32_t cap,
			      const char *s, uint32_t len)
{
	uint32_t hdr;
	if (len <= 23) {
		if (cap < 1 + len) return 0;
		buf[0] = 0x60 | (uint8_t)len;
		hdr = 1;
	} else if (len <= 0xFF) {
		if (cap < 2 + len) return 0;
		buf[0] = 0x78;
		buf[1] = (uint8_t)len;
		hdr = 2;
	} else if (len <= 0xFFFF) {
		if (cap < 3 + len) return 0;
		buf[0] = 0x79;
		buf[1] = (uint8_t)(len >> 8);
		buf[2] = (uint8_t)len;
		hdr = 3;
	} else {
		return 0;
	}
	memcpy(buf + hdr, s, len);
	return hdr + len;
}

/* Decode an int (signed). Returns 0 on failure, bytes consumed otherwise. */
static uint32_t cbor_dec_int(const uint8_t *buf, uint32_t len, int *out)
{
	if (len < 1) return 0;
	uint8_t mt = buf[0] >> 5;
	uint8_t ai = buf[0] & 0x1F;
	uint32_t val_bytes;
	uint64_t val;

	if (mt != 0 && mt != 1) return 0;

	if (ai <= 23) {
		val = ai;
		val_bytes = 0;
	} else if (ai == 24) {
		if (len < 2) return 0;
		val = buf[1];
		val_bytes = 1;
	} else if (ai == 25) {
		if (len < 3) return 0;
		val = ((uint64_t)buf[1] << 8) | buf[2];
		val_bytes = 2;
	} else if (ai == 26) {
		if (len < 5) return 0;
		val = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16) |
		      ((uint64_t)buf[3] << 8) | buf[4];
		val_bytes = 4;
	} else {
		return 0;
	}

	if (mt == 0) {
		if (val > 0x7FFFFFFF) return 0;
		*out = (int)val;
	} else {
		if (val > 0x7FFFFFFF) return 0;
		*out = -1 - (int)val;
	}
	return 1 + val_bytes;
}

/* Public API ------------------------------------------------------------- */

int edhoc_map_to_wire_err_code(enum err internal)
{
	switch (internal) {
	case unsupported_cipher_suite:
		return EDHOC_ERR_CODE_WRONG_CIPHER_SUITE;
	case credential_not_found:
	case no_such_ca:
		return EDHOC_ERR_CODE_UNKNOWN_CRED;
	default:
		return EDHOC_ERR_CODE_UNSPECIFIED;
	}
}

enum err edhoc_build_error_message(uint8_t *out, uint32_t out_max,
				   int err_code,
				   const char *diag, uint32_t diag_len,
				   const uint8_t *info_cbor, uint32_t info_cbor_len,
				   uint32_t *out_len)
{
	if (!out || !out_len) return wrong_parameter;

	uint32_t pos = 0;
	uint32_t w = cbor_enc_int(out + pos, out_max - pos, err_code);
	if (w == 0) return buffer_to_small;
	pos += w;

	switch (err_code) {
	case EDHOC_ERR_CODE_UNSPECIFIED:
		if (!diag) diag = "EDHOC error";
		if (diag_len == 0) diag_len = (uint32_t)strlen(diag);
		w = cbor_enc_tstr(out + pos, out_max - pos, diag, diag_len);
		if (w == 0) return buffer_to_small;
		pos += w;
		break;
	case EDHOC_ERR_CODE_WRONG_CIPHER_SUITE:
		if (!info_cbor || info_cbor_len == 0) return wrong_parameter;
		if (pos + info_cbor_len > out_max) return buffer_to_small;
		memcpy(out + pos, info_cbor, info_cbor_len);
		pos += info_cbor_len;
		break;
	case EDHOC_ERR_CODE_UNKNOWN_CRED:
		if (pos + 1 > out_max) return buffer_to_small;
		out[pos++] = 0xF5; /* CBOR true */
		break;
	default:
		return wrong_parameter;
	}

	*out_len = pos;
	return ok;
}

/* draft-ietf-lake-edhoc-psk-07 §9: all msg_3 processing failures (AEAD fail,
 * unknown credential, malformed input) MUST be externally indistinguishable.
 * Always emit ERR_CODE=1 with a fixed opaque diagnostic. */
enum err edhoc_build_error_message_psk_uniform(uint8_t *out, uint32_t out_max,
					       uint32_t *out_len)
{
	/* Single canonical diagnostic — same bytes regardless of underlying cause.
	 * Diagnostic text is intentionally generic per draft-07 §9 indistinguishability. */
	static const char DIAG[] = "EDHOC-PSK message_3 processing failed";
	return edhoc_build_error_message(out, out_max,
					 EDHOC_ERR_CODE_UNSPECIFIED,
					 DIAG, sizeof(DIAG) - 1,
					 NULL, 0, out_len);
}

bool edhoc_is_error_message(const uint8_t *buf, uint32_t len)
{
	if (len < 1) return false;
	uint8_t mt = buf[0] >> 5;
	return (mt == 0 || mt == 1);
}

enum err edhoc_parse_error_message(const uint8_t *buf, uint32_t buf_len,
				   int *err_code,
				   struct const_byte_array *err_info)
{
	if (!buf || !err_code) return wrong_parameter;
	int code = 0;
	uint32_t consumed = cbor_dec_int(buf, buf_len, &code);
	if (consumed == 0) return cbor_decoding_error;
	*err_code = code;
	if (err_info) {
		err_info->ptr = buf + consumed;
		err_info->len = buf_len - consumed;
	}
	return ok;
}
