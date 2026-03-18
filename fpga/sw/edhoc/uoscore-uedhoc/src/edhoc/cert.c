/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdbool.h>
#include <stdint.h>

#include "edhoc/buffer_sizes.h"

#include "edhoc/cert.h"

#include "common/memcpy_s.h"
#include "common/oscore_edhoc_error.h"
#include "common/crypto_wrapper.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_cert.h"

#ifdef MBEDTLS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <psa/crypto.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

struct deser_sign_ctx_s {
	uint8_t *seek;
	uint8_t *end;
	int unit_size;
};

static void deser_sign_ctx_init(struct deser_sign_ctx_s *ctx, uint8_t *seek,
				uint8_t *end, int unit_size)
{
	ctx->seek = seek;
	ctx->end = end;
	ctx->unit_size = unit_size;
}

static int deser_sign_cb(void *void_ctx, int tag, unsigned char *start,
			 size_t len)
{
	if (tag == MBEDTLS_ASN1_INTEGER) {
		struct deser_sign_ctx_s *ctx = void_ctx;
		uint8_t *unit_end = ctx->seek + ctx->unit_size;
		if (unit_end <= ctx->end) {
			memcpy(ctx->seek, start + len - ctx->unit_size,
			       (uint32_t)ctx->unit_size);
			ctx->seek = unit_end;
		}
	}
	return 0;
}

static int find_pk_cb(void *void_ppk, int tag, unsigned char *start, size_t len)
{
	(void)len;

	if (tag == MBEDTLS_ASN1_BIT_STRING) {
		uint8_t **pk = void_ppk;
		*pk = start;
	}
	return 0;
}

#define PSA_KEY_ALL_USAGES                                                     \
	(PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT |   \
	 PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_SIGN_MESSAGE |                  \
	 PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_SIGN_HASH |              \
	 PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_DERIVE)

#else /* MBEDTLS */

#define ISSUER_CN_OID "\x55\x04\x03"

#define EXPECTO_TAG(tag, cursor, len)                                          \
	if (*cursor != tag) {                                                  \
		rv = wrong_parameter;                                          \
		PRINTF(RED                                                     \
		       "Runtime error: expected %s tag at %s:%d\n\n" RESET,    \
		       #tag, __FILE__, __LINE__);                              \
		break;                                                         \
	} else {                                                               \
		cursor++;                                                      \
		mbedtls_asn1_get_len(&cursor, end, &len);                      \
		if (0 == *cursor) {                                            \
			cursor++;                                              \
			len--;                                                 \
		}                                                              \
	}

enum tag_map_enum {
	ASN1_INTEGER = 0x02,
	ASN1_BIT_STRING = 0x03,
	ASN1_SEQUENCE = 0x30
};

/* Extracted from mbedtls library; asn1_parse.c */
/* License for file: Apache-2.0 */
/* ASN.1 DER encoding is described in ITU-T X.690 standard. */
/* First bit of length byte contains information, if length
   value shall be concatenated with following byte length. */
static int mbedtls_asn1_get_len(const unsigned char **p,
				const unsigned char *end, uint32_t *len)
{
	if ((end - *p) < 1)
		return (buffer_to_small);

	if ((**p & 0x80) == 0)
		*len = *(*p)++;
	else {
		switch (**p & 0x7F) {
		case 1:
			if ((end - *p) < 2)
				return (buffer_to_small);

			*len = (*p)[1];
			(*p) += 2;
			break;

		case 2:
			if ((end - *p) < 3)
				return (buffer_to_small);

			*len = ((uint32_t)(*p)[1] << 8) | (*p)[2];
			(*p) += 3;
			break;

		case 3:
			if ((end - *p) < 4)
				return (buffer_to_small);

			*len = ((uint32_t)(*p)[1] << 16) |
			       ((uint32_t)(*p)[2] << 8) | (*p)[3];
			(*p) += 4;
			break;

		case 4:
			if ((end - *p) < 5)
				return (buffer_to_small);

			*len = ((uint32_t)(*p)[1] << 24) |
			       ((uint32_t)(*p)[2] << 16) |
			       ((uint32_t)(*p)[3] << 8) | (*p)[4];
			(*p) += 5;
			break;

		default:
			return (buffer_to_small);
		}
	}

	if (*len > (uint32_t)(end - *p))
		return (buffer_to_small);

	return (0);
}

#endif /* MBEDTLS */

/**
 * @brief retrieves the public key of the CA from CRED_ARRAY.
 * 
 * 
 * @param[in] cred_array contains the public key of the root CA
 * @param[in] issuer the issuer name, i.e. the name of the CA
 * @param[out] root_pk the root public key
 * @return error code
 */
static enum err ca_pk_get(const struct cred_array *cred_array,
			  const uint8_t *issuer, struct byte_array *root_pk)
{
	/* when single credential without certificate is stored, return stored ca_pk if available */
	if (1 == cred_array->len
#ifdef MBEDTLS
	    /* In case no MBEDTLS is enabled, issuer identification is not extracted from certificate */
	    && (0 == cred_array->ptr[0].ca.len ||
		NULL == cred_array->ptr[0].ca.ptr)
#endif
	) {
		if (NULL == cred_array->ptr[0].ca_pk.ptr ||
		    0 == cred_array->ptr[0].ca_pk.len) {
			return no_such_ca;
		}

		root_pk->ptr = cred_array->ptr[0].ca_pk.ptr;
		root_pk->len = cred_array->ptr[0].ca_pk.len;
		return ok;
	}

#ifdef MBEDTLS
	/* Accept only certificate based search if multiple credentials available*/
	for (uint16_t i = 0; i < cred_array->len; i++) {
		if (NULL == cred_array->ptr[i].ca.ptr ||
		    0 == cred_array->ptr[i].ca.len) {
			continue;
		}

		PRINT_ARRAY("cred_array[i].ca.ptr", cred_array->ptr[i].ca.ptr,
			    cred_array->ptr[i].ca.len);

		mbedtls_x509_crt m_cert;
		mbedtls_x509_crt_init(&m_cert);

		/* parse the certificate */
		TRY_EXPECT(mbedtls_x509_crt_parse_der_nocopy(
				   &m_cert, cred_array->ptr[i].ca.ptr,
				   cred_array->ptr[i].ca.len),
			   0);

		const mbedtls_x509_name *p = &m_cert.subject;
		const mbedtls_asn1_buf *subject_id = NULL;
		while (p) {
			if (0 == MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &p->oid)) {
				subject_id = &p->val;
			}
			p = p->next;
		};

		if (0 == memcmp(subject_id->p, issuer, subject_id->len)) {
			root_pk->ptr = cred_array->ptr[i].ca_pk.ptr;
			root_pk->len = cred_array->ptr[i].ca_pk.len;
			PRINT_ARRAY("Root PK of the CA", root_pk->ptr,
				    root_pk->len);
			mbedtls_x509_crt_free(&m_cert);
			return ok;
		} else {
			mbedtls_x509_crt_free(&m_cert);
		}
	}
#endif /* MBEDTLS */

	return no_such_ca;
}

enum err cert_c509_verify(struct const_byte_array *cert,
			  const struct cred_array *cred_array,
			  struct byte_array *pk, bool *verified)
{
	return certificate_authentication_failed;
}

enum err cert_x509_verify(struct const_byte_array *cert,
			  const struct cred_array *cred_array,
			  struct byte_array *pk, bool *verified)
{
	return certificate_authentication_failed;
}
