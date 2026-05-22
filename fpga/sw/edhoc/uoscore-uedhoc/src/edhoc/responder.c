/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"
#include "edhoc_internal.h"

#ifdef TIMING_BREAKDOWN
#define _RDC(v) __asm__ volatile("rdcycle %0" : "=r"(v))
volatile uint32_t _tb_msg2_cyc = 0;
volatile uint32_t _tb_msg3proc_cyc = 0;
#endif

#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/edhoc_error_msg.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/suites.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "cbor/edhoc_decode_message_1.h"
#include "cbor/edhoc_encode_message_2.h"
#include "cbor/edhoc_decode_message_3.h"

#define CBOR_UINT_SINGLE_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_UINT_MULTI_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_BSTR_TYPE_MIN_VALUE (0x40)
#define CBOR_BSTR_TYPE_MAX_VALUE (0x57)

/**
 * @brief   			Parses message 1.
 * @param[in] msg1 		Message 1.
 * @param[out] method 		EDHOC method.
 * @param[out] suites_i 	Cipher suites suported by the initiator
 * @param[out] g_x 		Public ephemeral key of the initiator.
 * @param[out] c_i 		Connection identifier of the initiator.
 * @param[out] ead1 		External authorized data 1.
 * @retval 			Ok or error code.
 */
static inline enum err
msg1_parse(struct byte_array *msg1, enum method_type *method,
	   struct byte_array *suites_i, struct byte_array *g_x,
	   struct byte_array *c_i, struct byte_array *ead1)
{
	uint32_t i;
	struct message_1 m;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_message_1(msg1->ptr, msg1->len, &m, &decode_len),
		   0);

	/*METHOD*/
	if ((m.message_1_METHOD > INITIATOR_SDHK_RESPONDER_SDHK) ||
	    (m.message_1_METHOD < INITIATOR_SK_RESPONDER_SK)) {
		return wrong_parameter;
	}
	*method = (enum method_type)m.message_1_METHOD;
	PRINTF("msg1 METHOD: %d\n", (int)*method);

	/*SUITES_I*/
	if (m.message_1_SUITES_I_choice == message_1_SUITES_I_int_c) {
		/*the initiator supports only one suite*/
		suites_i->ptr[0] = (uint8_t)m.message_1_SUITES_I_int;
		suites_i->len = 1;
	} else {
		if (0 == m.SUITES_I_suite_l_suite_count) {
			return suites_i_list_empty;
		}

		/*the initiator supports more than one suite*/
		if (m.SUITES_I_suite_l_suite_count > suites_i->len) {
			return suites_i_list_to_long;
		}

		for (i = 0; i < m.SUITES_I_suite_l_suite_count; i++) {
			suites_i->ptr[i] = (uint8_t)m.SUITES_I_suite_l_suite[i];
		}
		suites_i->len = (uint32_t)m.SUITES_I_suite_l_suite_count;
	}
	PRINT_ARRAY("msg1 SUITES_I", suites_i->ptr, suites_i->len);

	/*G_X*/
	TRY(_memcpy_s(g_x->ptr, g_x->len, m.message_1_G_X.value,
		      (uint32_t)m.message_1_G_X.len));
	g_x->len = (uint32_t)m.message_1_G_X.len;
	PRINT_ARRAY("msg1 G_X", g_x->ptr, g_x->len);

	/*C_I*/
	if (m.message_1_C_I_choice == message_1_C_I_int_c) {
		c_i->ptr[0] = (uint8_t)m.message_1_C_I_int;
		c_i->len = 1;
	} else {
		TRY(_memcpy_s(c_i->ptr, c_i->len, m.message_1_C_I_bstr.value,
			      (uint32_t)m.message_1_C_I_bstr.len));
		c_i->len = (uint32_t)m.message_1_C_I_bstr.len;
	}
	PRINT_ARRAY("msg1 C_I_raw", c_i->ptr, c_i->len);

	/*ead_1*/
	if (m.message_1_ead_1_present) {
		TRY(_memcpy_s(ead1->ptr, ead1->len, m.message_1_ead_1.value,
			      (uint32_t)m.message_1_ead_1.len));
		ead1->len = (uint32_t)m.message_1_ead_1.len;
		PRINT_ARRAY("msg1 ead_1", ead1->ptr, ead1->len);
	}
	return ok;
}

/**
 * @brief   			Checks if the selected cipher suite 
 * 				(the first in the list received from the 
 * 				initiator) is supported.
 * @param selected 		The selected suite.
 * @param[in] suites_r 		The list of suported cipher suites.
 * @retval  			True if supported.
 */
static inline bool selected_suite_is_supported(uint8_t selected,
					       struct byte_array *suites_r)
{
	for (uint32_t i = 0; i < suites_r->len; i++) {
		if (suites_r->ptr[i] == selected) {
			PRINTF("Suite %d will be used in this EDHOC run.\n",
			       selected);
			return true;
		}
	}
	return false;
}

/**
 * @brief   			Encodes message 2.
 * @param[in] g_y 		Public ephemeral DH key of the responder. 
 * @param[in] c_r 		Connection identifier of the responder.
 * @param[in] ciphertext_2 	The ciphertext.
 * @param[out] msg2 		The encoded message.
 * @retval  			Ok or error code.
 */
static inline enum err msg2_encode(const struct byte_array *g_y,
				   struct byte_array *c_r,
				   const struct byte_array *ciphertext_2,
				   struct byte_array *msg2)
{
	BYTE_ARRAY_NEW(g_y_ciphertext_2, G_Y_CIPHERTEXT_2,
		       g_y->len + ciphertext_2->len);

	memcpy(g_y_ciphertext_2.ptr, g_y->ptr, g_y->len);
	memcpy(g_y_ciphertext_2.ptr + g_y->len, ciphertext_2->ptr,
	       ciphertext_2->len);

	TRY(encode_bstr(&g_y_ciphertext_2, msg2));

	PRINT_ARRAY("message_2 (CBOR Sequence)", msg2->ptr, msg2->len);
	return ok;
}

enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  struct byte_array *c_i)
{
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	enum method_type method = INITIATOR_SK_RESPONDER_SK;
	BYTE_ARRAY_NEW(suites_i, SUITES_I_SIZE, SUITES_I_SIZE);
	BYTE_ARRAY_NEW(g_x, G_X_SIZE, G_X_SIZE);

	TRY(msg1_parse(&rc->msg, &method, &suites_i, &g_x, c_i, &rc->ead));

	if (suites_i.len == 0) {
		return wrong_parameter;
	}
	if (!(selected_suite_is_supported(suites_i.ptr[suites_i.len - 1],
					  &c->suites_r))) {
		/* Surface a real error code; the caller (run_extended) emits
		 * the RFC §6 wire-format error message with ERR_CODE=2 and
		 * SUITES_R as ERR_INFO. */
		return unsupported_cipher_suite;
	}

	/*get cipher suite*/
	TRY(get_suite((enum suite_label)suites_i.ptr[suites_i.len - 1],
		      &rc->suite));

	bool static_dh_r;
	authentication_type_get(method, &rc->static_dh_i, &static_dh_r);

	/******************* create and send message 2*************************/
	BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &c->g_y, &th2));

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->y, &g_x, g_xy.ptr));

	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);

	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);

	/*derive prk_3e2m*/
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, &th2, &PRK_2e, &g_x,
		       &c->r, rc->prk_3e2m.ptr));
	PRINT_ARRAY("prk_3e2m", rc->prk_3e2m.ptr, rc->prk_3e2m.len);

	/*compute signature_or_MAC_2*/
	BYTE_ARRAY_NEW(sign_or_mac_2, SIGNATURE_SIZE,
		       get_signature_len(rc->suite.edhoc_sign));

	TRY(signature_or_mac(GENERATE, static_dh_r, &rc->suite, &c->sk_r,
			     &c->pk_r, &rc->prk_3e2m, &c->c_r, &th2,
			     &c->id_cred_r, &c->cred_r, &c->ead_2, MAC_2,
			     &sign_or_mac_2));

	/*compute ciphertext_2*/
	BYTE_ARRAY_NEW(plaintext_2, PLAINTEXT2_SIZE,
		       AS_BSTR_SIZE(c->c_r.len) + c->id_cred_r.len +
			       AS_BSTR_SIZE(sign_or_mac_2.len) + c->ead_2.len);
	BYTE_ARRAY_NEW(ciphertext_2, CIPHERTEXT2_SIZE, plaintext_2.len);

	TRY(ciphertext_gen(CIPHERTEXT2, &rc->suite, &c->c_r, &c->id_cred_r,
			   &sign_or_mac_2, &c->ead_2, &PRK_2e, &th2,
			   &ciphertext_2, &plaintext_2));

	/* Clear the message buffer. */
	memset(rc->msg.ptr, 0, rc->msg.len);
	rc->msg.len = sizeof(rc->msg_buf);
	/*message 2 create*/
	TRY(msg2_encode(&c->g_y, &c->c_r, &ciphertext_2, &rc->msg));

	TRY(th34_calculate(rc->suite.edhoc_hash, &th2, &plaintext_2, &c->cred_r,
			   &rc->th3));

	return ok;
}

enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		      struct byte_array *initiator_pk)
{
	BYTE_ARRAY_NEW(ctxt3, CIPHERTEXT3_SIZE, rc->msg.len);
	TRY(decode_bstr(&rc->msg, &ctxt3));
	PRINT_ARRAY("CIPHERTEXT_3", ctxt3.ptr, ctxt3.len);

	BYTE_ARRAY_NEW(id_cred_i, ID_CRED_I_SIZE, ID_CRED_I_SIZE);
	BYTE_ARRAY_NEW(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);

	PRINTF("PLAINTEXT3_SIZE: %d\n", PLAINTEXT3_SIZE);
	PRINTF("ctxt3.len: %d\n", ctxt3.len);
#if defined(_WIN32)
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + 16, // 16 is max aead mac length
		       ctxt3.len);
#else
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ctxt3.len);
#endif

	TRY(ciphertext_decrypt_split(CIPHERTEXT3, &rc->suite, NULL, &id_cred_i,
				     &sign_or_mac, &rc->ead, &rc->prk_3e2m,
				     &rc->th3, &ctxt3, &ptxt3));

	/*check the authenticity of the initiator*/
	BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_i, G_I_SIZE, G_I_SIZE);

	TRY(retrieve_cred(rc->static_dh_i, cred_i_array, &id_cred_i, &cred_i,
			  &pk, &g_i));
	PRINT_ARRAY("CRED_I", cred_i.ptr, cred_i.len);
	PRINT_ARRAY("pk", pk.ptr, pk.len);
	PRINT_ARRAY("g_i", g_i.ptr, g_i.len);

	/* Export public key. */
	if ((NULL != initiator_pk) && (NULL != initiator_pk->ptr)) {
		_memcpy_s(initiator_pk->ptr, initiator_pk->len, pk.ptr, pk.len);
		initiator_pk->len = pk.len;
	}

	/*derive prk_4e3m*/
	TRY(prk_derive(rc->static_dh_i, rc->suite, SALT_4e3m, &rc->th3,
		       &rc->prk_3e2m, &g_i, &c->y, rc->prk_4e3m.ptr));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);

	TRY(signature_or_mac(VERIFY, rc->static_dh_i, &rc->suite, NULL, &pk,
			     &rc->prk_4e3m, &NULL_ARRAY, &rc->th3, &id_cred_i,
			     &cred_i, &rc->ead, MAC_3, &sign_or_mac));

	/*TH4*/
	// ptxt3.len = ptxt3.len - get_aead_mac_len(rc->suite.edhoc_aead);
	TRY(th34_calculate(rc->suite.edhoc_hash, &rc->th3, &ptxt3, &cred_i,
			   &rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	return ok;
}

#ifdef MESSAGE_4
enum err msg4_gen(struct edhoc_responder_context *c, struct runtime_context *rc)
{
	/*Ciphertext 4 calculate*/
	BYTE_ARRAY_NEW(ctxt4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
#if PLAINTEXT4_SIZE != 0
	BYTE_ARRAY_NEW(ptxt4, PLAINTEXT4_SIZE, PLAINTEXT4_SIZE);
#else
	struct byte_array ptxt4 = BYTE_ARRAY_INIT(NULL, 0);
#endif

	TRY(ciphertext_gen(CIPHERTEXT4, &rc->suite, &NULL_ARRAY, &NULL_ARRAY,
			   &NULL_ARRAY, &c->ead_4, &rc->prk_4e3m, &rc->th4,
			   &ctxt4, &ptxt4));

	TRY(encode_bstr(&ctxt4, &rc->msg));

	PRINT_ARRAY("Message 4 ", rc->msg.ptr, rc->msg.len);
	return ok;
}
#endif // MESSAGE_4

/* Encode a suites byte_array (each byte = suite label 0..255) as a CBOR
 * value usable as ERR_INFO for ERR_CODE=2. Single suite → CBOR int; multiple
 * → CBOR array of ints. Returns bytes written or 0 on overflow. */
static uint32_t encode_suites_cbor(uint8_t *buf, uint32_t cap,
				   const struct byte_array *suites)
{
	if (cap < 1 || suites->len == 0) return 0;

	uint32_t pos = 0;
	if (suites->len > 1) {
		/* CBOR array(N) header */
		if (suites->len <= 23) {
			buf[pos++] = 0x80 | (uint8_t)suites->len;
		} else if (suites->len <= 0xFF) {
			if (cap < pos + 2) return 0;
			buf[pos++] = 0x98;
			buf[pos++] = (uint8_t)suites->len;
		} else {
			return 0;
		}
	}
	for (uint32_t i = 0; i < suites->len; i++) {
		uint8_t s = suites->ptr[i];
		if (s <= 23) {
			if (cap < pos + 1) return 0;
			buf[pos++] = s;
		} else {
			if (cap < pos + 2) return 0;
			buf[pos++] = 0x18;
			buf[pos++] = s;
		}
	}
	return pos;
}

/* Build + transmit a wire-format error message and fill the caller's err_msg
 * buffer. Returns the original internal err so the caller can propagate. */
static enum err send_error(
	struct edhoc_responder_context *c, struct runtime_context *rc,
	struct byte_array *err_msg, enum err internal,
	enum err (*tx)(void *sock, struct byte_array *data))
{
	int wire = edhoc_map_to_wire_err_code(internal);
	uint8_t buf[MSG_MAX_SIZE];
	uint32_t buf_len = 0;
	enum err r;

	if (wire == EDHOC_ERR_CODE_WRONG_CIPHER_SUITE) {
		uint8_t info[16];
		uint32_t info_len = encode_suites_cbor(info, sizeof(info),
						       &c->suites_r);
		if (info_len == 0) return internal;
		r = edhoc_build_error_message(buf, sizeof(buf), wire,
					      NULL, 0, info, info_len, &buf_len);
	} else if (wire == EDHOC_ERR_CODE_UNKNOWN_CRED) {
		r = edhoc_build_error_message(buf, sizeof(buf), wire,
					      NULL, 0, NULL, 0, &buf_len);
	} else {
		const char *diag = "EDHOC responder internal error";
		r = edhoc_build_error_message(buf, sizeof(buf), wire,
					      diag, 0, NULL, 0, &buf_len);
	}
	if (r != ok) return internal;

	struct byte_array out = { .ptr = buf, .len = buf_len };
	(void)tx(c->sock, &out);

	if (err_msg && err_msg->ptr && err_msg->len >= buf_len) {
		memcpy(err_msg->ptr, buf, buf_len);
		err_msg->len = buf_len;
	}
	(void)rc;
	return internal;
}

/* On rx, copy a received error message into the caller's err_msg buffer. */
static void store_received_error(const struct byte_array *msg,
				 struct byte_array *err_msg)
{
	if (!err_msg || !err_msg->ptr || err_msg->len < msg->len) return;
	memcpy(err_msg->ptr, msg->ptr, msg->len);
	err_msg->len = msg->len;
}

#define R_FAIL_AND_SEND(_e)                                                    \
	do {                                                                   \
		enum err _r = (_e);                                            \
		if (_r != ok)                                                  \
			return send_error(c, &rc, err_msg, _r, tx);            \
	} while (0)

enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	struct byte_array *initiator_pub_key, struct byte_array *c_i_bytes,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);
	enum err r;

	/*receive message 1 — no error possible here (we are listening) */
	PRINT_MSG("waiting to receive message 1...\n");
	r = rx(c->sock, &rc.msg);
	if (r != ok) return r;

	/*create and send message 2 (includes suite-mismatch error path)*/
#ifdef TIMING_BREAKDOWN
	{ uint32_t _t0, _t1; _RDC(_t0);
	R_FAIL_AND_SEND(msg2_gen(c, &rc, c_i_bytes));
	_RDC(_t1); _tb_msg2_cyc = _t1 - _t0; }
#else
	R_FAIL_AND_SEND(msg2_gen(c, &rc, c_i_bytes));
#endif
	R_FAIL_AND_SEND(ead_process(c->params_ead_process, &rc.ead));
	r = tx(c->sock, &rc.msg);
	if (r != ok) return r;

	/*receive message 3 (may be an error from initiator) */
	PRINT_MSG("waiting to receive message 3...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	r = rx(c->sock, &rc.msg);
	if (r != ok) return r;
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		return error_message_received;
	}

#ifdef TIMING_BREAKDOWN
	{ uint32_t _t0, _t1; _RDC(_t0);
	R_FAIL_AND_SEND(msg3_process(c, &rc, cred_i_array, prk_out, initiator_pub_key));
	_RDC(_t1); _tb_msg3proc_cyc = _t1 - _t0; }
#else
	R_FAIL_AND_SEND(msg3_process(c, &rc, cred_i_array, prk_out, initiator_pub_key));
#endif
	R_FAIL_AND_SEND(ead_process(c->params_ead_process, &rc.ead));

	/*create and send message 4*/
#ifdef MESSAGE_4
	R_FAIL_AND_SEND(msg4_gen(c, &rc));
	r = tx(c->sock, &rc.msg);
	if (r != ok) return r;
#endif // MESSAGE_4
	return ok;
}

enum err edhoc_responder_run(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	BYTE_ARRAY_NEW(c_i, C_I_SIZE, C_I_SIZE);
	return edhoc_responder_run_extended(c, cred_i_array, err_msg, prk_out,
					    &NULL_ARRAY, &c_i, tx, rx,
					    ead_process);
}
