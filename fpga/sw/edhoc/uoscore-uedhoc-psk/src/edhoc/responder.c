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

#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
// #include "edhoc/signature_or_mac_msg.h"  // Not needed for PSK-only
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/suites.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"
#include "edhoc/edhoc_method_type.h"

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
	if ((m.message_1_METHOD > INITIATOR_PSK_RESPONDER_PSK) ||
	    (m.message_1_METHOD < INITIATOR_SK_RESPONDER_SK)) {
		#ifdef DEBUG_PRINT
			kprintf("[R] msg1_parse ERROR: Invalid method %d (valid: 0-4)\r\n", m.message_1_METHOD);
		#endif
		return wrong_parameter;
	}
	*method = (enum method_type)m.message_1_METHOD;
#ifdef DEBUG_PRINT
	PRINTF("msg1 METHOD: %d\r\n", (int)*method);
#endif

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
#ifdef DEBUG_PRINT
	PRINT_ARRAY("msg1 SUITES_I", suites_i->ptr, suites_i->len);
#endif

	/*G_X*/
	TRY(_memcpy_s(g_x->ptr, g_x->len, m.message_1_G_X.value,
		      (uint32_t)m.message_1_G_X.len));
	g_x->len = (uint32_t)m.message_1_G_X.len;
#ifdef DEBUG_PRINT
	PRINT_ARRAY("msg1 G_X", g_x->ptr, g_x->len);
#endif

	/*C_I*/
	if (m.message_1_C_I_choice == message_1_C_I_int_c) {
		c_i->ptr[0] = (uint8_t)m.message_1_C_I_int;
		c_i->len = 1;
	} else {
		TRY(_memcpy_s(c_i->ptr, c_i->len, m.message_1_C_I_bstr.value,
			      (uint32_t)m.message_1_C_I_bstr.len));
		c_i->len = (uint32_t)m.message_1_C_I_bstr.len;
	}
#ifdef DEBUG_PRINT
	PRINT_ARRAY("msg1 C_I_raw", c_i->ptr, c_i->len);
#endif

	/*ead_1*/
	if (m.message_1_ead_1_present) {
		TRY(_memcpy_s(ead1->ptr, ead1->len, m.message_1_ead_1.value,
			      (uint32_t)m.message_1_ead_1.len));
		ead1->len = (uint32_t)m.message_1_ead_1.len;
#ifdef DEBUG_PRINT
		PRINT_ARRAY("msg1 ead_1", ead1->ptr, ead1->len);
#endif
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
		if (suites_r->ptr[i] == selected)
#ifdef DEBUG_PRINT
			PRINTF("Suite %d will be used in this EDHOC run.\r\n",
			       selected);
#endif
		return true;
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

#ifdef DEBUG_PRINT
	PRINT_ARRAY("message_2 (CBOR Sequence)", msg2->ptr, msg2->len);
#endif
	return ok;
}

enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  struct byte_array *c_i)
{
	// TIMING_START(msg2_gen);
#ifdef DEBUG_PRINT
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);
#endif

	enum method_type method = INITIATOR_SK_RESPONDER_SK;
	BYTE_ARRAY_NEW(suites_i, SUITES_I_SIZE, SUITES_I_SIZE);
	BYTE_ARRAY_NEW(g_x, G_X_SIZE, G_X_SIZE);

#ifdef DEBUG_PRINT
	kprintf("[R] Parsing message 1...\r\n");
#endif
	TRY(msg1_parse(&rc->msg, &method, &suites_i, &g_x, c_i, &rc->ead));
#ifdef DEBUG_PRINT
	kprintf("[R] msg1_parse OK, method=%d, suite=%d\r\n", method, suites_i.ptr[suites_i.len - 1]);
#endif

	// TODO this may be a vulnerability in case suites_i.len is zero
	if (!(selected_suite_is_supported(suites_i.ptr[suites_i.len - 1],
					  &c->suites_r))) {
		kprintf("[R] ERROR: Suite %d not supported!\r\n", suites_i.ptr[suites_i.len - 1]);
		// TODO implement here the sending of an error message
		return error_message_sent;
	}
#ifdef DEBUG_PRINT
	kprintf("[R] Suite check passed\r\n");
#endif

	/*get cipher suite*/
	TRY(get_suite((enum suite_label)suites_i.ptr[suites_i.len - 1],
		      &rc->suite));
#ifdef DEBUG_PRINT
	kprintf("[R] get_suite OK, ecdh=%d\r\n", rc->suite.edhoc_ecdh);
#endif

	/* PSK Mode: No static DH authentication */
	rc->static_dh_i = false;
	rc->is_psk = true;
#ifdef DEBUG_PRINT
	kprintf("[R] PSK Mode (Method 4) - no static DH\r\n");
#endif

	/******************* create and send message 2*************************/
	BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));
#ifdef DEBUG_PRINT
	kprintf("[R] Computing TH_2...\r\n");
#endif
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
#ifdef DEBUG_PRINT
	kprintf("[R] hash OK\r\n");
#endif
	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &c->g_y, &th2));
#ifdef DEBUG_PRINT
	kprintf("[R] th2 OK\r\n");
#endif

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);
#ifdef DEBUG_PRINT
	kprintf("[R] Computing ECDH shared secret (ecdh_alg=%d)...\r\n", rc->suite.edhoc_ecdh);
#endif
	// TIMING_START(ecdh);
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->y, &g_x, g_xy.ptr));
	// TIMING_END(ecdh, "ECDH shared_secret_derive");
#ifdef DEBUG_PRINT
	kprintf("[R] shared_secret_derive OK\r\n");

	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);
#endif

	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	// TIMING_START(prk2e);
	TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	// TIMING_END(prk2e, "PRK_2e extraction");
#ifdef DEBUG_PRINT
	PRINT_ARRAY("PRK_2e\r\n", PRK_2e.ptr, PRK_2e.len);
#endif

	/* PSK mode: PRK_3e2m = PRK_2e (no static DH, per draft section 5.1) */
	memcpy(rc->prk_3e2m.ptr, PRK_2e.ptr, PRK_2e.len);
	rc->prk_3e2m.len = PRK_2e.len;
#ifdef DEBUG_PRINT
	PRINT_ARRAY("prk_3e2m (= PRK_2e)\r\n", rc->prk_3e2m.ptr, rc->prk_3e2m.len);
#endif

	/* PSK mode: PLAINTEXT_2A = (C_R, ?EAD_2) - No ID_CRED_R, no MAC_2 */
	uint32_t plaintext_2_len = c->c_r.len + c->ead_2.len;
	BYTE_ARRAY_NEW(plaintext_2, PLAINTEXT2_SIZE, plaintext_2_len);
	BYTE_ARRAY_NEW(ciphertext_2, CIPHERTEXT2_SIZE, plaintext_2_len);

	/* PSK Mode: Encrypt PLAINTEXT_2A with no ID_CRED_R or MAC_2 */
	TRY(ciphertext_gen_psk(CIPHERTEXT2, &rc->suite, &c->c_r, &c->ead_2,
			       &PRK_2e, &th2, &ciphertext_2, &plaintext_2));

	/* Clear the message buffer. */
	memset(rc->msg.ptr, 0, rc->msg.len);
	rc->msg.len = sizeof(rc->msg_buf);
	/*message 2 create*/
	TRY(msg2_encode(&c->g_y, &c->c_r, &ciphertext_2, &rc->msg));

	/* PSK mode: TH_3 = H(TH_2, PLAINTEXT_2A) - NO CRED_R */
	TRY(th3_calculate_psk(rc->suite.edhoc_hash, &th2, &plaintext_2, &rc->th3));

	// TIMING_END(msg2_gen, "msg2_gen TOTAL");
	return ok;
}

enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		      struct byte_array *initiator_pk)
{
	// TIMING_START(msg3_process);
	BYTE_ARRAY_NEW(ctxt3, CIPHERTEXT3_SIZE, rc->msg.len);
	TRY(decode_bstr(&rc->msg, &ctxt3));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("CIPHERTEXT_3", ctxt3.ptr, ctxt3.len);
#endif

	BYTE_ARRAY_NEW(id_cred_i, ID_CRED_I_SIZE, ID_CRED_I_SIZE);

#ifdef DEBUG_PRINT
	PRINTF("PLAINTEXT3_SIZE: %d\r\n", PLAINTEXT3_SIZE);
	PRINTF("ctxt3.len: %d\r\n", ctxt3.len);
#endif
#if defined(_WIN32)
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + 16, // 16 is max aead mac length
		       ctxt3.len);
#else
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ctxt3.len);
#endif

	// TIMING_START(decrypt3);
	
	/*check the authenticity of the initiator*/
	BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_i, G_I_SIZE, G_I_SIZE);
	
	/*derive prk_4e3m BEFORE decryption in PSK mode (needed for K_3/IV_3)*/
	// TIMING_START(prk4e3m);
	if (rc->is_psk) {
		/* PSK mode: PRK_4e3m = EDHOC_Extract(SALT_4e3m, PSK) */
#ifdef DEBUG_PRINT
		kprintf("[R] Deriving PRK_4e3m from PSK (len=%d)...\r\n", c->psk.len);
#endif
		TRY(prk_derive_psk(rc->suite, &rc->th3, &rc->prk_3e2m, &c->psk,
				   rc->prk_4e3m.ptr));
#ifdef DEBUG_PRINT
		kprintf("[R] PRK_4e3m derived from PSK\r\n");
#endif
	}
	// TIMING_END(prk4e3m, "PRK_4e3m derivation");
#ifdef DEBUG_PRINT
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);
#endif
	
	/* PSK mode: Use PSK-specific Message 3 decryption (no sig_or_mac) */
	TRY(ciphertext_decrypt_split_psk_msg3(&rc->suite, &id_cred_i, &rc->ead,
					      &rc->prk_3e2m, &rc->th3, &rc->prk_4e3m,
					      cred_i_array, &c->cred_r,
					      &ctxt3, &ptxt3));
	// TIMING_END(decrypt3, "Decrypt CIPHERTEXT_3");
	
	/* PSK mode: use id_cred_i as ID_CRED_PSK to retrieve credentials */
	TRY(retrieve_cred(cred_i_array, &id_cred_i, &cred_i,
			  &pk, &g_i));
	/* In PSK mode, pk contains the PSK itself */
#ifdef DEBUG_PRINT
	PRINT_ARRAY("CRED_I", cred_i.ptr, cred_i.len);
	PRINT_ARRAY("pk", pk.ptr, pk.len);
	PRINT_ARRAY("g_i", g_i.ptr, g_i.len);
#endif

	/* Export public key. */
	if ((NULL != initiator_pk) && (NULL != initiator_pk->ptr)) {
		_memcpy_s(initiator_pk->ptr, initiator_pk->len, pk.ptr, pk.len);
		initiator_pk->len = pk.len;
	}

	/* PSK mode: PRK_4e3m already derived from PSK before decryption */

	/* PSK mode: MAC_3 is skipped, authentication via PSK-based PRK_4e3m */

	/*TH4*/
	/* PSK mode: TH_4 = H(TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R)
	 * where ID_CRED_PSK = ID_CRED_I and PLAINTEXT_3B = (?EAD_3)
	 */
	TRY(th4_calculate_psk(rc->suite.edhoc_hash, &rc->th3, &id_cred_i,
			      &ptxt3, &cred_i, &c->cred_r, &rc->th4));

	/*PRK_out*/
	// TIMING_START(prk_out_derive);
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	// TIMING_END(prk_out_derive, "PRK_out derivation");
	// TIMING_END(msg3_process, "msg3_process TOTAL");
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

	/* PSK Message 4: PLAINTEXT_4 = ?EAD_4 only - no id_cred, no sig_or_mac */
	TRY(ciphertext_gen_psk(CIPHERTEXT4, &rc->suite, &NULL_ARRAY,
			       &c->ead_4, &rc->prk_4e3m, &rc->th4,
			       &ctxt4, &ptxt4));

	TRY(encode_bstr(&ctxt4, &rc->msg));

#ifdef DEBUG_PRINT
	PRINT_ARRAY("Message 4 ", rc->msg.ptr, rc->msg.len);
#endif
	return ok;
}
#endif // MESSAGE_4

enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	struct byte_array *initiator_pub_key, struct byte_array *c_i_bytes,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	uint64_t t_start, t_end;
	uint64_t t_msg2_gen = 0, t_msg3_process = 0;
	enum err r;
	
#ifdef DEBUG_PRINT
	kprintf("[R] edhoc_responder_run_extended START\r\n");
#endif
	
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	/*receive message 1*/
#ifdef DEBUG_PRINT
	kprintf("[R] RX msg1...\r\n");
#endif
	r = rx(c->sock, &rc.msg);
	if (r != ok) { kprintf("[R] RX msg1 FAILED: %d\r\n", r); return r; }
#ifdef DEBUG_PRINT
	kprintf("[R] RX msg1 OK, len=%d\r\n", rc.msg.len);
#endif

	/*process msg1 and generate message 2*/
#ifdef DEBUG_PRINT
	kprintf("[R] Processing msg1 & generating msg2...\r\n");
#endif
	__asm__ volatile ("rdcycle %0" : "=r"(t_start));
	r = msg2_gen(c, &rc, c_i_bytes);
	if (r != ok) { kprintf("[R] msg2_gen FAILED: %d\r\n", r); return r; }
	r = ead_process(c->params_ead_process, &rc.ead);
	__asm__ volatile ("rdcycle %0" : "=r"(t_end));
	t_msg2_gen = t_end - t_start;
	if (r != ok) { kprintf("[R] ead_process FAILED: %d\r\n", r); return r; }
#ifdef DEBUG_PRINT
	kprintf("[R] msg2_gen OK, len=%d\r\n", rc.msg.len);
#endif
	
#ifdef DEBUG_PRINT
	kprintf("[R] TX msg2...\r\n");
#endif
	r = tx(c->sock, &rc.msg);
	if (r != ok) { kprintf("[R] TX msg2 FAILED: %d\r\n", r); return r; }
#ifdef DEBUG_PRINT
	kprintf("[R] TX msg2 OK\r\n");
#endif

	/*receive message 3*/
#ifdef DEBUG_PRINT
	kprintf("[R] RX msg3...\r\n");
#endif
	rc.msg.len = sizeof(rc.msg_buf);
	r = rx(c->sock, &rc.msg);
	if (r != ok) { kprintf("[R] RX msg3 FAILED: %d\r\n", r); return r; }
#ifdef DEBUG_PRINT
	kprintf("[R] RX msg3 OK, len=%d\r\n", rc.msg.len);
#endif
	
	/*process msg3*/
#ifdef DEBUG_PRINT
	kprintf("[R] Processing msg3...\r\n");
#endif
	__asm__ volatile ("rdcycle %0" : "=r"(t_start));
	r = msg3_process(c, &rc, cred_i_array, prk_out, initiator_pub_key);
	if (r != ok) { kprintf("[R] msg3_process FAILED: %d\r\n", r); return r; }
	r = ead_process(c->params_ead_process, &rc.ead);
	__asm__ volatile ("rdcycle %0" : "=r"(t_end));
	t_msg3_process = t_end - t_start;
	if (r != ok) { kprintf("[R] ead_process FAILED: %d\r\n", r); return r; }
#ifdef DEBUG_PRINT
	kprintf("[R] msg3_process OK\r\n");
#endif

	/*create and send message 4*/
#ifdef MESSAGE_4
	uint64_t t_msg4_gen = 0;
	__asm__ volatile ("rdcycle %0" : "=r"(t_start));
	TRY(msg4_gen(c, &rc));
	__asm__ volatile ("rdcycle %0" : "=r"(t_end));
	t_msg4_gen = t_end - t_start;
	TRY(tx(c->sock, &rc.msg));
#ifdef DEBUG_PRINT
	kprintf("[TIMING] Responder msg4_gen: %lu cycles\r\n", (unsigned long)t_msg4_gen);
#endif
#endif // MESSAGE_4

	/* Print detailed timing */
// #ifdef DEBUG_PRINT
	kprintf("[TIMING] Responder msg2_gen (includes msg1_process): %lu cycles\r\n", (unsigned long)t_msg2_gen);
	kprintf("[TIMING] Responder msg3_process: %lu cycles\r\n", (unsigned long)t_msg3_process);
	kprintf("[TIMING] Responder COMPUTE TOTAL: %lu cycles\r\n", (unsigned long)(t_msg2_gen + t_msg3_process));
// #endif
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
