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
#include "edhoc_internal.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "edhoc/buffer_sizes.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "cbor/edhoc_encode_message_1.h"
#include "cbor/edhoc_decode_message_2.h"
#include "cbor/edhoc_encode_message_3.h"

/** 
 * @brief   			Parses message 2.
 * @param c 			Initiator context.
 * @param[in] msg2 		Message 2. 
 * @param[out] g_y		G_Y ephemeral public key of the responder.
 * @param[out] ciphertext2	Ciphertext 2.
 * @retval			Ok or error code.
 */
static inline enum err msg2_parse(struct byte_array *msg2,
				  struct byte_array *g_y,
				  struct byte_array *ciphertext2)
{
	BYTE_ARRAY_NEW(g_y_ciphertext_2, G_Y_CIPHERTEXT_2, G_Y_CIPHERTEXT_2);
	TRY(decode_bstr(msg2, &g_y_ciphertext_2));

	TRY(_memcpy_s(g_y->ptr, g_y->len, g_y_ciphertext_2.ptr, g_y->len));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("g_y", g_y->ptr, g_y->len);
#endif

	TRY(_memcpy_s(ciphertext2->ptr, ciphertext2->len,
		      g_y_ciphertext_2.ptr + g_y->len,
		      g_y_ciphertext_2.len - g_y->len));

	ciphertext2->len = g_y_ciphertext_2.len - g_y->len;
#ifdef DEBUG_PRINT
	PRINT_ARRAY("ciphertext2", ciphertext2->ptr, ciphertext2->len);
#endif

	return ok;
}

enum err msg1_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc)
{
	struct message_1 m1;

	/*METHOD_CORR*/
	m1.message_1_METHOD = (int32_t)c->method;

	/*SUITES_I*/
	if (c->suites_i.len == 1) {
		/* only one suite, encode into int */
		m1.message_1_SUITES_I_choice = message_1_SUITES_I_int_c;
		m1.message_1_SUITES_I_int = c->suites_i.ptr[0];
	} else if (c->suites_i.len > 1) {
		/* more than one suites, encode into array */
		m1.message_1_SUITES_I_choice = SUITES_I_suite_l_c;
		m1.SUITES_I_suite_l_suite_count = c->suites_i.len;
		for (uint32_t i = 0; i < c->suites_i.len; i++) {
			m1.SUITES_I_suite_l_suite[i] = c->suites_i.ptr[i];
		}
	}

	/* G_X ephemeral public key */
	m1.message_1_G_X.value = c->g_x.ptr;
	m1.message_1_G_X.len = c->g_x.len;

	/* C_I connection ID  of the initiator*/
#ifdef DEBUG_PRINT
	PRINT_ARRAY("C_I", c->c_i.ptr, c->c_i.len);
#endif
	if (c_x_is_encoded_int(&c->c_i)) {
		m1.message_1_C_I_choice = message_1_C_I_int_c;
		TRY(decode_int(&c->c_i, &m1.message_1_C_I_int));
	} else {
		m1.message_1_C_I_choice = message_1_C_I_bstr_c;
		m1.message_1_C_I_bstr.value = c->c_i.ptr;
		m1.message_1_C_I_bstr.len = c->c_i.len;
	}

	if (c->ead_1.len != 0) {
		/* ead_1 unprotected opaque auxiliary data */
		m1.message_1_ead_1.value = c->ead_1.ptr;
		m1.message_1_ead_1.len = c->ead_1.len;
		m1.message_1_ead_1_present = true;
	} else {
		m1.message_1_ead_1_present = false;
	}

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_message_1(rc->msg.ptr, rc->msg.len, &m1,
					 &payload_len_out), 0);
	rc->msg.len = (uint32_t)payload_len_out;

#ifdef DEBUG_PRINT
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);
#endif

	TRY(get_suite((enum suite_label)c->suites_i.ptr[c->suites_i.len - 1],
		      &rc->suite));
	/* Calculate hash of msg1 for TH2. */
	uint64_t t_hash_start, t_hash_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_hash_start));
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	__asm__ volatile ("rdcycle %0" : "=r"(t_hash_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] hash(msg1): %lu cycles\r\n", (unsigned long)(t_hash_end - t_hash_start));
#endif
	return ok;
}

static enum err msg2_process(const struct edhoc_initiator_context *c,
			     struct runtime_context *rc,
			     struct cred_array *cred_r_array,
			     struct byte_array *c_r, bool static_dh_i,
			     bool static_dh_r, struct byte_array *th3,
			     struct byte_array *PRK_3e2m)
{
	BYTE_ARRAY_NEW(g_y, G_Y_SIZE, get_ecdh_pk_len(rc->suite.edhoc_ecdh));
	uint32_t ciphertext_len = rc->msg.len - g_y.len;
	ciphertext_len -= BSTR_ENCODING_OVERHEAD(ciphertext_len);
	BYTE_ARRAY_NEW(ciphertext, CIPHERTEXT2_SIZE, ciphertext_len);
	BYTE_ARRAY_NEW(plaintext, PLAINTEXT2_SIZE, ciphertext.len);
#ifdef DEBUG_PRINT
	PRINT_ARRAY("message_2 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);
#endif

	/*parse the message*/
	TRY(msg2_parse(&rc->msg, &g_y, &ciphertext));

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);

	uint64_t t_ecdh_start, t_ecdh_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_ecdh_start));
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->x, &g_y, g_xy.ptr));
	__asm__ volatile ("rdcycle %0" : "=r"(t_ecdh_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] shared_secret_derive(X25519): %lu cycles\r\n", (unsigned long)(t_ecdh_end - t_ecdh_start));
#endif
#ifdef DEBUG_PRINT
	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);
#endif

	/*calculate th2*/
	BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));

	uint64_t t_th2_start, t_th2_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_th2_start));
	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &g_y, &th2));
	__asm__ volatile ("rdcycle %0" : "=r"(t_th2_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] th2_calculate: %lu cycles\r\n", (unsigned long)(t_th2_end - t_th2_start));
#endif

	/*calculate PRK_2e*/
	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	uint64_t t_hkdf_start, t_hkdf_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_hkdf_start));
	TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	__asm__ volatile ("rdcycle %0" : "=r"(t_hkdf_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] hkdf_extract(PRK_2e): %lu cycles\r\n", (unsigned long)(t_hkdf_end - t_hkdf_start));
#endif
#ifdef DEBUG_PRINT
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);
#endif

	plaintext.len = ciphertext.len;
	TRY(check_buffer_size(PLAINTEXT2_SIZE, plaintext.len));

	/* PSK Mode: Decrypt CIPHERTEXT_2 (no ID_CRED_R, no MAC_2) */
	uint64_t t_decrypt_start, t_decrypt_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_decrypt_start));
	TRY(ciphertext_decrypt_split_psk(CIPHERTEXT2, &rc->suite, c_r, &rc->ead,
					  &PRK_2e, &th2, &ciphertext, &plaintext));
	__asm__ volatile ("rdcycle %0" : "=r"(t_decrypt_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] ciphertext_decrypt_split_psk(msg2): %lu cycles\r\n", (unsigned long)(t_decrypt_end - t_decrypt_start));
#endif

	/* PSK mode: PRK_3e2m = PRK_2e (no static DH, per draft section 5.1) */
	memcpy(PRK_3e2m->ptr, PRK_2e.ptr, PRK_2e.len);
	PRK_3e2m->len = PRK_2e.len;
#ifdef DEBUG_PRINT
	PRINT_ARRAY("prk_3e2m (= PRK_2e)", PRK_3e2m->ptr, PRK_3e2m->len);
#endif

	/* PSK mode: TH_3 = H(TH_2, PLAINTEXT_2A) - NO CRED_R */
	uint64_t t_th3_start, t_th3_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_th3_start));
	TRY(th3_calculate_psk(rc->suite.edhoc_hash, &th2, &plaintext, th3));
	__asm__ volatile ("rdcycle %0" : "=r"(t_th3_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] th3_calculate_psk: %lu cycles\r\n", (unsigned long)(t_th3_end - t_th3_start));
#endif

	/* PSK mode: Derive PRK_4e3m from PSK */
	uint64_t t_prk4_start, t_prk4_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_prk4_start));
	TRY(prk_derive_psk(rc->suite, th3, PRK_3e2m, &c->psk, rc->prk_4e3m.ptr));
	__asm__ volatile ("rdcycle %0" : "=r"(t_prk4_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] prk_derive_psk(PRK_4e3m): %lu cycles\r\n", (unsigned long)(t_prk4_end - t_prk4_start));
#endif
#ifdef DEBUG_PRINT
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);
#endif

	return ok;
}

static enum err msg3_only_gen(const struct edhoc_initiator_context *c,
			      struct runtime_context *rc, bool static_dh_i,
			      struct cred_array *cred_r_array,
			      struct byte_array *th3,
			      struct byte_array *PRK_3e2m,
			      struct byte_array *prk_out)
{
	BYTE_ARRAY_NEW(plaintext, PLAINTEXT3_SIZE, c->ead_3.len);
	BYTE_ARRAY_NEW(ciphertext, CIPHERTEXT3_SIZE,
		       AS_BSTR_SIZE(plaintext.len) +
			       get_aead_mac_len(rc->suite.edhoc_aead));
	
	/* PSK mode: Get responder credential from cred_r_array (assume first entry) */
	if (cred_r_array->len == 0) {
		return credential_not_found;
	}
	struct byte_array cred_r = cred_r_array->ptr[0].cred;
	
	/* PSK mode: Generate CIPHERTEXT_3 with PSK-specific function */
	uint64_t t_encrypt_start, t_encrypt_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_encrypt_start));
	TRY(ciphertext_gen_psk_msg3(&rc->suite, &c->id_cred_psk, &c->ead_3,
				    PRK_3e2m, th3, &rc->prk_4e3m, &c->cred_i,
				    &cred_r, &ciphertext, &plaintext));
	__asm__ volatile ("rdcycle %0" : "=r"(t_encrypt_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] ciphertext_gen_psk_msg3: %lu cycles\r\n", (unsigned long)(t_encrypt_end - t_encrypt_start));
#endif

	/*massage 3 create and send*/
	TRY(encode_bstr(&ciphertext, &rc->msg));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("msg3", rc->msg.ptr, rc->msg.len);
#endif

	/* PSK mode: TH_4 = H(TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R)
	 * where ID_CRED_PSK = ID_CRED_I and PLAINTEXT_3B = (?EAD_3)
	 */
	uint64_t t_th4_start, t_th4_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_th4_start));
	TRY(th4_calculate_psk(rc->suite.edhoc_hash, th3, &c->id_cred_psk,
			      &c->ead_3, &c->cred_i, &cred_r, &rc->th4));
	__asm__ volatile ("rdcycle %0" : "=r"(t_th4_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] th4_calculate_psk: %lu cycles\r\n", (unsigned long)(t_th4_end - t_th4_start));
#endif

	/*PRK_out*/
	uint64_t t_kdf_start, t_kdf_end;
	__asm__ volatile ("rdcycle %0" : "=r"(t_kdf_start));
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	__asm__ volatile ("rdcycle %0" : "=r"(t_kdf_end));
#ifdef TIMING_PRINT
	kprintf("[TIMING-I] edhoc_kdf(PRK_out): %lu cycles\r\n", (unsigned long)(t_kdf_end - t_kdf_start));
#endif
	return ok;
}

enum err msg3_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc, struct cred_array *cred_r_array,
		  struct byte_array *c_r, struct byte_array *prk_out)
{
	bool static_dh_i = false, static_dh_r = false;
	authentication_type_get(c->method, &static_dh_i, &static_dh_r);
	BYTE_ARRAY_NEW(th3, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW(PRK_3e2m, PRK_SIZE, PRK_SIZE);

	/*process message 2*/
	TRY(msg2_process(c, rc, cred_r_array, c_r, static_dh_i, static_dh_r,
			 &th3, &PRK_3e2m));

	/*generate message 3*/
	msg3_only_gen(c, rc, static_dh_i, cred_r_array, &th3, &PRK_3e2m, prk_out);
	return ok;
}

#ifdef MESSAGE_4
enum err msg4_process(struct runtime_context *rc)
{
#ifdef DEBUG_PRINT
	PRINT_ARRAY("message4 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);
#endif

	BYTE_ARRAY_NEW(ciphertext4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
	TRY(decode_bstr(&rc->msg, &ciphertext4));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("ciphertext_4", ciphertext4.ptr, ciphertext4.len);
#endif

	BYTE_ARRAY_NEW(plaintext4,
		       PLAINTEXT4_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ciphertext4.len);
	TRY(ciphertext_decrypt_split_psk(CIPHERTEXT4, &rc->suite, NULL, &rc->ead,
					  &rc->prk_4e3m, &rc->th4, &ciphertext4,
					  &plaintext4));
	return ok;
}
#endif // MESSAGE_4

enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *c_r_bytes, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	uint64_t t_start, t_end;
	uint64_t t_msg1_gen = 0, t_msg3_gen = 0;

	/*create and send message 1*/
	__asm__ volatile ("rdcycle %0" : "=r"(t_start));
	TRY(msg1_gen(c, &rc));
	__asm__ volatile ("rdcycle %0" : "=r"(t_end));
	t_msg1_gen = t_end - t_start;
	TRY(tx(c->sock, &rc.msg));

	/*receive message 2*/
#ifdef DEBUG_PRINT
	PRINT_MSG("waiting to receive message 2...\n");
#endif
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));

	/*create and send message 3*/
	__asm__ volatile ("rdcycle %0" : "=r"(t_start));
	TRY(msg3_gen(c, &rc, cred_r_array, c_r_bytes, prk_out));
	__asm__ volatile ("rdcycle %0" : "=r"(t_end));
	t_msg3_gen = t_end - t_start;
	TRY(ead_process(c->params_ead_process, &rc.ead));
	TRY(tx(c->sock, &rc.msg));

	/*receive message 4*/
#ifdef MESSAGE_4
#ifdef DEBUG_PRINT
	PRINT_MSG("waiting to receive message 4...\n");
#endif
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));
	TRY(msg4_process(&rc));
	TRY(ead_process(c->params_ead_process, &rc.ead));
#endif // MESSAGE_4

	/* Print detailed timing */
// #ifdef DEBUG_PRINT
	kprintf("[TIMING] Responder msg2_gen (includes msg1_process): %lu cycles\r\n", (unsigned long)t_msg1_gen);
	kprintf("[TIMING] Responder msg3_process: %lu cycles\r\n", (unsigned long)t_msg3_gen);
	kprintf("[TIMING] Responder COMPUTE TOTAL: %lu cycles\r\n", (unsigned long)(t_msg1_gen + t_msg3_gen));
// #endif

	return ok;
}

enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	BYTE_ARRAY_NEW(c_r, C_R_SIZE, C_R_SIZE);

	return edhoc_initiator_run_extended(c, cred_r_array, err_msg, &c_r,
					    prk_out, tx, rx, ead_process);
}
