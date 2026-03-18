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

#include "edhoc/okm.h"
#include "edhoc/ciphertext.h"
#include "edhoc/plaintext.h"
#include "edhoc/suites.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"
#include "edhoc/retrieve_cred.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

#ifdef DEBUG_PRINT
/* Helper to print hex bytes (kprintf doesn't support %02x) */
static void print_hex(const char *label, const uint8_t *data, uint32_t len)
{
	kprintf("%s", label);
	for (uint32_t i = 0; i < len; i++) {
		if (i > 0 && (i % 16) == 0) {
			kprintf("\r\n                          "); // Indent continuation lines
		}
		uint8_t b = data[i];
		uint8_t hi = (b >> 4) & 0xF;
		uint8_t lo = b & 0xF;
		char hex[3];
		hex[0] = (hi < 10) ? ('0' + hi) : ('a' + hi - 10);
		hex[1] = (lo < 10) ? ('0' + lo) : ('a' + lo - 10);
		hex[2] = ' ';
		kprintf("%c%c ", hex[0], hex[1]);
	}
	kprintf("\r\n");
}
#endif

/**
 * @brief 			Xors two arrays.
 * 
 * @param[in] in1		An input array.
 * @param[in] in2 		An input array.
 * @param[out] out 		The result of the xor operation.
 * @retval			Ok or error code.
 */
static inline enum err xor_arrays(const struct byte_array *in1,
				  const struct byte_array *in2,
				  struct byte_array *out)
{
	if (in1->len != in2->len) {
		return xor_error;
	}
	for (uint32_t i = 0; i < in1->len; i++) {
		out->ptr[i] = in1->ptr[i] ^ in2->ptr[i];
	}
	return ok;
}

/**
 * @brief 			Encrypts a plaintext or decrypts a ciphertext.
 * 
 * @param use_xor 		True for XOR (Message 2), false for AEAD (Message 3/4).
 * @param op 			ENCRYPT or DECRYPT.
 * @param[in] in 		Ciphertext or plaintext. 
 * @param[in] key 		The key used of encryption/decryption.
 * @param[in] nonce 		AEAD nonce.
 * @param[in] aad 		Additional authenticated data for AEAD.
 * @param[out] out 		The result.
 * @param[out] tag 		AEAD authentication tag.
 * @return 			Ok or error code. 
 */
static enum err ciphertext_encrypt_decrypt(
	bool use_xor, enum aes_operation op,
	const struct byte_array *in, const struct byte_array *key,
	struct byte_array *nonce, const struct byte_array *aad,
	struct byte_array *out, struct byte_array *tag)
{
	if (use_xor) {
		/* PSK Message 2: XOR encryption */
		xor_arrays(in, key, out);
	} else {
		/* PSK Message 3/4: AEAD encryption */
		// PRINT_ARRAY("in", in->ptr, in->len);
		TRY(aead(op, in, key, nonce, aad, out, tag));
	}
	return ok;
}

/**
 * @brief 			Computes the key stream for message 2 and 
 * 				the key and IV for message 3 and 4 (PSK mode). 
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4.
 * @param edhoc_hash 		The EDHOC hash algorithm.
 * @param prk 			Pseudorandom key (PRK_2e for msg2, PRK_4e3m for msg3/4).
 * @param th 			Transcript hash.
 * @param[out] key 		The generated key/key stream.
 * @param[out] iv 		The generated iv (only for msg3/4).
 * @return 			Ok or error code. 
 */
static enum err key_gen_psk(enum ciphertext ctxt, enum hash_alg edhoc_hash,
			struct byte_array *prk, struct byte_array *th,
			struct byte_array *key, struct byte_array *iv)
{
	switch (ctxt) {
	case CIPHERTEXT2:
		/* PSK Message 2: KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 1, TH_2, len) */
		TRY(edhoc_kdf(edhoc_hash, prk, KEYSTREAM_2, th, key));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("KEYSTREAM_2", key->ptr, key->len);
#endif
		break;

	case CIPHERTEXT3:
		/* PSK Message 3: K_3 = EDHOC_KDF(PRK_4e3m, 3, TH_3, key_len) */
		TRY(edhoc_kdf(edhoc_hash, prk, K_3, th, key));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("K_3", key->ptr, key->len);
#endif
		/* IV_3 = EDHOC_KDF(PRK_4e3m, 4, TH_3, iv_len) */
		TRY(edhoc_kdf(edhoc_hash, prk, IV_3, th, iv));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("IV_3", iv->ptr, iv->len);
#endif
		break;

	case CIPHERTEXT4:
		/* Message 4: K_4 = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_len) */
#ifdef DEBUG_PRINT
		PRINT_ARRAY("PRK_4e3m", prk->ptr, prk->len);
		PRINT_ARRAY("TH_4", th->ptr, th->len);
#endif
		TRY(edhoc_kdf(edhoc_hash, prk, K_4, th, key));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("K_4", key->ptr, key->len);
#endif
		/* IV_4 = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_len) */
		TRY(edhoc_kdf(edhoc_hash, prk, IV_4, th, iv));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("IV_4", iv->ptr, iv->len);
#endif
		break;
	}
	return ok;
}

/* ======================== PSK-ONLY FUNCTIONS ========================
 * These functions are specifically for PSK mode (Method 4) and do NOT
 * use id_cred or sig_or_mac parameters, eliminating Method 0-3 baggage.
 * ==================================================================== */

enum err ciphertext_gen_psk(
	enum ciphertext ctxt, struct suite *suite,
	const struct byte_array *c_r,
	const struct byte_array *ead,
	struct byte_array *prk,
	struct byte_array *th,
	struct byte_array *ciphertext,
	struct byte_array *plaintext)
{
	/* PSK Message 2/4: No id_cred, no sig_or_mac */
	if (ctxt != CIPHERTEXT2 && ctxt != CIPHERTEXT4) {
		return wrong_parameter; /* Only for Message 2 or 4 */
	}

	/* Build plaintext based on message type */
	uint32_t ptxt_buf_capacity = plaintext->len;
	plaintext->len = 0;
	
	if (ctxt == CIPHERTEXT2) {
		/* PSK Message 2: PLAINTEXT_2 = (C_R, ?EAD_2) - no ID_CRED, no MAC */
		if (c_x_is_encoded_int(c_r)) {
			TRY(byte_array_append(plaintext, c_r, ptxt_buf_capacity));
		} else {
			BYTE_ARRAY_NEW(c_r_enc, AS_BSTR_SIZE(C_I_SIZE),
				       AS_BSTR_SIZE(c_r->len));
			TRY(encode_bstr(c_r, &c_r_enc));
			TRY(byte_array_append(plaintext, &c_r_enc, ptxt_buf_capacity));
		}
	} else {
		/* CIPHERTEXT4: PLAINTEXT_4 = ?EAD_4 only */
		plaintext->len = 0;
	}
	
	if (ead->len > 0) {
		TRY(byte_array_append(plaintext, ead, ptxt_buf_capacity));
	}

#ifdef DEBUG_PRINT
	PRINT_ARRAY("plaintext", plaintext->ptr, plaintext->len);
#endif

	/* Generate key and iv (no iv for ciphertext 2) */
	uint32_t key_len;
	if (ctxt == CIPHERTEXT2) {
		key_len = plaintext->len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}

	BYTE_ARRAY_NEW(key, CIPHERTEXT2_SIZE, key_len);
	BYTE_ARRAY_NEW(iv, AEAD_IV_SIZE, get_aead_iv_len(suite->edhoc_aead));

	TRY(key_gen_psk(ctxt, suite->edhoc_hash, prk, th, &key, &iv));

	/* Encrypt */
	BYTE_ARRAY_NEW(aad, AAD_SIZE, AAD_SIZE);
	BYTE_ARRAY_NEW(tag, MAC_SIZE, get_aead_mac_len(suite->edhoc_aead));

	if (ctxt != CIPHERTEXT2) {
		/* PSK Message 4: AAD = TH_4 */
		aad.len = th->len;
		TRY(_memcpy_s(aad.ptr, aad.len, th->ptr, th->len));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("aad_data", aad.ptr, aad.len);
#endif
	} else {
		/* PSK Message 2: XOR mode, no tag */
		tag.len = 0;
	}

	ciphertext->len = plaintext->len;

	TRY(ciphertext_encrypt_decrypt(ctxt == CIPHERTEXT2, ENCRYPT, plaintext, &key, &iv,
				       &aad, ciphertext, &tag));
	ciphertext->len += tag.len;

#ifdef DEBUG_PRINT
	PRINT_ARRAY("ciphertext_2/4_psk", ciphertext->ptr, ciphertext->len);
#endif
	return ok;
}

enum err ciphertext_decrypt_split_psk(
	enum ciphertext ctxt, struct suite *suite,
	struct byte_array *c_r,
	struct byte_array *ead,
	struct byte_array *prk,
	struct byte_array *th,
	struct byte_array *ciphertext,
	struct byte_array *plaintext)
{
	/* PSK Message 2/4: No id_cred, no sig_or_mac */
	if (ctxt != CIPHERTEXT2 && ctxt != CIPHERTEXT4) {
		return wrong_parameter; /* Only for Message 2 or 4 */
	}

	/* Generate key and iv (no iv for ciphertext 2) */
	uint32_t key_len;
	if (ctxt == CIPHERTEXT2) {
		key_len = ciphertext->len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}

	BYTE_ARRAY_NEW(key, CIPHERTEXT2_SIZE, key_len);
	BYTE_ARRAY_NEW(iv, AEAD_IV_SIZE, get_aead_iv_len(suite->edhoc_aead));

	TRY(key_gen_psk(ctxt, suite->edhoc_hash, prk, th, &key, &iv));

	/* PSK mode: no associated data for CIPHERTEXT2 (uses XOR), 
	 * CIPHERTEXT4 uses TH_4 as AAD */
	BYTE_ARRAY_NEW(associated_data, AAD_SIZE, AAD_SIZE);
	if (ctxt == CIPHERTEXT2) {
		/* Message 2: XOR mode, no AAD */
		associated_data.len = 0;
	} else {
		/* Message 4: AEAD mode, TH_4 is AAD */
		associated_data.len = th->len;
		TRY(_memcpy_s(associated_data.ptr, associated_data.len,
		              th->ptr, th->len));
	}
	
#ifdef DEBUG_PRINT
	PRINT_ARRAY("associated_data", associated_data.ptr, associated_data.len);
#endif

	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
	if (ctxt != CIPHERTEXT2) {
		if (plaintext->len < tag_len) {
			return error_message_received;
		}
		plaintext->len -= tag_len;
	}
	struct byte_array tag = BYTE_ARRAY_INIT(ciphertext->ptr, tag_len);
	TRY(ciphertext_encrypt_decrypt(ctxt == CIPHERTEXT2, DECRYPT, ciphertext, &key, &iv,
				       &associated_data, plaintext, &tag));

#ifdef DEBUG_PRINT
	PRINT_ARRAY("plaintext", plaintext->ptr, plaintext->len);
#endif

	if (ctxt == CIPHERTEXT4) {
		/* Message 4: plaintext contains only ?EAD_4 */
		if (plaintext->len != 0) {
			TRY(decode_bstr(plaintext, ead));
#ifdef DEBUG_PRINT
			PRINT_ARRAY("EAD_4", ead->ptr, ead->len);
#endif
		} else {
			ead->ptr = NULL;
			ead->len = 0;
#ifdef DEBUG_PRINT
			PRINT_MSG("No EAD_4\r\n");
#endif
		}
	} else {
		/* Message 2: PSK mode PLAINTEXT_2 = (C_R, ?EAD_2) - no ID_CRED, no MAC */
#ifdef DEBUG_PRINT
		kprintf("[CIPHER] PSK mode: calling plaintext_split_psk_msg2\r\n");
		kprintf("[CIPHER] plaintext->len=%d\r\n", plaintext->len);
#endif
		TRY(plaintext_split_psk_msg2(plaintext, c_r, ead));
#ifdef DEBUG_PRINT
		PRINT_ARRAY("C_R (raw)", c_r->ptr, c_r->len);
		
		if (ead->len) {
			PRINT_ARRAY("ead", ead->ptr, ead->len);
		}
#endif
	}
#ifdef DEBUG_PRINT
	kprintf("==========================================\r\n\r\n");
#endif
	return ok;
}

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
	struct byte_array *plaintext)
{
	/* PSK Message 3: Two-layer encryption per draft-ietf-lake-edhoc-psk-06 Section 5.3
	 * PLAINTEXT_3B = (?EAD_3)
	 * CIPHERTEXT_3B = AEAD(PLAINTEXT_3B, K_3, IV_3, external_aad)
	 *   where external_aad = << ID_CRED_PSK, TH_3, CRED_I, CRED_R >>
	 * PLAINTEXT_3A = (ID_CRED_PSK, CIPHERTEXT_3B)
	 * CIPHERTEXT_3A = PLAINTEXT_3A XOR KEYSTREAM_3A
	 */
	
	/* Step 1: Create PLAINTEXT_3B = (?EAD_3) */
	BYTE_ARRAY_NEW(plaintext_3b, PLAINTEXT3_SIZE, ead->len);
	if (ead->len > 0) {
		TRY(byte_array_append(&plaintext_3b, ead, plaintext_3b.len));
	}
#ifdef DEBUG_PRINT
	PRINT_ARRAY("PLAINTEXT_3B", plaintext_3b.ptr, plaintext_3b.len);
#endif
	
	/* Step 2: Generate K_3 and IV_3 from PRK_4e3m */
	uint32_t key_len = get_aead_key_len(suite->edhoc_aead);
	uint32_t iv_len = get_aead_iv_len(suite->edhoc_aead);
	BYTE_ARRAY_NEW(k_3, PK_SIZE, key_len);
	BYTE_ARRAY_NEW(iv_3, AEAD_IV_SIZE, iv_len);
	
#ifdef DEBUG_PRINT
	kprintf("\r\n========== INITIATOR: ENCRYPT_3B ==========\r\n");
	print_hex("[I-ENC] PRK_4e3m: ", prk_4e3m->ptr, prk_4e3m->len);
	print_hex("[I-ENC] TH_3: ", th3->ptr, th3->len);
	kprintf("[I-ENC] key_len=%d, iv_len=%d\r\n", key_len, iv_len);
#endif
	
	TRY(edhoc_kdf(suite->edhoc_hash, prk_4e3m, K_3, th3, &k_3));
#ifdef DEBUG_PRINT
	print_hex("[I-ENC] K_3: ", k_3.ptr, k_3.len);
#endif
	
	TRY(edhoc_kdf(suite->edhoc_hash, prk_4e3m, IV_3, th3, &iv_3));
#ifdef DEBUG_PRINT
	print_hex("[I-ENC] IV_3: ", iv_3.ptr, iv_3.len);
#endif
	
	/* Step 3: Build external_aad = << ID_CRED_PSK, TH_3, CRED_I, CRED_R >>
	 * Note: << >> means CBOR sequence - raw CBOR data items concatenated, NOT encoded as bstr
	 */
	BYTE_ARRAY_NEW(external_aad, AAD_SIZE * 4, AAD_SIZE * 4);
	uint32_t external_aad_capacity = external_aad.len;
	external_aad.len = 0;
	
	/* Append ID_CRED_PSK as raw CBOR data item (compactly encoded if {4: kid}) */
	TRY(byte_array_append(&external_aad, id_cred_psk, external_aad_capacity));
	
	/* Append TH_3 as raw bytes (32-byte hash value, per draft test vector "TH_3 (Raw Value)") */
	TRY(byte_array_append(&external_aad, th3, external_aad_capacity));
	
	/* Append CRED_I as raw CBOR data item (already a CBOR map) */
	TRY(byte_array_append(&external_aad, cred_i, external_aad_capacity));
	
	/* Append CRED_R as raw CBOR data item (already a CBOR map) */
	TRY(byte_array_append(&external_aad, cred_r, external_aad_capacity));
	
#ifdef DEBUG_PRINT
	kprintf("[I-ENC] external_aad.len=%d\r\n", external_aad.len);
	print_hex("[I-ENC] external_aad (FULL): ", external_aad.ptr, external_aad.len);
	print_hex("[I-ENC] CRED_I: ", cred_i->ptr, cred_i->len);
	print_hex("[I-ENC] CRED_R: ", cred_r->ptr, cred_r->len);
#endif
	
	/* Step 4: CIPHERTEXT_3B = AEAD(PLAINTEXT_3B, K_3, IV_3, external_aad) */
	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
	BYTE_ARRAY_NEW(ciphertext_3b, CIPHERTEXT3_SIZE, 
	               plaintext_3b.len + tag_len);
	BYTE_ARRAY_NEW(tag_3b, MAC_SIZE, tag_len);
	
	if (plaintext_3b.len > 0) {
		TRY(aead(ENCRYPT, &plaintext_3b, &k_3, &iv_3, &external_aad, 
		         &ciphertext_3b, &tag_3b));
		ciphertext_3b.len += tag_3b.len;
	} else {
		/* Empty plaintext: only generate authentication tag */
		ciphertext_3b.len = 0;
		TRY(aead(ENCRYPT, &plaintext_3b, &k_3, &iv_3, &external_aad, 
			         &ciphertext_3b, &tag_3b));
		ciphertext_3b.len = tag_len;
	}
#ifdef DEBUG_PRINT
	print_hex("[I-ENC] CIPHERTEXT_3B (final): ", ciphertext_3b.ptr, ciphertext_3b.len);
	kprintf("==========================================\r\n\r\n");
#endif	/* Step 5: Create PLAINTEXT_3A = (ID_CRED_PSK, CIPHERTEXT_3B) with compact encoding */
	uint8_t id_cred_compact[2];
	if (id_cred_psk->len == 4 && id_cred_psk->ptr[0] == 0xa1 && id_cred_psk->ptr[1] == 0x04) {
		uint8_t kid_byte = id_cred_psk->ptr[3];
		id_cred_compact[0] = 0x41;
		id_cred_compact[1] = kid_byte;
	} else {
		return wrong_parameter;
	}
	struct byte_array id_cred_encoded = BYTE_ARRAY_INIT(id_cred_compact, 2);
	
	BYTE_ARRAY_NEW(plaintext_3a, PLAINTEXT3_SIZE, 
	               id_cred_encoded.len + ciphertext_3b.len);
	plaintext_3a.len = 0;
	
	TRY(byte_array_append(&plaintext_3a, &id_cred_encoded, 
	                      plaintext_3a.len + id_cred_encoded.len));
	
	BYTE_ARRAY_NEW(ciphertext_3b_enc, AS_BSTR_SIZE(CIPHERTEXT3_SIZE), 
	               AS_BSTR_SIZE(ciphertext_3b.len));
	TRY(encode_bstr(&ciphertext_3b, &ciphertext_3b_enc));
	TRY(byte_array_append(&plaintext_3a, &ciphertext_3b_enc, 
	                      plaintext_3a.len + ciphertext_3b_enc.len));
	
	/* Step 6: Generate KEYSTREAM_3A from PRK_3e2m */
	BYTE_ARRAY_NEW(keystream_3a, CIPHERTEXT3_SIZE, plaintext_3a.len);
	TRY(edhoc_kdf(suite->edhoc_hash, prk_3e2m, KEYSTREAM_3A, th3, &keystream_3a));
	
	/* Step 7: CIPHERTEXT_3A = PLAINTEXT_3A XOR KEYSTREAM_3A */
	ciphertext->len = plaintext_3a.len;
	TRY(xor_arrays(&plaintext_3a, &keystream_3a, ciphertext));
	
	/* For TH_4 calculation, plaintext output is PLAINTEXT_3B */
	plaintext->len = plaintext_3b.len;
	TRY(_memcpy_s(plaintext->ptr, plaintext->len, 
	              plaintext_3b.ptr, plaintext_3b.len));
	
	return ok;
}

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
	struct byte_array *plaintext)
{
	/* PSK Message 3: Two-layer decryption per draft-ietf-lake-edhoc-psk-06 Section 5.3 */
	
	/* Step 1: CIPHERTEXT_3A = ciphertext (from Message 3) */
	/* Step 6: Generate KEYSTREAM_3A from PRK_3e2m */
	BYTE_ARRAY_NEW(keystream_3a, CIPHERTEXT3_SIZE, ciphertext->len);
	TRY(edhoc_kdf(suite->edhoc_hash, prk_3e2m, KEYSTREAM_3A, th3, &keystream_3a));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("KEYSTREAM_3A", keystream_3a.ptr, keystream_3a.len);
#endif
	
	/* Step 2: PLAINTEXT_3A = CIPHERTEXT_3A XOR KEYSTREAM_3A */
	BYTE_ARRAY_NEW(plaintext_3a, PLAINTEXT3_SIZE, ciphertext->len);
	TRY(xor_arrays(ciphertext, &keystream_3a, &plaintext_3a));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("PLAINTEXT_3A", plaintext_3a.ptr, plaintext_3a.len);
#endif
	
	/* Step 3: Extract ID_CRED_PSK and CIPHERTEXT_3B from PLAINTEXT_3A */
	struct byte_array plaintext_3a_remaining = plaintext_3a;
	
	/* Expect compact encoding: 0x41 <kid_byte> */
	if (plaintext_3a_remaining.len < 2 || plaintext_3a_remaining.ptr[0] != 0x41) {
		return cbor_decoding_error;
	}
	uint8_t kid_byte = plaintext_3a_remaining.ptr[1];
	
	/* Reconstruct full ID_CRED_PSK map: { 4 : h'XX' } */
	id_cred_psk->ptr[0] = 0xa1;
	id_cred_psk->ptr[1] = 0x04;
	id_cred_psk->ptr[2] = 0x41;
	id_cred_psk->ptr[3] = kid_byte;
	id_cred_psk->len = 4;
	
	plaintext_3a_remaining.ptr += 2;
	plaintext_3a_remaining.len -= 2;
#ifdef DEBUG_PRINT
	PRINT_ARRAY("ID_CRED_PSK (reconstructed)", id_cred_psk->ptr, id_cred_psk->len);
#endif
	
	/* Decode CIPHERTEXT_3B */
	BYTE_ARRAY_NEW(ciphertext_3b, CIPHERTEXT3_SIZE, CIPHERTEXT3_SIZE);
	TRY(decode_bstr(&plaintext_3a_remaining, &ciphertext_3b));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("CIPHERTEXT_3B (decoded)", ciphertext_3b.ptr, ciphertext_3b.len);
#endif
	
	/* Step 4: Retrieve CRED_I using ID_CRED_PSK */
	BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE);
	BYTE_ARRAY_NEW(pk_i, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_i_dummy, G_I_SIZE, G_I_SIZE);
	TRY(retrieve_cred(cred_i_array, id_cred_psk, &cred_i, &pk_i, &g_i_dummy));
#ifdef DEBUG_PRINT
	PRINT_ARRAY("CRED_I (retrieved)", cred_i.ptr, cred_i.len);
#endif
	
	/* Step 5: Generate K_3 and IV_3 from PRK_4e3m */
	uint32_t key_len = get_aead_key_len(suite->edhoc_aead);
	uint32_t iv_len = get_aead_iv_len(suite->edhoc_aead);
	BYTE_ARRAY_NEW(k_3, PK_SIZE, key_len);
	BYTE_ARRAY_NEW(iv_3, AEAD_IV_SIZE, iv_len);
	
#ifdef DEBUG_PRINT
	kprintf("\r\n========== RESPONDER: DECRYPT_3B ==========\r\n");
#endif
	TRY(edhoc_kdf(suite->edhoc_hash, prk_4e3m, K_3, th3, &k_3));
#ifdef DEBUG_PRINT
	print_hex("[R-DEC] K_3: ", k_3.ptr, k_3.len);
#endif
	TRY(edhoc_kdf(suite->edhoc_hash, prk_4e3m, IV_3, th3, &iv_3));
#ifdef DEBUG_PRINT
	print_hex("[R-DEC] IV_3: ", iv_3.ptr, iv_3.len);
#endif
	
	/* Step 6: Build external_aad = << ID_CRED_PSK, TH_3, CRED_I, CRED_R >>
	 * Note: << >> means CBOR sequence - raw CBOR data items concatenated, NOT encoded as bstr
	 */
	BYTE_ARRAY_NEW(external_aad, AAD_SIZE * 4, AAD_SIZE * 4);
	uint32_t external_aad_capacity = external_aad.len;
	external_aad.len = 0;
	
	/* Append ID_CRED_PSK as raw CBOR data item (compactly encoded if {4: kid}) */
	TRY(byte_array_append(&external_aad, id_cred_psk, external_aad_capacity));
	
	/* Append TH_3 as raw bytes (32-byte hash value, per draft test vector "TH_3 (Raw Value)") */
	TRY(byte_array_append(&external_aad, th3, external_aad_capacity));
	
	/* Append CRED_I as raw CBOR data item (already a CBOR map) */
	TRY(byte_array_append(&external_aad, &cred_i, external_aad_capacity));
	
	/* Append CRED_R as raw CBOR data item (already a CBOR map) */
	TRY(byte_array_append(&external_aad, cred_r, external_aad_capacity));
	
#ifdef DEBUG_PRINT
	kprintf("[R-DEC] external_aad.len=%d\r\n", external_aad.len);
	print_hex("[R-DEC] external_aad (FULL): ", external_aad.ptr, external_aad.len);
	print_hex("[R-DEC] CRED_I: ", cred_i.ptr, cred_i.len);
	print_hex("[R-DEC] CRED_R: ", cred_r->ptr, cred_r->len);
#endif
	
	/* Step 7: PLAINTEXT_3B = AEAD_decrypt(CIPHERTEXT_3B) 
	 * Note: For TinyCrypt, the tag must remain at the end of ciphertext_3b buffer
	 */
	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
#ifdef DEBUG_PRINT
	kprintf("[R-DEC] About to decrypt: ciphertext_3b.len=%d, tag_len=%d\r\n",
	        ciphertext_3b.len, tag_len);
	print_hex("[R-DEC] ciphertext_3b buffer: ", ciphertext_3b.ptr, ciphertext_3b.len);
#endif
	
	/* Calculate expected plaintext length */
	uint32_t plaintext_len = ciphertext_3b.len > tag_len ? ciphertext_3b.len - tag_len : 0;
	
	/* Allocate plaintext buffer - MUST allocate actual buffer even if plaintext is empty
	 * because TinyCrypt validates (out != NULL). BYTE_ARRAY_NEW with SIZE=0 sets ptr=NULL!
	 * Solution: Always allocate at least 1 byte, then set .len to actual plaintext length.
	 */
	BYTE_ARRAY_NEW(plaintext_3b, PLAINTEXT3_SIZE, plaintext_len > 0 ? plaintext_len : 1);
	plaintext_3b.len = plaintext_len;  // Set to actual plaintext length (may be 0)
	BYTE_ARRAY_NEW(tag_3b, MAC_SIZE, tag_len);
	
	/* TinyCrypt CCM expects ciphertext+tag in one buffer, don't modify ciphertext_3b */
	TRY(aead(DECRYPT, &ciphertext_3b, &k_3, &iv_3, &external_aad, 
	         &plaintext_3b, &tag_3b));
	kprintf("==========================================\r\n\r\n");
	PRINT_ARRAY("PLAINTEXT_3B (decrypted)", plaintext_3b.ptr, plaintext_3b.len);
	
	/* Step 8: Extract ?EAD_3 from PLAINTEXT_3B */
	if (plaintext_3b.len > 0) {
		TRY(decode_bstr(&plaintext_3b, ead));
		PRINT_ARRAY("EAD_3 (PSK)", ead->ptr, ead->len);
	} else {
		ead->len = 0;
		ead->ptr = NULL;
	}
	
	/* Copy PLAINTEXT_3B to plaintext output for TH_4 calculation */
	plaintext->len = plaintext_3b.len;
	TRY(_memcpy_s(plaintext->ptr, plaintext->len, 
	              plaintext_3b.ptr, plaintext_3b.len));
	
	return ok;
}
