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

#include "edhoc/buffer_sizes.h"

#include "edhoc/suites.h"
#include "edhoc/prk.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"
#include "common/debug.h"

enum err prk_derive(struct suite suite, uint8_t label,
		    struct byte_array *context, const struct byte_array *prk_in,
		    const struct byte_array *stat_pk,
		    const struct byte_array *stat_sk, uint8_t *prk_out)
{
	/* PSK mode: no static DH authentication, just copy prk_in to prk_out */
	(void)suite;      /* Unused in PSK mode */
	(void)label;      /* Unused in PSK mode */
	(void)context;    /* Unused in PSK mode */
	(void)stat_pk;    /* Unused in PSK mode */
	(void)stat_sk;    /* Unused in PSK mode */
	
	/* PRKs have the same size, safe to copy */
	memcpy(prk_out, prk_in->ptr, prk_in->len);
	return ok;
}

/**
 * @brief   			Derives PRK_4e3m for PSK authentication.
 * 				For PSK mode: PRK_4e3m = EDHOC_Extract(SALT_4e3m, PSK)
 * 
 * @param suite 		The used crypto suite.
 * @param context 		Context for SALT_4e3m derivation (typically TH_3).
 * @param prk_in 		Input PRK (PRK_3e2m) for salt derivation.
 * @param psk 			The pre-shared key.
 * @param[out] prk_out 	The derived PRK_4e3m.
 * @return  			Ok or error code.
 */
enum err prk_derive_psk(struct suite suite, struct byte_array *context,
			const struct byte_array *prk_in,
			const struct byte_array *psk, uint8_t *prk_out)
{
#ifdef DEBUG_PRINT
	kprintf("\r\n========== PRK_4e3m DERIVATION (PSK) ==========\r\n");
	kprintf("[PRK_PSK] PRK_3e2m: "); PRINT_ARRAY("", prk_in->ptr, prk_in->len);
	kprintf("[PRK_PSK] TH_3: "); PRINT_ARRAY("", context->ptr, context->len);
	kprintf("[PRK_PSK] PSK: "); PRINT_ARRAY("", psk->ptr, psk->len);
#endif
	
	BYTE_ARRAY_NEW(salt_4e3m, HASH_SIZE, get_hash_len(suite.edhoc_hash));
	TRY(edhoc_kdf(suite.edhoc_hash, prk_in, SALT_4e3m, context, &salt_4e3m));
#ifdef DEBUG_PRINT
	kprintf("[PRK_PSK] SALT_4e3m: "); PRINT_ARRAY("", salt_4e3m.ptr, salt_4e3m.len);
#endif

	/* Cast away const - hkdf_extract API doesn't modify ikm but signature isn't const */
	TRY(hkdf_extract(suite.edhoc_hash, &salt_4e3m, (struct byte_array *)psk, prk_out));
#ifdef DEBUG_PRINT
	kprintf("[PRK_PSK] PRK_4e3m: "); PRINT_ARRAY("", prk_out, get_hash_len(suite.edhoc_hash));
#endif
	
	return ok;
}

