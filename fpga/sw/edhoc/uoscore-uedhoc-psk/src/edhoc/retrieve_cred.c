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

#include "edhoc/bstr_encode_decode.h"
#include "edhoc/retrieve_cred.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "cbor/edhoc_decode_id_cred_x.h"

/**
 * @brief 			Get the local credential for PSK authentication.
 * 
 * @param[in] cred_array 	An array of credentials
 * @param[in] ID_cred 		The ID of the actual credential.
 * @param[out] cred 		The retrieved credentials	
 * @param[out] pk 		The retrieved PSK (stored in pk field)
 * @param[out] g 		Unused in PSK mode
 * @return 			Ok or error code
 */
static enum err get_local_cred(struct cred_array *cred_array,
			       struct byte_array *ID_cred,
			       struct byte_array *cred, struct byte_array *pk,
			       struct byte_array *g)
{
	for (uint32_t i = 0; i < cred_array->len; i++) {
		if ((cred_array->ptr[i].id_cred.len == ID_cred->len) &&
		    (0 == memcmp(cred_array->ptr[i].id_cred.ptr, ID_cred->ptr,
				 ID_cred->len))) {
#ifdef DEBUG_PRINT
			kprintf("[DEBUG] retrieve_cred: cred dest.len=%u, source.len=%u\r\n", 
				cred->len, cred_array->ptr[i].cred.len);
			kprintf("[DEBUG] retrieve_cred: pk dest.len=%u, source.len=%u\r\n", 
				pk->len, cred_array->ptr[i].pk.len);
#endif
			/*retrieve CRED_x*/
			TRY(_memcpy_s(cred->ptr, cred->len,
				      cred_array->ptr[i].cred.ptr,
				      cred_array->ptr[i].cred.len));
			cred->len = cred_array->ptr[i].cred.len;

			/*retrieve PSK (stored in pk field)*/
			g->len = 0; /* Not used in PSK mode */
			TRY(_memcpy_s(pk->ptr, pk->len,
				      cred_array->ptr[i].pk.ptr,
				      cred_array->ptr[i].pk.len));
			pk->len = cred_array->ptr[i].pk.len;
			return ok;
		}
	}

	return credential_not_found;
}

enum err retrieve_cred(struct cred_array *cred_array,
		       struct byte_array *id_cred, struct byte_array *cred,
		       struct byte_array *pk, struct byte_array *g)
{
	size_t decode_len = 0;
	struct id_cred_x_map map = { 0 };

	TRY_EXPECT(cbor_decode_id_cred_x_map(id_cred->ptr, id_cred->len, &map,
					     &decode_len),
		   0);
	
	/* PSK mode: credential should be locally available (kid is used) */
	if (map.id_cred_x_map_kid_present || map.id_cred_x_map_x5u_present ||
	    map.id_cred_x_map_x5t_present || map.id_cred_x_map_c5u_present ||
	    map.id_cred_x_map_c5t_present) {
		TRY(get_local_cred(cred_array, id_cred, cred, pk, g));
		return ok;
	}
	
	/* PSK mode does not support certificate-based authentication */
	return credential_not_found;
}
