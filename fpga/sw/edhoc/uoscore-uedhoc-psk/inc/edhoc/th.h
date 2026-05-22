/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef TH_H
#define TH_H

#include "suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief                       Calculates transcript hash TH2
 *                              TH_2 = H( G_Y, H(message_1) ). 
 * 
 * @param alg                   Hash algorithm to be used.
 * @param[in] msg1_hash         Hash of Message 1.
 * @param[in] g_y               Public DH parameter.
 * @param[out] th2              The result.
 * @retval                      Ok or error.
 */
enum err th2_calculate(enum hash_alg alg, struct byte_array *msg1_hash,
		       struct byte_array *g_y,
		       struct byte_array *th2);

/**
 * @brief                       Calculates transcript hash th3/th4 
 *                              TH_3 = H(TH_2, PLAINTEXT_2) 
 *                              TH_4 = H(TH_3, PLAINTEXT_3) 
 * 
 * @param alg                   Hash algorithm to be used.
 * @param[in] th23              th2 ot th3.
 * @param[in] plaintext_23      Plaintext 2 or plaintext 3.
 * @param[in] cred              The credential.
 * @param[out] th34             The result.
 */
#ifndef EDHOC_PSK_ONLY
enum err th34_calculate(enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred, struct byte_array *th34);
#endif

/**
 * @brief 			Computes TH_3 for PSK mode. 
 * 				TH_3 = H(TH_2, PLAINTEXT_2A)
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] th2 		TH_2.
 * @param[in] plaintext_2a 	PLAINTEXT_2A (C_R, ?EAD_2).
 * @param[out] th3 		The result.
 * @return 			Ok or error. 
 */
enum err th3_calculate_psk(enum hash_alg alg, struct byte_array *th2,
			   struct byte_array *plaintext_2a,
			   struct byte_array *th3);

/**
 * @brief 			Computes TH_4 for PSK mode.
 * 				TH_4 = H(TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R)
 * 				where ID_CRED_PSK = ID_CRED_I and PLAINTEXT_3B = (?EAD_3)
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] th3 		TH_3.
 * @param[in] id_cred_psk 	ID_CRED_I (credential identifier).
 * @param[in] plaintext_3b 	PLAINTEXT_3B = (?EAD_3).
 * @param[in] cred_i 		CRED_I.
 * @param[in] cred_r 		CRED_R.
 * @param[out] th4 		The result.
 * @return 			Ok or error. 
 */
enum err th4_calculate_psk(enum hash_alg alg, struct byte_array *th3,
			   const struct byte_array *id_cred_psk,
			   const struct byte_array *plaintext_3b,
			   const struct byte_array *cred_i,
			   const struct byte_array *cred_r,
			   struct byte_array *th4);

#endif
