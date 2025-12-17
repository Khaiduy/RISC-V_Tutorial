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

#include "edhoc/edhoc_method_type.h"

#include "common/oscore_edhoc_error.h"

void authentication_type_get(enum method_type m, volatile bool *static_dh_i,
			     volatile bool *static_dh_r)
{
	/* PSK mode only: Method 4 - no static DH authentication */
	(void)m; /* Unused - only Method 4 supported */
	*static_dh_i = false;
	*static_dh_r = false;
}

bool is_psk_authentication(enum method_type m)
{
	return (m == INITIATOR_PSK_RESPONDER_PSK);
}
