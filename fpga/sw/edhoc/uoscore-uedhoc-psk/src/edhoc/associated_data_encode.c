/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <string.h>

#include "edhoc/associated_data_encode.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/byte_array.h"
#include "common/debug.h"

enum err associated_data_encode(struct byte_array *thX, struct byte_array *out)
{
	// kprintf("[ASSOC] === FUNCTION ENTRY === thX addr=%lx out addr=%lx\r\n", 
	//         (unsigned long)thX, (unsigned long)out);
	// kprintf("[ASSOC] thX->ptr=%lx thX->len=%d\r\n", (unsigned long)thX->ptr, thX->len);
	// kprintf("[ASSOC] out->ptr=%lx out->len=%d\r\n", (unsigned long)out->ptr, out->len);
	
	/* CRITICAL: Do NOT use { "string" } syntax - it includes null terminator!
	 * Use "string" directly or {'c','h','a','r','s'} to avoid extra byte */
	uint8_t context_str[] = "Encrypt0";  // 8 bytes: E,n,c,r,y,p,t,0 (no null terminator in size calc)
	// kprintf("[ASSOC] Context string allocated\r\n");
	
	/* Use hardcoded length 8 to match COSE spec exactly */
	struct byte_array context = BYTE_ARRAY_INIT(context_str, 8);
	// kprintf("[ASSOC] Context initialized, len=%d\r\n", context.len);
	
	/* Use local empty array instead of global NULL_ARRAY to avoid linkage issues */
	struct byte_array protected_empty = {.len = 0, .ptr = NULL};
	// kprintf("[ASSOC] Protected empty array: ptr=%lx len=%d\r\n", 
	//         (unsigned long)protected_empty.ptr, protected_empty.len);
	// kprintf("[ASSOC] Calling cose_enc_structure_encode...\r\n");
	enum err result = cose_enc_structure_encode(&context, &protected_empty, thX, out);
	// kprintf("[ASSOC] cose_enc_structure_encode returned: %d\r\n", result);
	return result;
}
