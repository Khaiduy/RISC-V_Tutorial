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

#include "common/print_util.h"
#include "common/oscore_edhoc_error.h"
#include "common/debug.h"

void print_array(const uint8_t *in_data, uint32_t in_len)
{
	/* Print array using kprintf for bare-metal debugging */
	if (in_data == NULL || in_len == 0) {
		kprintf("[empty]\r\n");
		return;
	}
	
	for (uint32_t i = 0; i < in_len; i++) {
		kprintf("%x ", in_data[i]);
		if ((i + 1) % 16 == 0) {
			kprintf("\r\n");
		}
	}
	if (in_len % 16 != 0) {
		kprintf("\r\n");
	}
}

void handle_runtime_error(int error_code, const char *file_name, const int line)
{
	/* Always print errors in bare-metal for debugging */
	kprintf("[ERROR] Runtime error: code %d at %s:%d\r\n", error_code, file_name, line);
}

void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line)
{
// 	/* Always print errors in bare-metal for debugging */
	kprintf("[ERROR] External lib error: code %d at %s:%d\r\n", error_code, file_name, line);
}
