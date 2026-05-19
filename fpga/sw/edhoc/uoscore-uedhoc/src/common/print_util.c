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
#include <stdio.h>

#include "common/print_util.h"

extern void kputc(char c);
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/* Build the full hex dump in one buffer and emit via a single printf — eliminates
 * the per-byte printf transitions that cause the FT2232H to drop bytes mid-dump.
 * One printf = one sync-byte prefix + one continuous burst on the wire. */
static char dump_buf[1024];
static const char hex_digits[] = "0123456789ABCDEF";

static char *emit_decimal(char *p, uint32_t value)
{
	char tmp[10];
	int n = 0;
	if (value == 0) { *p++ = '0'; return p; }
	while (value != 0) { tmp[n++] = (char)('0' + (value % 10)); value /= 10; }
	while (n != 0) { *p++ = tmp[--n]; }
	return p;
}

void print_array(const uint8_t *in_data, uint32_t in_len)
{
	print_labeled_array(NULL, in_data, in_len);
}

void print_labeled_array(const char *label, const uint8_t *in_data,
			 uint32_t in_len)
{
	char *p = dump_buf;

	if (NULL != label) {
		const char *s = label;
		while (*s != '\0' && (size_t)(p - dump_buf) < sizeof(dump_buf) - 1)
			*p++ = *s++;
	}

	*p++ = ' '; *p++ = '('; *p++ = 's'; *p++ = 'i'; *p++ = 'z'; *p++ = 'e'; *p++ = ' ';
	p = emit_decimal(p, in_len);
	*p++ = ')'; *p++ = ':';

	uint8_t xor_chk = 0;
	if (NULL != in_data) {
		for (uint32_t i = 0; i < in_len; i++) {
			/* Stop if buffer is about to overflow (leave room for "\r\n[xor:0xNN]\r\n\0") */
			if ((size_t)(p - dump_buf) > sizeof(dump_buf) - 28) {
				*p++ = '.'; *p++ = '.'; *p++ = '.';
				break;
			}
			if (i % 16 == 0) { *p++ = '\r'; *p++ = '\n'; *p++ = ' '; *p++ = ' '; }
			*p++ = hex_digits[(in_data[i] >> 4) & 0xF];
			*p++ = hex_digits[in_data[i] & 0xF];
			*p++ = ' ';
			xor_chk ^= in_data[i];
		}
	}
	/* Integrity tag: XOR of all bytes. If captured dump XORs to this value,
	 * no bytes were lost on the wire. If not, retry the run. */
	*p++ = '\r'; *p++ = '\n';
	*p++ = '['; *p++ = 'x'; *p++ = 'o'; *p++ = 'r'; *p++ = ':'; *p++ = '0'; *p++ = 'x';
	*p++ = hex_digits[(xor_chk >> 4) & 0xF];
	*p++ = hex_digits[xor_chk & 0xF];
	*p++ = ']'; *p++ = '\r'; *p++ = '\n';
	*p = '\0';

	/* Single printf — single vkprintf trip, single sync byte, no mid-dump transitions */
	// kprintf("%s", dump_buf);
	// 4. THE NUCLEAR OPTION: Per-byte delay
		char *curr = dump_buf;
		while (*curr != '\0') {
			kputc(*curr);
			
			/* * A small delay after EVERY byte. 
			* At 57,600 baud, one byte takes ~173 microseconds.
			* We add a ~50 microsecond gap.
			*/
			for (volatile int d = 0; d < 2000; d++); 

			// Additional pause on newlines
			if (*curr == '\n') {
				for (volatile int d = 0; d < 50000; d++); 
			}
			curr++;
		}
}

void handle_runtime_error(int error_code, const char *file_name, const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;

#ifdef DEBUG_PRINT
	if (transport_deinitialized == error_code) {
		PRINTF(transport_deinit_message, file_name, line);
	} else {
		PRINTF(runtime_error_message, error_code, file_name, line);
	}
#endif
}

void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;

#ifdef DEBUG_PRINT
	PRINTF(external_runtime_error_message, error_code, file_name, line);
#endif
}
