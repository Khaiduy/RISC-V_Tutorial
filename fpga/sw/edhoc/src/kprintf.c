// See LICENSE.Sifive for license details.
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include "kprintf.h"

#include <stddef.h>


// memmove moved to libc_stubs.c


static inline void _kputs(const char *s)
{
	char c;
	for (; (c = *s) != '\0'; s++)
		kputc(c);
}

void kputs(const char *s)
{
	_kputs(s);
	kputc('\r');
	kputc('\n');
}

void kprintf(const char *fmt, ...)
{
	va_list vl;
	bool is_format, is_long, is_char;
	char c;

	va_start(vl, fmt);
	is_format = false;
	is_long = false;
	is_char = false;
	
	while ((c = *fmt++) != '\0') {
		if (is_format) {
			switch (c) {
			case 'l':
				is_long = true;
				continue;
				
			case 'd': {
				if (is_long) {
					// Handle %ld - unsigned long decimal
					unsigned long n = va_arg(vl, unsigned long);
					char buf[32];
					int idx = 0;
					
					if (n == 0) {
						kputc('0');
					} else {
						// Build string in reverse
						while (n != 0) {
							buf[idx++] = '0' + (n % 10);
							n = n / 10;
						}
						// Print in correct order
						for (int i = idx - 1; i >= 0; i--) {
							kputc(buf[i]);
						}
					}
				} else {
					// Handle %d - unsigned int decimal
					unsigned int n = va_arg(vl, unsigned int);
					char buf[16];
					int idx = 0;
					
					if (n == 0) {
						kputc('0');
					} else {
						// Build string in reverse
						while (n != 0) {
							buf[idx++] = '0' + (n % 10);
							n = n / 10;
						}
						// Print in correct order
						for (int i = idx - 1; i >= 0; i--) {
							kputc(buf[i]);
						}
					}
				}
				break;
			}
			
			case 'u': {
				// Same as %d but more explicit about unsigned
				if (is_long) {
					unsigned long n = va_arg(vl, unsigned long);
					char buf[32];
					int idx = 0;
					
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) {
							buf[idx++] = '0' + (n % 10);
							n = n / 10;
						}
						for (int i = idx - 1; i >= 0; i--) {
							kputc(buf[i]);
						}
					}
				} else {
					unsigned int n = va_arg(vl, unsigned int);
					char buf[16];
					int idx = 0;
					
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) {
							buf[idx++] = '0' + (n % 10);
							n = n / 10;
						}
						for (int i = idx - 1; i >= 0; i--) {
							kputc(buf[i]);
						}
					}
				}
				break;
			}
			
			case 'h':
				is_char = true;
				continue;
				
			case 'x': {
				unsigned long n;
				long i;
				if (is_long) {
					n = va_arg(vl, unsigned long);
					i = (sizeof(unsigned long) << 3) - 4;
				} else {
					n = va_arg(vl, unsigned int);
					if (is_char) {
						i = 4;  // 1 byte = 2 hex digits = 8 bits, start at bit 4
					} else {
						i = (sizeof(unsigned int) << 3) - 4;
					}
				}
				
				// Skip leading zeros for non-char types
				if (!is_char) {
					// Find first non-zero nibble
					long temp_i = i;
					while (temp_i > 0 && ((n >> temp_i) & 0xF) == 0) {
						temp_i -= 4;
					}
					i = temp_i;
				}
				
				for (; i >= 0; i -= 4) {
					long d;
					d = (n >> i) & 0xF;
					kputc(d < 10 ? '0' + d : 'a' + d - 10);
				}
				break;
			}
			
			case 's':
				_kputs(va_arg(vl, const char *));
				break;
				
			case 'c':
				kputc(va_arg(vl, int));
				break;
				
			case '%':
				kputc('%');
				break;
				
			default:
				// Unknown format specifier, just print it
				kputc('%');
				kputc(c);
				break;
			}
			
			is_format = false;
			is_long = false;
			is_char = false;
			
		} else if (c == '%') {
			is_format = true;
		} else {
			kputc(c);
		}
	}
	va_end(vl);
}