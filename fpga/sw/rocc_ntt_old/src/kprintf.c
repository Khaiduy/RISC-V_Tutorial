// See LICENSE.Sifive for license details.
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include "kprintf.h"

#include <stddef.h>


// Provide memmove since -nostdlib
void *memmove(void *dest, const void *src, size_t n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    if (d < s) {
        for (size_t i = 0; i < n; ++i) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0; --i) {
            d[i-1] = s[i-1];
        }
    }
    return dest;
}

// Add this before kprintf function
void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}


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
					i = (sizeof(unsigned long) << 3) - 4;  // 64-bit: start at bit 60
				} else if (is_char) {
					n = va_arg(vl, unsigned int) & 0xFF;
					i = 4;  // 8-bit: only 2 hex digits
				} else {
					// Regular %x treats it as 32-bit unsigned int
					n = va_arg(vl, unsigned int);
					// Mask to 32 bits to prevent sign extension
					n = n & 0xFFFFFFFFUL;
					i = (sizeof(unsigned int) << 3) - 4;  // 32-bit: start at bit 28
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
