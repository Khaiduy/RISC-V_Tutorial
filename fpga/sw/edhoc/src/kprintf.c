// See LICENSE.Sifive for license details.
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include "kprintf.h"

#include <stddef.h>


// memmove moved to libc_stubs.c

/* Single out-of-line kputc definition.
 * Under -flto, an inline-in-header version may be inlined inconsistently across
 * translation units; one out-of-line definition guarantees every caller hits
 * the same verified-clean MMIO sequence (load → branch-if-full → store). */
__attribute__((noinline)) void kputc(char c)
{
	volatile uint32_t *tx = &REG32(uart, UART_REG_TXFIFO);
	while ((int32_t)(*tx) < 0);
	*tx = (uint32_t)(uint8_t)c;
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

void vkprintf(const char *fmt, va_list vl)
{
	bool is_format, is_long, is_char;
	char c;

	is_format = false;
	is_long = false;
	is_char = false;

	while ((c = *fmt++) != '\0') {
		if (is_format) {
			switch (c) {
			case '0':
				continue;

			case '1': case '2': case '3': case '4': case '5':
			case '6': case '7': case '8': case '9':
				continue;

			case 'l':
				is_long = true;
				continue;

			case 'd': {
				if (is_long) {
					unsigned long n = va_arg(vl, unsigned long);
					char buf[32];
					int idx = 0;
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) { buf[idx++] = '0' + (n % 10); n = n / 10; }
						for (int i = idx - 1; i >= 0; i--) kputc(buf[i]);
					}
				} else {
					int n = va_arg(vl, int);
					char buf[16];
					int idx = 0;
					if (n < 0) { kputc('-'); n = -n; }
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) { buf[idx++] = '0' + (n % 10); n = n / 10; }
						for (int i = idx - 1; i >= 0; i--) kputc(buf[i]);
					}
				}
				break;
			}

			case 'u': {
				if (is_long) {
					unsigned long n = va_arg(vl, unsigned long);
					char buf[32];
					int idx = 0;
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) { buf[idx++] = '0' + (n % 10); n = n / 10; }
						for (int i = idx - 1; i >= 0; i--) kputc(buf[i]);
					}
				} else {
					unsigned int n = va_arg(vl, unsigned int);
					char buf[16];
					int idx = 0;
					if (n == 0) {
						kputc('0');
					} else {
						while (n != 0) { buf[idx++] = '0' + (n % 10); n = n / 10; }
						for (int i = idx - 1; i >= 0; i--) kputc(buf[i]);
					}
				}
				break;
			}

			case 'h':
				is_char = true;
				continue;

			case 'X':
			case 'x': {
				unsigned long n;
				long i;
				bool upper = (c == 'X');
				if (is_long) {
					n = va_arg(vl, unsigned long);
					i = (sizeof(unsigned long) << 3) - 4;
				} else {
					n = va_arg(vl, unsigned int);
					i = is_char ? 4 : (sizeof(unsigned int) << 3) - 4;
				}
				if (!is_char) {
					long temp_i = i;
					while (temp_i > 0 && ((n >> temp_i) & 0xF) == 0) temp_i -= 4;
					i = temp_i;
				}
				for (; i >= 0; i -= 4) {
					long d = (n >> i) & 0xF;
					kputc(d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10);
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
}

void kprintf(const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vkprintf(fmt, vl);
	va_end(vl);
}
