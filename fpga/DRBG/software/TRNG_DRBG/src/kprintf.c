// See LICENSE.Sifive for license details.
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include "kprintf.h"

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
    bool is_format = false;
    bool is_long = false;
    char c;

    va_start(vl, fmt);

    while ((c = *fmt++) != '\0') {
        if (is_format) {
            switch (c) {
            case 'l':
                is_long = true;
                continue;

            case 'x': {
                uint64_t n;
                int i;
                bool started = false;

                if (is_long)
                    n = va_arg(vl, uint64_t);
                else
                    n = va_arg(vl, uint32_t);

                for (i = (is_long ? 60 : 28); i >= 0; i -= 4) {
                    uint8_t d = (n >> i) & 0xF;
                    if (d || started || i == 0) {
                        kputc(d < 10 ? '0' + d : 'a' + d - 10);
                        started = true;
                    }
                }
                break;
            }

            case 's':
                _kputs(va_arg(vl, const char *));
                break;

            case 'c':
                kputc(va_arg(vl, int));
                break;
            }

            is_format = false;
            is_long = false;
        }
        else if (c == '%') {
            is_format = true;
        }
        else {
            kputc(c);
        }
    }

    va_end(vl);
}

