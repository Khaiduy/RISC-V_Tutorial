/*
 * Minimal libc stubs for bare-metal RISC-V
 * 
 * These provide basic string and I/O functions without the full C library
 * to save code size.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

// Forward declarations of bare-metal print functions
extern int kprintf(const char *format, ...);
extern void vkprintf(const char *format, va_list vl);

// ============================================
// Memory Functions
// ============================================

void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    
    while (n--) {
        *d++ = *s++;
    }
    
    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    
    while (n--) {
        *p++ = (uint8_t)c;
    }
    
    return s;
}

size_t strlen(const char *s) {
    size_t len = 0;
    
    while (*s++) {
        len++;
    }
    
    return len;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    
    // Pad with null bytes if needed
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    
    return 0;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    
    if (d < s) {
        // Copy forward
        while (n--) {
            *d++ = *s++;
        }
    } else {
        // Copy backward
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    
    return dest;
}

// ============================================
// I/O Functions (stub implementations)
// ============================================

int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vkprintf(format, args);
    va_end(args);
    return 0;
}

// ============================================
// Other commonly needed stubs
// ============================================

void abort(void) {
    // Hang forever
    while (1) {
        __asm__ volatile("nop");
    }
}

void __assert_func(const char *file, int line, const char *func, const char *expr) {
    (void)file;
    (void)line;
    (void)func;
    (void)expr;
    abort();
}

// For newer GCC
void __stack_chk_fail(void) {
    abort();
}

void *__stack_chk_guard = (void *)0xdeadbeef;

// ============================================
// Memory allocation stubs (not actually implemented)
// ============================================

void *malloc(size_t size) {
    (void)size;
    return (void *)0;  // Return NULL - allocation not supported
}

void *calloc(size_t nmemb, size_t size) {
    (void)nmemb;
    (void)size;
    return (void *)0;  // Return NULL - allocation not supported
}

void *realloc(void *ptr, size_t size) {
    (void)ptr;
    (void)size;
    return (void *)0;  // Return NULL - reallocation not supported
}

void free(void *ptr) {
    (void)ptr;
    // Do nothing - no heap management
}

/* File I/O stubs intentionally removed: wolfSSL is built with NO_FILESYSTEM,
 * and no app code calls fopen/fread/etc. If a future build references one,
 * the linker will fail loudly — better than a silent no-op.
 */
