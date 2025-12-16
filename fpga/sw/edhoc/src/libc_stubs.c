/*
 * Minimal libc stubs for bare-metal RISC-V
 * 
 * These provide basic string and I/O functions without the full C library
 * to save code size.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

// Forward declaration of kprintf (if available)
extern int kprintf(const char *format, ...);

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
    // For EDHOC demo, we can either:
    // 1. Use kprintf if available
    // 2. Just return 0 (no-op) to save code size
    
    // Option 1: Use kprintf
    va_list args;
    va_start(args, format);
    // Note: This requires kprintf to accept va_list, or we skip it
    va_end(args);
    
    // Option 2: No-op (uncomment to disable printf completely)
    // (void)format;
    // return 0;
    
    return 0;
}

int putchar(int c) {
    // Stub: would normally output to UART
    // For now, just return the character
    (void)c;
    return c;
}

int puts(const char *s) {
    // Stub implementation
    (void)s;
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

// ============================================
// File I/O stubs (not implemented for bare-metal)
// ============================================

typedef struct {
    int unused;
} FILE;

FILE *fopen(const char *filename, const char *mode) {
    (void)filename;
    (void)mode;
    return (FILE *)0;  // Return NULL - file operations not supported
}

int fclose(FILE *stream) {
    (void)stream;
    return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;  // No bytes read
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;  // No bytes written
}
