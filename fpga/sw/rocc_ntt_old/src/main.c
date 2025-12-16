#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <riscv-pk/encoding.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"

#define REG32(p, i) ((p)[(i) >> 2])

// ============================================
// Test variables
// ============================================
volatile uint32_t g_counter = 0;
volatile uint32_t g_value = 0xDEAD;
uint32_t g_array[8] = {10, 20, 30, 40, 50, 60, 70, 80};

typedef struct {
    uint32_t x;
    uint32_t y;
} point_t;

point_t g_point = {100, 200};

// ============================================
// Test 1: Arithmetic
// ============================================
uint32_t add(uint32_t a, uint32_t b) {
    uint32_t result = a + b;  // ← Breakpoint: inspect a, b, result
    return result;
}

uint32_t multiply(uint32_t a, uint32_t b) {
    uint32_t result = a * b;  // ← Breakpoint
    return result;
}

void test_arithmetic(void) {
    kprintf("[T1] Arithmetic\r\r\r\n");
    uint32_t r1 = add(123, 456);
    uint32_t r2 = multiply(7, 9);
    kprintf("  add=%u mul=%u\r\r\n", r1, r2);
}

// ============================================
// Test 2: Arrays
// ============================================
uint32_t sum_array(uint32_t *arr, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];  // ← Breakpoint: watch sum grow
    }
    return sum;
}

void fill_array(uint32_t *arr, int len, uint32_t start) {
    for (int i = 0; i < len; i++) {
        arr[i] = start + i;  // ← Breakpoint: watch array fill
    }
}

void test_arrays(void) {
    kprintf("[T2] Arrays\r\r\n");
    uint32_t s = sum_array(g_array, 8);
    kprintf("  sum=%u\r\n", s);
    fill_array(g_array, 4, 100);
    kprintf("  arr[0]=%u [3]=%u\r\n", g_array[0], g_array[3]);
}

// ============================================
// Test 3: Structures
// ============================================
void move_point(point_t *p, int dx, int dy) {
    p->x += dx;  // ← Breakpoint: watch struct change
    p->y += dy;
}

uint32_t point_distance(point_t *p) {
    return p->x + p->y;  // Simple "distance"
}

void test_structures(void) {
    kprintf("[T3] Structs\r\r\n");
    kprintf("  before: x=%u y=%u\r\n", g_point.x, g_point.y);
    move_point(&g_point, 5, 10);
    kprintf("  after:  x=%u y=%u\r\n", g_point.x, g_point.y);
}

// ============================================
// Test 4: Recursion
// ============================================
uint32_t factorial(uint32_t n) {
    if (n <= 1) {
        return 1;  // ← Breakpoint: base case
    }
    return n * factorial(n - 1);  // ← Breakpoint: check backtrace
}

uint32_t fibonacci(uint32_t n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

void test_recursion(void) {
    kprintf("[T4] Recursion\r\r\n");
    uint32_t f1 = factorial(5);
    uint32_t f2 = fibonacci(7);
    kprintf("  5!=%u fib(7)=%u\r\n", f1, f2);
}

// ============================================
// Test 5: Bit operations
// ============================================
uint32_t count_bits(uint32_t value) {
    uint32_t count = 0;
    for (int i = 0; i < 32; i++) {
        if (value & (1u << i)) {  // ← Conditional breakpoint: i==16
            count++;
        }
    }
    return count;
}

uint32_t reverse_bits(uint32_t value) {
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {  // Just reverse 8 bits
        result <<= 1;
        result |= (value & 1);
        value >>= 1;
    }
    return result;
}

void test_bits(void) {
    kprintf("[T5] Bits\r\r\n");
    uint32_t c = count_bits(0xA5A5);
    uint32_t r = reverse_bits(0x12);
    kprintf("  count=%u rev=0x%x\r\n", c, r);
}

// ============================================
// Test 6: Pointers and Memory
// ============================================
void swap(uint32_t *a, uint32_t *b) {
    uint32_t temp = *a;  // ← Breakpoint: examine pointers
    *a = *b;
    *b = temp;
}

void test_pointers(void) {
    kprintf("[T6] Pointers\r\r\n");
    uint32_t x = 111, y = 222;
    kprintf("  before: x=%u y=%u\r\n", x, y);
    swap(&x, &y);
    kprintf("  after:  x=%u y=%u\r\n", x, y);
}

// Test 8: Call stack depth
// ============================================
void deep_c(uint32_t d) {
    g_counter = d;  // ← Breakpoint: check backtrace depth
}

void deep_b(uint32_t d) {
    deep_c(d + 1);
}

void deep_a(uint32_t d) {
    deep_b(d + 1);
}

void test_callstack(void) {
    kprintf("[T8] Callstack\r\r\n");
    deep_a(1);
    kprintf("  depth=%u\r\n", g_counter);
}

// ============================================
// Test 9: Loops and conditions
// ============================================
uint32_t find_max(uint32_t *arr, int len) {
    uint32_t max = arr[0];
    for (int i = 1; i < len; i++) {
        if (arr[i] > max) {  // ← Conditional breakpoint
            max = arr[i];
        }
    }
    return max;
}

void test_loops(void) {
    kprintf("[T9] Loops\r\r\n");
    uint32_t max = find_max(g_array, 8);
    kprintf("  max=%u\r\n", max);
}

// ============================================
// Main
// ============================================
int main(void) {
    // Init UART
    REG32(uart, UART_REG_DIV) = 83; //Frequency / Baudrate
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;

    kprintf("\r\nPrint with new frequency\r\r\r\n");

    // Run all tests
    test_arithmetic();
    test_arrays();
    test_structures();
    test_recursion();
    test_bits();
    test_pointers();
    test_callstack();
    test_loops();
    kprintf("=== Tests Complete ===\r\r\r\n");

    // Infinite loop for manual GDB testing
    while (1) {
        g_counter++;  // ← Main breakpoint for manual testing
        g_value ^= 1;

        // Progress indicator every ~1000 loops
        if ((g_counter % 1000) == 0) {
            kprintf(".\r\n");

        }
    }
    
    return 0;
}