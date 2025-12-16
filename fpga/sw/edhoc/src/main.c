#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
//#include <time.h>
// #include <riscv-pk/encoding.h>  // Not needed for bare-metal
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
// #include "x25519/x25519.h"  // Not used in current main()
// #include "rocc.h"

// #define DELAY_COUNT 373502771
// void delay(uint32_t count) {
//     for (; count > 0; count--) {
//         // Busy-wait loop (no-op)
//         kprintf("count: %u\r\n", count);
//     }
// }

// #define REG32(p, i)	((p)[(i) >> 2])

// // Accurate timing measurement macro
// #define START_TIMING() \
//     do { \
//         asm volatile ("fence" ::: "memory"); \
//         start = rdcycle(); \
//     } while(0)

// #define END_TIMING() \
//     do { \
//         asm volatile ("fence" ::: "memory"); \
//         end = rdcycle(); \
//     } while(0)

// int main(int hartid, char **argv) {
  
//   REG32(uart, UART_REG_DIV) = 868; // 50MHz / 57600
//   REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
//   kprintf("Hello from EDHOC FPGA board\r\n");

//   void* x25519ctrl = (void*)X25519_CTRL_ADDR;
//   kprintf("X25519 ECDH Protocol Test (RFC 7748)\r\n");
//   kprintf("====================================\r\n");
//   unsigned long start, end;

//   uint64_t alice_private[4] = {
//       0x00c9a7a05a86e348ULL,
//       0x3723b76b016f39c4ULL,
//       0x117409f0f934ab05ULL,
//       0x608f0e1e23bb7d75ULL
//   };

//   uint64_t bob_private[4] = {
//       0x5625b841a21c0000ULL,
//       0x32b956a8512af35fULL,
//       0xe26832a35bcc2932ULL,
//       0xf56b9fcf4418f6e9ULL
//   };

//   uint64_t base_point[4] = {
//       0x0900000000000000ULL,
//       0x0000000000000000ULL,
//       0x0000000000000000ULL,
//       0x0000000000000000ULL
//   };

//   uint64_t alice_public[4];
//   uint64_t bob_public[4];
//   uint64_t alice_shared[4];
//   uint64_t bob_shared[4];

//   // Step 1: Alice computes K_A = X25519(a, 9)
//   kprintf("Alice's private key 'a': ");
//   for(int i = 3; i >= 0; i--) {  // Print in reverse order (big-endian)
//       kprintf("%lx", alice_private[i]);
//   }
//   kprintf("\r\n");

//   START_TIMING();
//   hwx25519_init(x25519ctrl, alice_private, base_point);
//   hwx25519_results(x25519ctrl, alice_public);
//   END_TIMING();
//   kprintf("Step 1: %lu cycles\r\n", (unsigned long)(end - start));

//   kprintf("Alice's public key 'K_A': ");
//   for(int i = 3; i >= 0; i--) {
//       kprintf("%lx", alice_public[i]);
//   }
//   kprintf("\r\n\r\n");

//   // Step 2: Bob computes K_B = X25519(b, 9)
//   kprintf("Bob's private key 'b':    ");
//   for(int i = 3; i >= 0; i--) {
//       kprintf("%lx", bob_private[i]);
//   }
//   kprintf("\r\n");

//   START_TIMING();
//   hwx25519_init(x25519ctrl, bob_private, base_point);
//   hwx25519_results(x25519ctrl, bob_public);
//   END_TIMING();
//   kprintf("Step 2: %lu cycles\r\n", (unsigned long)(end - start));

//   kprintf("Bob's public key 'K_B':   ");
//   for(int i = 3; i >= 0; i--) {
//       kprintf("%lx", bob_public[i]);
//   }
//   kprintf("\r\n\r\n");

//   // Step 3: Alice computes shared secret X25519(a, K_B)
//   START_TIMING();
//   hwx25519_init(x25519ctrl, alice_private, bob_public);
//   hwx25519_results(x25519ctrl, alice_shared);
//   END_TIMING();
//   kprintf("Step 3: %lu cycles\r\n", (unsigned long)(end - start));

//   kprintf("Alice's shared secret:    ");
//   for(int i = 3; i >= 0; i--) {
//       kprintf("%lx", alice_shared[i]);
//   }
//   kprintf("\r\n\r\n");

//   // Step 4: Bob computes shared secret X25519(b, K_A)
//   START_TIMING();
//   hwx25519_init(x25519ctrl, bob_private, alice_public);
//   hwx25519_results(x25519ctrl, bob_shared);
//   END_TIMING();
//   kprintf("Step 4: %lu cycles\r\n", (unsigned long)(end - start));

//   kprintf("Bob's shared secret:      ");
//   for(int i = 3; i >= 0; i--) {
//       kprintf("%lx", bob_shared[i]);
//   }
//   kprintf("\r\n\r\n");

//   // Verify shared secrets match
//   kprintf("Secrets match: ");
//   int match = 1;
//   for(int i = 0; i < 4; i++) {
//       if(alice_shared[i] != bob_shared[i]) {
//           match = 0;
//           break;
//       }
//   }
//   kprintf("%s\r\n", match ? "YES" : "NO");


// while (1) {
// //    kprintf("Exiting main\r\n");
// //    delay(DELAY_COUNT);
// }
//   return 0;
// }


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
    REG32(uart, UART_REG_DIV) = 868; //Frequency / Baudrate
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

        // Progress indicator every ~1000000 loops
        if ((g_counter % 1000000) == 0) {
            kprintf(".\r\n");

        }
    }
    
    return 0;
}
