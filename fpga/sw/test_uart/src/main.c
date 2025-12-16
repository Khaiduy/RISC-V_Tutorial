#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"

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
// UART Test Configuration
// ============================================
#define UART0_BASE 0x64000000UL  // USB UART
#define UART1_BASE 0x64003000UL  // PMOD C UART

#define REG32(p, i) ((p)[(i) >> 2])

// Simple UART functions
static inline void uart_putc(volatile uint32_t *uart_base, char c) {
    while ((int32_t)REG32(uart_base, UART_REG_TXFIFO) < 0);
    REG32(uart_base, UART_REG_TXFIFO) = c;
}

static inline int uart_getc(volatile uint32_t *uart_base) {
    int32_t val = (int32_t)REG32(uart_base, UART_REG_RXFIFO);
    return (val < 0) ? -1 : (val & 0xFF);
}

// ============================================
// UART Test Functions
// ============================================

// Test 1: Check UART configuration
void test_uart_config(void) {
    volatile uint32_t *uart0 = (volatile uint32_t *)UART0_BASE;
    volatile uint32_t *uart1 = (volatile uint32_t *)UART1_BASE;
    
    kprintf("\r\n=== UART Configuration Test ===\r\n");
    kprintf("UART0 (USB):   0x%x\r\n", UART0_BASE);
    kprintf("UART1 (PMOD):  0x%x\r\n", UART1_BASE);
    
    uint32_t uart0_tx = REG32(uart0, UART_REG_TXCTRL);
    uint32_t uart0_rx = REG32(uart0, UART_REG_RXCTRL);
    uint32_t uart1_tx = REG32(uart1, UART_REG_TXCTRL);
    uint32_t uart1_rx = REG32(uart1, UART_REG_RXCTRL);
    
    kprintf("UART0: TX=%s RX=%s\r\n", 
            (uart0_tx & UART_TXEN) ? "ON" : "OFF",
            (uart0_rx & UART_RXEN) ? "ON" : "OFF");
    kprintf("UART1: TX=%s RX=%s\r\n", 
            (uart1_tx & UART_TXEN) ? "ON" : "OFF",
            (uart1_rx & UART_RXEN) ? "ON" : "OFF");
}

// Test 2: Board A - Send characters and receive echo
void test_board_a(void) {
    volatile uint32_t *uart0 = (volatile uint32_t *)UART0_BASE;
    volatile uint32_t *uart1 = (volatile uint32_t *)UART1_BASE;
    
    kprintf("\r\n=== Board A Mode ===\r\n");
    kprintf("Type characters - they will be sent to Board B\r\n");
    kprintf("Board B will echo back what it receives\r\n");
    kprintf("Press Ctrl+C to exit\r\n\r\n");
    
    while (1) {
        // Check for key press on UART0 (USB console)
        int c = uart_getc(uart0);
        if (c >= 0) {
            // Display what we're sending
            kprintf("A->B: '%c' (0x%02x)\r\n", c, c);
            
            // Send character to Board B via UART1
            uart_putc(uart1, c);
            
            // Wait for echo from Board B
            int echo = -1;
            int timeout = 100000;  // Timeout counter
            while (timeout-- > 0) {
                echo = uart_getc(uart1);
                if (echo >= 0) break;
            }
            
            if (echo >= 0) {
                kprintf("B->A: '%c' (0x%02x) ", echo, echo);
                if (echo == c) {
                    kprintf("[MATCH]\r\n");
                } else {
                    kprintf("[MISMATCH!]\r\n");
                }
            } else {
                kprintf("B->A: [TIMEOUT]\r\n");
            }
            kprintf("\r\n");
        }
    }
}

// Test 3: Board B - Receive and echo characters
void test_board_b(void) {
    volatile uint32_t *uart0 = (volatile uint32_t *)UART0_BASE;
    volatile uint32_t *uart1 = (volatile uint32_t *)UART1_BASE;
    
    kprintf("\r\n=== Board B Mode ===\r\n");
    kprintf("Waiting for characters from Board A on UART1...\r\n");
    kprintf("Will echo back each received character\r\n\r\n");
    
    while (1) {
        // Wait for character from Board A on UART1
        int c = uart_getc(uart1);
        if (c >= 0) {
            // Display what we received on UART0 (USB console)
            kprintf("A->B: '%c' (0x%02x)\r\n", c, c);
            
            // Echo the same character back to Board A via UART1
            uart_putc(uart1, c);
            kprintf("B->A: '%c' (0x%02x) [ECHOED]\r\n\r\n", c, c);
        }
    }
}

// ============================================
// Main
// ============================================
int main(void) {
    // Init UART0 (USB console)
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32(uart, UART_REG_RXCTRL) = UART_RXEN;
    
    // Init UART1 (PMOD C)
    volatile uint32_t *uart1 = (volatile uint32_t *)UART1_BASE;
    REG32(uart1, UART_REG_DIV) = 868;
    REG32(uart1, UART_REG_TXCTRL) = UART_TXEN;
    REG32(uart1, UART_REG_RXCTRL) = UART_RXEN;

    kprintf("\r\n==================================\r\n");
    kprintf("  Dual UART Test - Arty A7 100T\r\n");
    kprintf("==================================\r\n");

    // Show configuration
    test_uart_config();
    
    // Select mode
    kprintf("\r\nSelect mode:\r\n");
    kprintf("  1 - Board A (send messages)\r\n");
    kprintf("  2 - Board B (echo messages)\r\n");
    kprintf("Press 1 or 2: ");
    
    // int mode = -1;
    // while (mode < 0) {
    //     int c = uart_getc((volatile uint32_t *)UART0_BASE);
    //     if (c == '1') mode = 1;
    //     else if (c == '2') mode = 2;
    // }
    
    // kprintf("%d\r\n", mode);
    
    // if (mode == 1) {
    //     test_board_a();
    // } else {
    //     test_board_b();
    // }

    while (1)
    {
        kprintf("No mode selected. Exiting main loop.\r\n");
    }
    
    
    return 0;
}
