
#include "x25519.h"
#include "mmio.h"
#include <riscv-pk/encoding.h>
#include "kprintf.h"

void hwx25519_reset(void* x25519ctrl) {
    // Set reset bit
    _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = X25519_CTRL_RESET;

    // Clear reset bit (release reset)
    _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = 0x00;
}

void hwx25519_init(void* x25519ctrl, uint64_t scalar[4], uint64_t point_in[4]) {

    hwx25519_reset(x25519ctrl);

    // Write 256-bit scalar (4 x 64-bit values)
    for(int i = 0; i < 4; i++) {
        _REG64((char*)x25519ctrl, X25519_REG_SCALAR + (i*8)) = scalar[i];
    }

    // Write 256-bit input point (4 x 64-bit values)
    for(int i = 0; i < 4; i++) {
        _REG64((char*)x25519ctrl, X25519_REG_POINT_IN + (i*8)) = point_in[i];
    }

    // Start computation
    _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = X25519_CTRL_START;
}

void hwx25519_results(void* x25519ctrl, uint64_t* result) {
//    uint64_t result[4];
    uint32_t status_reg;

    // Wait for computation to complete (wait until valid = 1)
    do {
        status_reg = _REG32((char*)x25519ctrl, X25519_REG_STATUS);
    } while(!(status_reg & X25519_STATUS_VALID)); // Wait for valid bit

    // Read 256-bit output point (4 x 64-bit values)
    for(int i = 0; i < 4; i++) {
        result[3-i] = _REG64((char*)x25519ctrl, X25519_REG_POINT_OUT + (i*8));  // Note: 3-i
    }

//    // Print results
//    for(int i = 0; i < 4; i++) {
//        printf("%016lx", result[i]);
//    }
//    printf("\n");

    _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = 0x00;
}

// void print_x25519_value(const char* label, uint64_t* value) {
//     kprintf("%s", label);
//     // Print in natural order since result array is already correctly ordered
//     for(int i = 0; i < 4; i++) {
//         kprintf("%016lx", value[i]);
//     }
//     kprintf("\n");
//     kprintf("we are here\n");
// }

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

// void generate_address_key(uint64_t* key) {
//     volatile uint64_t stack_var1;
//     volatile uint64_t stack_var2;
//     volatile uint64_t stack_var3;

//     // Use multiple stack addresses for more entropy
//     uint64_t addr1 = (uint64_t)&stack_var1;
//     uint64_t addr2 = (uint64_t)&stack_var2;
//     uint64_t addr3 = (uint64_t)&stack_var3;

//     // Combine addresses for initial seed
//     uint64_t seed = addr1 ^ (addr2 << 16) ^ (addr3 >> 8);

//     for(int i = 0; i < 4; i++) {
//         // Linear Congruential Generator (LCG)
//         seed = seed * 1664525ULL + 1013904223ULL;
//         key[i] = seed;
//     }
// }

// void hwx25519_selftest(void* x25519ctrl) {
//     kprintf("X25519 ECDH Protocol Test (RFC 7748)\r\n");
//     kprintf("====================================\r\n");
//     unsigned long start, end;
//     // Private keys
// //    uint64_t alice_private[4];
// //    uint64_t bob_private[4];
// //    generate_address_key(alice_private);
// //    generate_address_key(bob_private);

//     uint64_t alice_private[4] = {
//         0x00c9a7a05a86e349ULL,
//         0x3723b76b016f39c4ULL,
//         0x117409f0f934ab05ULL,
//         0x608f0e1e23bb7d75ULL
//     };

//     uint64_t bob_private[4] = {
//         0x5625b841a21c0000ULL,
//         0x32b956a8512af35fULL,
//         0xe26832a35bcc2932ULL,
//         0xf56b9fcf4418f6e9ULL
//     };

//     uint64_t base_point[4] = {
//         0x0900000000000000ULL,
//         0x0000000000000000ULL,
//         0x0000000000000000ULL,
//         0x0000000000000000ULL
//     };

//     uint64_t alice_public[4];
//     uint64_t bob_public[4];
//     uint64_t alice_shared[4];
//     uint64_t bob_shared[4];

// //    printf("=== Step 1: Alice computes K_A = X25519(a, 9) ===\n");
//     print_x25519_value("Alice's private key 'a': \r\n", alice_private);

//     START_TIMING();
//     hwx25519_init(x25519ctrl, alice_private, base_point);
//     hwx25519_results(x25519ctrl, alice_public);
//     END_TIMING();
//     kprintf("Step 1: %lu cycles\r\n", end - start);

// //    print_x25519_value("Alice's public key K_A:  ", alice_public);
// //    printf("\n");

// //    printf("=== Step 2: Bob computes K_B = X25519(b, 9) ===\n");
//     print_x25519_value("Bob's private key 'b':   \r\n", bob_private);
//     START_TIMING();
//     hwx25519_init(x25519ctrl, bob_private, base_point);
//     hwx25519_results(x25519ctrl, bob_public);
//     END_TIMING();
//     kprintf("Step 2: %lu cycles\r\n", end - start);

// //    print_x25519_value("Bob's public key K_B:    ", bob_public);
// //    printf("\n");

// //    printf("=== Step 3: Alice computes shared secret X25519(a, K_B) ===\n");
// //    print_x25519_value("Alice's private key 'a': ", alice_private);
// //    print_x25519_value("Bob's public key K_B:    ", bob_public);
//     START_TIMING();
//     hwx25519_init(x25519ctrl, alice_private, bob_public);
//     hwx25519_results(x25519ctrl, alice_shared);
//     END_TIMING();
//     kprintf("Step 3: %lu cycles\r\n", end - start);
// //    print_x25519_value("Alice's shared secret:   ", alice_shared);
// //    printf("\n");

// //    printf("=== Step 4: Bob computes shared secret X25519(b, K_A) ===\n");
// //    print_x25519_value("Bob's private key 'b':   ", bob_private);
// //    print_x25519_value("Alice's public key K_A:  ", alice_public);
//     START_TIMING();
//     hwx25519_init(x25519ctrl, bob_private, alice_public);
//     hwx25519_results(x25519ctrl, bob_shared);
//     END_TIMING();
//     kprintf("Step 4: %lu cycles\r\n", end - start);

// //    print_x25519_value("Bob's shared secret:     ", bob_shared);
// //    printf("\n");

// //    printf("=== Step 5: Verify shared secrets match ===\n");
// //    print_x25519_value("Alice's shared secret: ", alice_shared);
// //    print_x25519_value("Bob's shared secret:   ", bob_shared);

//     if(alice_shared[0] == bob_shared[0] &&
//        alice_shared[1] == bob_shared[1] &&
//        alice_shared[2] == bob_shared[2] &&
//        alice_shared[3] == bob_shared[3]) {
//         kprintf("✓ SUCCESS: Shared secrets match!\r\n");
//     } else {
//         kprintf("✗ FAILURE: Shared secrets don't match!\r\n");
//         kprintf("=== Step 1: Alice computes K_A = X25519(a, 9) ===\r\n");
//         print_x25519_value("Alice's private key 'a': ", alice_private);
//         print_x25519_value("Alice's public key K_A:  ", alice_public);
//         kprintf("\r\n");

//         kprintf("=== Step 2: Bob computes K_B = X25519(b, 9) ===\r\n");
//         print_x25519_value("Bob's private key 'b':   ", bob_private);
//         print_x25519_value("Bob's public key K_B:    ", bob_public);
//         kprintf("\r\n");

//         kprintf("=== Step 3: Alice computes shared secret X25519(a, K_B) ===\r\n");
//         print_x25519_value("Alice's private key 'a': ", alice_private);
//         print_x25519_value("Bob's public key K_B:    ", bob_public);
//         print_x25519_value("Alice's shared secret:   ", alice_shared);
//         kprintf("\r\n");

//         kprintf("=== Step 4: Bob computes shared secret X25519(b, K_A) ===\r\n");
//         print_x25519_value("Bob's private key 'b':   ", bob_private);
//         print_x25519_value("Alice's public key K_A:  ", alice_public);
//         print_x25519_value("Bob's shared secret:     ", bob_shared);
//         kprintf("\r\n");

//         kprintf("=== Step 5: Verify shared secrets match ===\r\n");
//         print_x25519_value("Alice's shared secret: ", alice_shared);
//         print_x25519_value("Bob's shared secret:   ", bob_shared);
//     }
// }