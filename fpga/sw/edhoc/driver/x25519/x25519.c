
#include "x25519.h"
#include "mmio.h"

// rdcycle for timing - only needed for self-test
static inline unsigned long rdcycle(void) {
    unsigned long cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}

// Forward declare kprintf for self-test
extern void kprintf(const char* fmt, ...);


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
//     kprintf(label);
//     // Print each 64-bit value as two 32-bit hex numbers
//     for(int i = 0; i < 4; i++) {
//         uint32_t hi = (uint32_t)(value[i] >> 32);
//         uint32_t lo = (uint32_t)(value[i] & 0xFFFFFFFF);
//         kprintf("%x", hi);
//         kprintf("%x", lo);
//         if (i < 3) kprintf(" ");
//     }
//     kprintf("\r\n");
// }

// // // Accurate timing measurement macro
// // #define START_TIMING() \
// //     do { \
// //         asm volatile ("fence" ::: "memory"); \
// //         start = rdcycle(); \
// //     } while(0)

// // #define END_TIMING() \
// //     do { \
// //         asm volatile ("fence" ::: "memory"); \
// //         end = rdcycle(); \
// //     } while(0)

// // void generate_address_key(uint64_t* key) {
// //     volatile uint64_t stack_var1;
// //     volatile uint64_t stack_var2;
// //     volatile uint64_t stack_var3;

// //     // Use multiple stack addresses for more entropy
// //     uint64_t addr1 = (uint64_t)&stack_var1;
// //     uint64_t addr2 = (uint64_t)&stack_var2;
// //     uint64_t addr3 = (uint64_t)&stack_var3;

// //     // Combine addresses for initial seed
// //     uint64_t seed = addr1 ^ (addr2 << 16) ^ (addr3 >> 8);

// //     for(int i = 0; i < 4; i++) {
// //         // Linear Congruential Generator (LCG)
// //         seed = seed * 1664525ULL + 1013904223ULL;
// //         key[i] = seed;
// //     }
// // }

// void hwx25519_selftest(void* x25519ctrl) {
//     kprintf("X25519 EDHOC Key Test\r\n");
//     kprintf("======================\r\n");
//     unsigned long start, end;
    
//     // EDHOC Initiator private key x_i
//     // x_i = 36 8e c1 f6 9a eb 65 9b a3 7d 5a 8d 45 b2 1b dc 02 99 dc ea a8 ef 23 5f 3c a4 2c e3 53 0f 95 25
//     uint64_t initiator_private[4] = {
//         0x9b65eb9af6c18e36ULL,  // bytes 0-7 (little-endian)
//         0xdc1bb2458d5a7da3ULL,  // bytes 8-15
//         0x5f23efa8eadc9902ULL,  // bytes 16-23
//         0x25950f53e32ca43cULL   // bytes 24-31
//     };
    
//     // EDHOC Responder private key y_r
//     // y_r = dc 88 d2 d5 1d a5 ed 67 fc 46 16 35 6b c8 ca 74 ef 9e be 8b 38 7e 62 3a 36 0b a4 80 b9 b2 9d 1c
//     uint64_t responder_private[4] = {
//         0x67eda51dd5d288dcULL,
//         0x74cac86b351646fcULL,
//         0x3a627e388bbe9eefULL,
//         0x1c9db2b980a40b36ULL
//     };
    
//     // X25519 base point = 9
//     uint64_t base_point[4] = {
//         0x0900000000000000ULL,
//         0x0000000000000000ULL,
//         0x0000000000000000ULL,
//         0x0000000000000000ULL
//     };

//     uint64_t initiator_public[4];
//     uint64_t responder_public[4];
//     uint64_t initiator_shared[4];
//     uint64_t responder_shared[4];

//     kprintf("\r\n=== Step 1: Generate Public Keys ===\r\n");
    
//     kprintf("Initiator: Computing G_X = x_i * 9\r\n");
//     print_x25519_value("  x_i (private): ", initiator_private);
//     START_TIMING();
//     hwx25519_init(x25519ctrl, initiator_private, base_point);
//     hwx25519_results(x25519ctrl, initiator_public);
//     END_TIMING();
//     kprintf("  Computation time: %d cycles\r\n", (unsigned int)(end - start));
//     print_x25519_value("  G_X (public):  ", initiator_public);

//     kprintf("\r\nResponder: Computing G_Y = y_r * 9\r\n");
//     print_x25519_value("  y_r (private): ", responder_private);
//     START_TIMING();
//     hwx25519_init(x25519ctrl, responder_private, base_point);
//     hwx25519_results(x25519ctrl, responder_public);
//     END_TIMING();
//     kprintf("  Computation time: %d cycles\r\n", (unsigned int)(end - start));
//     print_x25519_value("  G_Y (public):  ", responder_public);

//     kprintf("\r\n=== Step 2: Compute Shared Secret (G_XY) ===\r\n");
    
//     kprintf("Initiator: Computing G_XY = x_i * G_Y\r\n");
//     START_TIMING();
//     hwx25519_init(x25519ctrl, initiator_private, responder_public);
//     hwx25519_results(x25519ctrl, initiator_shared);
//     END_TIMING();
//     kprintf("  Computation time: %d cycles\r\n", (unsigned int)(end - start));
//     print_x25519_value("  G_XY result:   ", initiator_shared);

//     kprintf("\r\nResponder: Computing G_XY = y_r * G_X\r\n");
//     START_TIMING();
//     hwx25519_init(x25519ctrl, responder_private, initiator_public);
//     hwx25519_results(x25519ctrl, responder_shared);
//     END_TIMING();
//     kprintf("  Computation time: %d cycles\r\n", (unsigned int)(end - start));
//     print_x25519_value("  G_XY result:   ", responder_shared);

//     kprintf("\r\n=== Verification ===\r\n");
//     if(initiator_shared[0] == responder_shared[0] &&
//        initiator_shared[1] == responder_shared[1] &&
//        initiator_shared[2] == responder_shared[2] &&
//        initiator_shared[3] == responder_shared[3]) {
//         kprintf("SUCCESS: G_XY values match!\r\n");
//         kprintf("X25519 hardware is working correctly.\r\n");
//     } else {
//         kprintf("FAILURE: G_XY values do NOT match!\r\n");
//         kprintf("This indicates a hardware or driver bug.\r\n");
//     }
// }