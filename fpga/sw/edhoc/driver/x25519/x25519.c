
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

// 32-bit version for RV32 systems
// Takes raw byte arrays and sends them directly to hardware
// Hardware receives: reg[0] = bytes[0:3], reg[1] = bytes[4:7], etc.
void hwx25519_init32_bytes(void* x25519ctrl, const uint8_t scalar[32], const uint8_t point_in[32]) {

    hwx25519_reset(x25519ctrl);

    // Write 256-bit scalar and point_in (8 x 32-bit values each)
    // Send directly: reg[0] gets bytes[0:3], reg[1] gets bytes[4:7], etc.
    // Within each register: little-endian packing (byte[0] at bits[7:0])
    
    for(int i = 0; i < 8; i++) {
        // Pack 4 bytes directly from array in little-endian
        _REG32((char*)x25519ctrl, X25519_REG_SCALAR + (i*4)) = 
            ((uint32_t)scalar[i*4 + 3]) |
            ((uint32_t)scalar[i*4 + 2] << 8) |
            ((uint32_t)scalar[i*4 + 1] << 16) |
            ((uint32_t)scalar[i*4 + 0] << 24);
    }
    
    for(int i = 0; i < 8; i++) {
        _REG32((char*)x25519ctrl, X25519_REG_POINT_IN + (i*4)) = 
            ((uint32_t)point_in[i*4 + 3]) |
            ((uint32_t)point_in[i*4 + 2] << 8) |
            ((uint32_t)point_in[i*4 + 1] << 16) |
            ((uint32_t)point_in[i*4 + 0] << 24);
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

// 32-bit version for RV32 systems - returns raw bytes
void hwx25519_results32_bytes(void* x25519ctrl, uint8_t* result) {
    uint32_t status_reg;
    uint32_t reg_val;

    // Wait for computation to complete (wait until valid = 1)
    do {
        status_reg = _REG32((char*)x25519ctrl, X25519_REG_STATUS);
    } while(!(status_reg & X25519_STATUS_VALID)); // Wait for valid bit

    // Read 256-bit output point (8 x 32-bit values)
    // Read directly: reg[0] -> bytes[0:3], reg[1] -> bytes[4:7], etc.
    
    for(int i = 0; i < 8; i++) {
        reg_val = _REG32((char*)x25519ctrl, X25519_REG_POINT_OUT + (i*4));
        
        // Unpack little-endian: byte[0] at LSB
        result[(7-i)*4 + 3] = (uint8_t)(reg_val & 0xFF);
        result[(7-i)*4 + 2] = (uint8_t)((reg_val >> 8) & 0xFF);
        result[(7-i)*4 + 1] = (uint8_t)((reg_val >> 16) & 0xFF);
        result[(7-i)*4 + 0] = (uint8_t)((reg_val >> 24) & 0xFF);
    }

    _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = 0x00;
}


// void hwx25519_compute_debug(void* x25519ctrl, const uint8_t* scalar, const uint8_t* point_in, uint8_t* result) {
//     // Reset
//     hwx25519_reset(x25519ctrl);
    
//     kprintf("Writing scalar...\r\n");
//     // Write scalar - LITTLE-ENDIAN byte order
//     for(int i = 0; i < 8; i++) {
//         uint32_t val = ((uint32_t)scalar[i*4 + 0]) |
//                        ((uint32_t)scalar[i*4 + 1] << 8) |
//                        ((uint32_t)scalar[i*4 + 2] << 16) |
//                        ((uint32_t)scalar[i*4 + 3] << 24);
//         _REG32((char*)x25519ctrl, X25519_REG_SCALAR + (i*4)) = val;
//         kprintf("  scalar[");
//         kprintf("%x", i);
//         kprintf("] = ");
//         kprintf("%x", val);
//         kprintf("\r\n");
//     }
    
//     kprintf("Writing point_in...\r\n");
//     // Write point_in - LITTLE-ENDIAN byte order
//     for(int i = 0; i < 8; i++) {
//         uint32_t val = ((uint32_t)point_in[i*4 + 0]) |
//                        ((uint32_t)point_in[i*4 + 1] << 8) |
//                        ((uint32_t)point_in[i*4 + 2] << 16) |
//                        ((uint32_t)point_in[i*4 + 3] << 24);
//         _REG32((char*)x25519ctrl, X25519_REG_POINT_IN + (i*4)) = val;
//         kprintf("  point_in[");
//         kprintf("%x", i);
//         kprintf("] = ");
//         kprintf("%x", val);
//         kprintf("\r\n");
//     }
    
//     kprintf("Starting computation...\r\n");
//     // Start
//     _REG32((char*)x25519ctrl, X25519_REG_CONTROL) = X25519_CTRL_START;
    
//     // Check status immediately
//     uint32_t status = _REG32((char*)x25519ctrl, X25519_REG_STATUS);
//     kprintf("Status after start: ");
//     kprintf("%x", status);
//     kprintf("\r\n");
    
//     // Get results
//     hwx25519_results32_bytes(x25519ctrl, result);
//     kprintf("Computation complete\r\n");
// }


// void print_x25519_bytes(const char* label, const uint8_t* value) {
//     kprintf("%s", label);
//     for(int i = 0; i < 32; i++) {
//         if (i > 0 && i % 16 == 0) kprintf("\r\n                ");
//         kprintf("%02x", value[i]);
//     }
//     kprintf("\r\n");
// }

// void hwx25519_selftest(void* x25519ctrl) {
//     kprintf("\r\n");
//     kprintf("==================================\r\n");
//     kprintf("X25519 Hardware Accelerator Test\r\n");
//     kprintf("==================================\r\n");
//     unsigned long start, end;
    
//     // Test vector from FPGA test (LITTLE-ENDIAN byte order)
//     uint8_t scalar[32] = {
//         0x61,0xc9,0xd9,0x2a,0x4f,0x81,0x2e,0x59,
//         0xb0,0x12,0x9e,0xa9,0xd0,0xdb,0xce,0x90,
//         0x5c,0x70,0x0b,0x50,0x39,0x05,0x47,0x08,
//         0x91,0x66,0xb6,0x5c,0x8e,0xc2,0x2e,0x09
//     };
    
//     uint8_t base_point[32] = {
//         9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
//     };
    
//     uint8_t expected[32] = {
//         0x48,0x4f,0x76,0x70,0x1e,0x75,0xff,0xec,
//         0x0d,0x9b,0x74,0x97,0x27,0x36,0xc1,0xdf,
//         0xc5,0x56,0xa5,0xae,0x55,0x1d,0xbf,0x04,
//         0x2b,0xfc,0x24,0xe7,0x5b,0x75,0xc7,0x9d
//     };
    
//     uint8_t result[32];

//     kprintf("\r\nTest Vector:\r\n");
//     print_x25519_bytes("  Scalar:   ", scalar);
//     print_x25519_bytes("  Point:    ", base_point);
//     print_x25519_bytes("  Expected: ", expected);
    
//     kprintf("\r\nStarting X25519 computation...\r\n");
//     start = rdcycle();
//     hwx25519_init32_bytes(x25519ctrl, scalar, base_point);
//     hwx25519_results32_bytes(x25519ctrl, result);
//     end = rdcycle();
    
//     print_x25519_bytes("  Result:   ", result);
//     kprintf("  Cycles:   %lu\r\n", end - start);
    
//     // Verify result
//     int match = 1;
//     for(int i = 0; i < 32; i++) {
//         if(result[i] != expected[i]) {
//             match = 0;
//             break;
//         }
//     }
    
//     kprintf("\r\n");
//     if(match) {
//         kprintf("*** TEST PASSED ***\r\n");
//         kprintf("Hardware X25519 is working correctly!\r\n");
//     } else {
//         kprintf("*** TEST FAILED ***\r\n");
//         kprintf("Hardware result does not match expected value\r\n");
//     }
//     kprintf("==================================\r\n");
// }