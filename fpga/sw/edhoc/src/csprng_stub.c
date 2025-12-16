/*
 * Stub CSPRNG for bare-metal RISC-V
 * 
 * WARNING: This is a VERY INSECURE stub implementation for testing only!
 * In production, you should use a proper hardware RNG or cryptographic PRNG.
 */

#include <stddef.h>
#include <stdint.h>

// Simple (insecure!) pseudo-random number generator for demonstration
// In a real system, use hardware RNG or a proper CSPRNG
static uint32_t prng_state = 0x12345678;

static uint32_t simple_rand(void) {
    // Very simple linear congruential generator
    prng_state = prng_state * 1664525 + 1013904223;
    return prng_state;
}

/**
 * default_CSPRNG - Cryptographically Secure Pseudo-Random Number Generator
 * 
 * WARNING: This is a stub implementation and is NOT cryptographically secure!
 * It's only for testing/demonstration purposes.
 * 
 * For production:
 * - Use hardware RNG (e.g., from RISC-V crypto extension)
 * - Or use a proper software CSPRNG seeded from hardware entropy
 * 
 * @param dest  Destination buffer for random bytes
 * @param size  Number of random bytes to generate
 * @return      1 on success, 0 on failure
 */
int default_CSPRNG(uint8_t *dest, unsigned int size) {
    if (dest == NULL || size == 0) {
        return 0;
    }
    
    // Generate random bytes using simple PRNG
    // WARNING: This is NOT cryptographically secure!
    for (unsigned int i = 0; i < size; i++) {
        dest[i] = (uint8_t)(simple_rand() & 0xFF);
    }
    
    return 1;  // Success
}

/**
 * Initialize the PRNG with a seed value
 * In production, this should be called with entropy from a hardware RNG
 */
void init_prng(uint32_t seed) {
    prng_state = seed;
}
