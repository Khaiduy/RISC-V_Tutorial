/* Ed25519 stubs for Method 3 (SDHK-SDHK).
 *
 * Method 3 uses only static DH keys for authentication — Ed25519 sign/verify
 * are never called at runtime. These stubs satisfy the linker when
 * monocypher-ed25519.c is excluded from the M3 build.
 */
#include <stdint.h>
#include <stddef.h>

void crypto_ed25519_sign(uint8_t signature[64],
                         const uint8_t secret_key[64],
                         const uint8_t *message, size_t message_size)
{
    (void)signature; (void)secret_key; (void)message; (void)message_size;
    /* Unreachable in Method 3 */
    while (1);
}

int crypto_ed25519_check(const uint8_t signature[64],
                         const uint8_t public_key[32],
                         const uint8_t *message, size_t message_size)
{
    (void)signature; (void)public_key; (void)message; (void)message_size;
    /* Unreachable in Method 3 */
    while (1);
    return -1;
}
