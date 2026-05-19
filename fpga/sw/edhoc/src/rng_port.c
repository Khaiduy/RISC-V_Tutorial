/* rng_port.c — bridge CUSTOM_RAND_GENERATE_BLOCK to platform CSPRNG */
#ifdef WOLFCRYPT

#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>

extern int default_CSPRNG(uint8_t *dest, unsigned int size);

/* Called directly by wolfSSL as CUSTOM_RAND_GENERATE_BLOCK.
 * wolfSSL expects 0 on success; default_CSPRNG returns 1 on success. */
int csprng_generate_block(unsigned char *output, unsigned int sz)
{
    return default_CSPRNG((uint8_t *)output, sz) == 1 ? 0 : -1;
}

#endif /* WOLFCRYPT */
