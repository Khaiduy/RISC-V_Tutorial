/*
 * Minimal mbedTLS configuration for EDHOC Method 3 + Suite 0/1
 * 
 * Method 3 (Static DH) + Suite 0/1 (X25519) requirements:
 * - X25519 ECDH
 * - AES-CCM
 * - SHA-256
 * - HMAC
 * 
 * NO certificates, NO X.509, NO filesystem I/O
 */

// PSA crypto support
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_STORAGE_C

// Platform support for bare-metal
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

// AES support
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_CCM_C

// SHA256 support
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C

// ECC support for X25519 (Curve25519) and P-256
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

// NO X.509 certificates
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_PK_C
#undef MBEDTLS_PK_PARSE_C
#undef MBEDTLS_OID_C
#undef MBEDTLS_ASN1_PARSE_C
#undef MBEDTLS_ASN1_WRITE_C

// NO ECDSA signatures (Method 3 uses static DH only)
#undef MBEDTLS_ECDSA_C

// MD (message digest) wrapper for HMAC
#define MBEDTLS_MD_C

// Additional required modules
#define MBEDTLS_CIPHER_C

// Optimizations for embedded
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_NO_INTERNAL_RNG

// Memory and error handling
#include <stdlib.h>

// Validation macros
#include "mbedtls/check_config.h"
