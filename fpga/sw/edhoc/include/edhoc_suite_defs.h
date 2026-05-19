/*
 * edhoc_suite_defs.h - Compile-time suite classification macros
 *
 * Derives all suite-dependent constants from EDHOC_CRYPTO_SUITE (set by Makefile).
 * All suites use wolfCrypt as the crypto library.
 * Include this in app files instead of duplicating suite conditionals.
 *
 * Suite → Curve + Sig mapping (RFC 9528 §3.6):
 *   Suites 0,1,4,6,7: X25519 + EdDSA/Ed25519  (wolfCrypt)
 *   Suites 2,3,5:     P-256  + ES256            (wolfCrypt)
 *   Suite 24:         P-384  + ES384            (wolfCrypt, CNSA 1.0)
 *   Suite 25:         X448   + Ed448            (wolfCrypt)
 *
 * Suite → AEAD mapping:
 *   Suites 0,1,2,3: AES-128-CCM (wolfCrypt)
 *   Suites 4,5,25:  ChaCha20/Poly1305 (wolfCrypt)
 *   Suite 6:        AES-128-GCM (wolfCrypt)
 *   Suite 7:        Ascon-AEAD-128 (wolfCrypt)
 *   Suite 24:       AES-256-GCM (wolfCrypt)
 */
#ifndef EDHOC_SUITE_DEFS_H
#define EDHOC_SUITE_DEFS_H

#include "edhoc/suites.h"
#include "crypto_wrapper.h"

#ifndef EDHOC_CRYPTO_SUITE
#error "EDHOC_CRYPTO_SUITE must be defined by the Makefile"
#endif

/* --- Curve family flags --- */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || EDHOC_CRYPTO_SUITE == 5
#define SUITE_USES_P256   1
#else
#define SUITE_USES_P256   0
#endif

#if EDHOC_CRYPTO_SUITE == 24
#define SUITE_USES_P384   1
#else
#define SUITE_USES_P384   0
#endif

#if EDHOC_CRYPTO_SUITE == 25
#define SUITE_USES_X448   1
#else
#define SUITE_USES_X448   0
#endif

/* --- ECDH algorithm --- */
#if SUITE_USES_P384
#define SUITE_ECDH_ALG    P384
#elif SUITE_USES_X448
#define SUITE_ECDH_ALG    X448
#elif SUITE_USES_P256
#define SUITE_ECDH_ALG    P256
#else
#define SUITE_ECDH_ALG    X25519
#endif

/* --- Signature algorithm and secret key length --- */
#if SUITE_USES_P384
#define SUITE_SIGN_ALG    ES384
#define SUITE_SIGN_SK_LEN 48
#elif SUITE_USES_X448
#define SUITE_SIGN_ALG    Ed448
#define SUITE_SIGN_SK_LEN 57
#elif SUITE_USES_P256
#define SUITE_SIGN_ALG    ES256
#define SUITE_SIGN_SK_LEN 32
#else
#define SUITE_SIGN_ALG    EdDSA
#define SUITE_SIGN_SK_LEN 64
#endif

/* --- COSE curve values for CCS credentials --- */
#if SUITE_USES_P384
#define SUITE_CRV_DH      2   /* P-384 */
#define SUITE_CRV_SIGN    2   /* P-384 */
#elif SUITE_USES_X448
#define SUITE_CRV_DH      5   /* X448 */
#define SUITE_CRV_SIGN    7   /* Ed448 */
#elif SUITE_USES_P256
#define SUITE_CRV_DH      1   /* P-256 */
#define SUITE_CRV_SIGN    1   /* P-256 */
#else
#define SUITE_CRV_DH      4   /* X25519 */
#define SUITE_CRV_SIGN    6   /* Ed25519 */
#endif

/* --- ECC (P-256 or P-384 projective arithmetic) --- */
#define SUITE_USES_ECC (SUITE_USES_P256 || SUITE_USES_P384)

/* --- Ed25519 (suites not using ECC or X448) --- */
#define SUITE_USES_ED25519 (!SUITE_USES_ECC && !SUITE_USES_X448)

/* --- DH key size (private and public, raw bytes) --- */
#if SUITE_USES_P384
#define SUITE_DH_LEN    48
#elif SUITE_USES_X448
#define SUITE_DH_LEN    56
#else
#define SUITE_DH_LEN    32
#endif

/* --- Signing public key size --- */
#if SUITE_USES_P384
#define SUITE_SIGN_PK_LEN  48
#elif SUITE_USES_X448
#define SUITE_SIGN_PK_LEN  57
#else
#define SUITE_SIGN_PK_LEN  32
#endif

/* --- PRK_out / hash output size --- */
#if EDHOC_CRYPTO_SUITE == 24
#define SUITE_PRK_LEN   48
#else
#define SUITE_PRK_LEN   32
#endif

/* --- ChaCha20/Poly1305 --- */
#if EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 25
#define SUITE_USES_CHACHA20 1
#else
#define SUITE_USES_CHACHA20 0
#endif

/* --- Suite byte for CBOR suites_i encoding --- */
#define SUITE_BYTE ((uint8_t)(EDHOC_CRYPTO_SUITE))

/* --- Suite enum for get_suite() --- */
#define SUITE_ENUM ((enum suite_label)(EDHOC_CRYPTO_SUITE))

#endif /* EDHOC_SUITE_DEFS_H */
