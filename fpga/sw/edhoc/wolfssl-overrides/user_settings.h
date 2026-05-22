/* user_settings.h — wolfCrypt bare-metal config for RV32IMAC EDHOC
 *
 * All suites 0–7, 24, 25 share this file.  Features are conditionally enabled
 * by EDHOC_CRYPTO_SUITE (injected via Makefile -D flag) so that only the
 * cryptographic primitives actually needed for a given suite are compiled.
 *
 * Suite → required wolfCrypt features:
 *   0,1 : AES-CCM + SHA-256 + X25519 + Ed25519  (Ed25519 needs SHA-512)
 *   2,3 : AES-CCM + SHA-256 + P-256 + ES256
 *   4   : ChaCha20/Poly1305 + SHA-256 + X25519 + Ed25519
 *   5   : ChaCha20/Poly1305 + SHA-256 + P-256 + ES256
 *   6   : AES-128-GCM + SHA-256 + X25519 + Ed25519
 *   7   : Ascon-AEAD-128 + Ascon-Hash256 + X25519 + Ed25519
 *   24  : AES-256-GCM + SHA-384 + P-384 + ES384
 *   25  : ChaCha20/Poly1305 + SHAKE-256 + X448 + Ed448
 */
#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H

/* ── Core mode ─────────────────────────────────────────────────────── */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_MEMORY       /* no wolfSSL memory wrappers; use raw libc */
#define WOLFSSL_EXPERIMENTAL_SETTINGS  /* required for Ascon */

/* ── Math backend: SP (single-precision) C-only ────────────────────── */
#define WOLFSSL_SP_MATH_ALL     /* covers P-256, P-384, X25519, X448 */
#define WOLFSSL_SP_SMALL        /* smaller code / fewer unrolled loops */
#define WOLFSSL_SP_NO_PINNED_REGS

/* ── AEAD ciphers — selected by suite ──────────────────────────────── */

/* AES (CCM for suites 0-3, GCM for suites 6 and 24) */
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3
#  define HAVE_AESCCM
#  define WOLFSSL_AES_128
#endif

#if EDHOC_CRYPTO_SUITE == 6
#  define HAVE_AESGCM
#  define WOLFSSL_AES_128
#endif

#if EDHOC_CRYPTO_SUITE == 24
#  define HAVE_AESGCM
#  define WOLFSSL_AES_256
#endif

/* ChaCha20/Poly1305 for suites 4, 5, 25 */
#if EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 5 || \
    EDHOC_CRYPTO_SUITE == 25
#  define HAVE_CHACHA
#  define HAVE_POLY1305
#endif

/* Ascon for Suite 7 */
#if EDHOC_CRYPTO_SUITE == 7
#  define HAVE_ASCON
#endif

/* ── Hash algorithms — selected by suite ───────────────────────────── */

/* SHA-256: always needed (HKDF base, suite hash for 0-7) */
#define HAVE_SHA256

/* SHA-512: required by Ed25519 (suites 0,1,4,6,7), SHA-384 (suite 24),
 * and Ed448 (suite 25 — wolfSSL settings.h enforces this dependency).
 * EDHOC_AUTH_SK: this role signs.
 * EDHOC_PEER_SK: the peer signs; this role must verify. */
#if (EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
     EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 6 || \
     EDHOC_CRYPTO_SUITE == 7 || EDHOC_CRYPTO_SUITE == 24 || \
     EDHOC_CRYPTO_SUITE == 25) \
    && (defined(EDHOC_AUTH_SK) || defined(EDHOC_PEER_SK))
#  define WOLFSSL_SHA512
#endif

/* SHA-384: Suite 24 only (implemented via sha512.c machinery) */
#if EDHOC_CRYPTO_SUITE == 24
#  define HAVE_SHA384
#  define WOLFSSL_SHA384
#endif

/* SHA-3 / SHAKE-256 / KMAC256: Suite 25 only.
 * RFC 9528 §4.1.1 mandates KMAC256 (not HMAC-SHA3-256) for EDHOC_Extract/Expand. */
#if EDHOC_CRYPTO_SUITE == 25
#  define WOLFSSL_SHA3
#  define WOLFSSL_SHAKE256
#  define WOLFSSL_KMAC
#endif

#define NO_SHA
#define NO_MD5

/* ── KDF / MAC ──────────────────────────────────────────────────────── */
#define HAVE_HKDF
#define HAVE_HMAC
#define NO_HMAC_FIPS

/* ── X25519 — Suites 0, 1, 4, 6, 7 ────────────────────────────────── */
/* X25519 (DH): always needed for ephemeral key exchange in these suites. */
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 6 || \
    EDHOC_CRYPTO_SUITE == 7
#  define HAVE_CURVE25519
#  define CURVE25519_SMALL
#endif

/* ── Ed25519 sign — Suites 0, 1, 4, 7 (NOT Suite 6, per RFC 9528 Table 6) ──
 * Suite 6 uses X25519 for ECDH but ES256 for signing. */
#if (EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
     EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 7) \
    && (defined(EDHOC_AUTH_SK) || defined(EDHOC_PEER_SK))
#  define HAVE_ED25519
#  define ED25519_SMALL
#endif
#if defined(HAVE_ED25519) && defined(EDHOC_PEER_SK) && !defined(EDHOC_AUTH_SK)
#  define NO_ED25519_SIGN
#endif
#if defined(HAVE_ED25519) && defined(EDHOC_AUTH_SK) && !defined(EDHOC_PEER_SK)
#  define NO_ED25519_VERIFY
#endif

/* ── ECC P-256 / ES256 — Suites 2, 3, 5, 6 ───────────────────────────
 * Suites 2/3/5: P-256 ECDH + ES256 sign (need HAVE_ECC_DHE).
 * Suite 6:      X25519 ECDH + ES256 sign (ECDH via curve25519, ECC only for sign). */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6
#  define HAVE_ECC
#  define WOLFSSL_HAVE_SP_ECC   /* enables sp_c32.c P-256 path; without this,
                                 * ecc.c falls back to heap-alloc generic path
                                 * which fails on bare-metal (malloc returns NULL) */
#  define WOLFSSL_SP_NO_384     /* P-256 builds: exclude P-384 SP code */
#  define ECC_TIMING_RESISTANT
#  define HAVE_COMP_KEY         /* wc_ecc_import_x963_ex (0x02/0x03 prefix)
                                 * returns NOT_COMPILED_IN without this */
#endif
/* HAVE_ECC_DHE only for the suites that actually use P-256 for ECDH (not Suite 6). */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5
#  define HAVE_ECC_DHE
#endif

/* ── ECC P-384 / ES384 — Suite 24 ──────────────────────────────────── */
#if EDHOC_CRYPTO_SUITE == 24
#  define HAVE_ECC
#  define HAVE_ECC_DHE
#  define WOLFSSL_HAVE_SP_ECC   /* enables sp_c32.c P-384 path */
#  define WOLFSSL_SP_384        /* gates the P-384 block in sp_c32.c */
#  define WOLFSSL_SP_NO_256     /* P-384 builds: exclude P-256 SP code */
#  define HAVE_ECC384           /* needed alongside WOLFSSL_SP_384 */
#  define ECC_TIMING_RESISTANT
#  define HAVE_COMP_KEY         /* wc_ecc_import_x963_ex (compressed point) uses
                                 * sp_ecc_uncompress_384 — no heap needed */
#endif

/* Sign/verify gating: wolfSSL's settings.h force-defines HAVE_ECC_SIGN and
 * HAVE_ECC_VERIFY whenever HAVE_ECC is set. Use the NO_* opt-outs to remove
 * the path the role doesn't need. Mirrors the Ed25519/Ed448 NO_*_SIGN/VERIFY
 * pattern: only drop a path when its opposite is explicitly active.
 * Verify-only role (PEER_SK, !AUTH_SK) → drop SIGN.
 * Sign-only role  (AUTH_SK, !PEER_SK) → drop VERIFY.
 * Method 3 (neither flag): keep both (sp_c32.c needs order arithmetic that
 * is only compiled in when SIGN or VERIFY is enabled). */
#if (EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
     EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6 || \
     EDHOC_CRYPTO_SUITE == 24)
#  if defined(EDHOC_PEER_SK) && !defined(EDHOC_AUTH_SK)
#    define NO_ECC_SIGN
#  endif
#  if defined(EDHOC_AUTH_SK) && !defined(EDHOC_PEER_SK)
#    define NO_ECC_VERIFY
#  endif
#endif

/* ── X448 / Ed448 — Suite 25 ────────────────────────────────────────── */
#if EDHOC_CRYPTO_SUITE == 25
#  define HAVE_CURVE448
#  define CURVE448_SMALL
#endif
/* Ed448: only when this role signs (AUTH_SK) or verifies (PEER_SK).
 * Method 3 uses static DH on both sides and needs no Ed448 at all. */
#if EDHOC_CRYPTO_SUITE == 25 \
    && (defined(EDHOC_AUTH_SK) || defined(EDHOC_PEER_SK))
#  define HAVE_ED448
#  define ED448_SMALL
#endif
#if EDHOC_CRYPTO_SUITE == 25 && defined(EDHOC_PEER_SK) && !defined(EDHOC_AUTH_SK)
#  define NO_ED448_SIGN
#endif
#if EDHOC_CRYPTO_SUITE == 25 && defined(EDHOC_AUTH_SK) && !defined(EDHOC_PEER_SK)
#  define NO_ED448_VERIFY
#endif

/* ── RNG ─────────────────────────────────────────────────────────────── */
/* Bypass wolfSSL's DRBG — call our platform CSPRNG directly. */
#ifndef __ASSEMBLER__
int csprng_generate_block(unsigned char *output, unsigned int sz);
#endif
#define CUSTOM_RAND_GENERATE_BLOCK csprng_generate_block

/* ── Disabled features (reduce footprint) ───────────────────────────── */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_AES_CBC
#define NO_CERTS
#define NO_ASN
#define NO_ASN_CRYPT
#define NO_PSK
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_STUB
#define WOLFSSL_NO_SOCK
#define NO_MULTIBYTE_PRINT
#define WC_NO_RNG_SIMPLE
#define NO_OLD_RNGNAME
#define NO_PWDBASED
#define WOLFSSL_NO_HASH_RAW

/* ── Bare-metal I/O ──────────────────────────────────────────────────── */
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM

/* ── Size optimisations for embedded ─────────────────────────────────── */
/* WOLFSSL_SMALL_STACK intentionally disabled: malloc() always returns NULL on
 * this bare-metal target, so heap-allocated wolfSSL structs would silently
 * fail, producing zero-filled hash/HMAC outputs.  All structs go on the
 * stack instead; ~31 KB of headroom is available. */

#endif /* WOLF_USER_SETTINGS_H */
